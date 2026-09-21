"""Tree-sitter CST → normalized SyntaxGraph.

Walks named syntax nodes only. String and comment nodes are recorded as data
and never become calls, sources, or sinks.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from app.domain.language import ParserTier
from app.domain.source import ParsedEntity, ParsedImport, ParsedParameter
from app.parsing.grammar import Grammar, grammar_for
from app.parsing.model import (
    Binding,
    CallKind,
    CallSite,
    ParserDiagnostics,
    ReturnSite,
    Scope,
    ScopeKind,
    SemanticKind,
    SemanticNode,
    Symbol,
    SymbolKind,
    SyntaxEvent,
    SyntaxGraph,
)
from app.parsing.span import SourceSpan, span_from_ts_node
from app.parsing.treesitter import (
    MAX_NESTING,
    MAX_WALK_NODES,
    collect_error_spans,
    parse_treesitter,
)

_NON_CALL_NAMES = frozenset(
    {
        "if",
        "else",
        "for",
        "while",
        "switch",
        "case",
        "catch",
        "try",
        "return",
        "throw",
        "typeof",
        "sizeof",
        "new",
        "delete",
        "await",
        "yield",
        "class",
        "struct",
        "enum",
        "interface",
        "func",
        "fn",
        "fun",
        "def",
        "function",
        "var",
        "let",
        "const",
        "val",
        "package",
        "import",
        "from",
        "as",
        "in",
        "of",
        "and",
        "or",
        "not",
    }
)


def parse_treesitter_graph(language_id: str, file_path: Path, source: str) -> SyntaxGraph | None:
    grammar_key_filename = str(file_path)
    grammar = grammar_for(language_id, filename=grammar_key_filename)
    if grammar is None:
        return None
    ts_name = grammar.ts_name
    parse_input = source
    if language_id == "php" and "<?" not in source and _looks_like_php_code(source):
        parse_input = "<?php " + source
    parsed = parse_treesitter(language_id, parse_input, ts_language=ts_name)
    if parsed is None:
        return None
    root = getattr(parsed.tree, "root_node", None)
    if root is None:
        return None
    builder = _GraphBuilder(
        language_id=language_id,
        file_path=str(file_path),
        source=parse_input,
        source_bytes=parsed.source_bytes,
        grammar=grammar,
        truncated=parsed.truncated,
    )
    builder.walk(root)
    if bool(getattr(root, "has_error", False)):
        extra = collect_error_spans(root)
        if extra:
            seen = {(s.start_byte, s.end_byte) for s in builder.error_spans}
            for span in extra:
                if (span.start_byte, span.end_byte) not in seen:
                    builder.error_spans.append(span)
        if not builder.errors:
            builder.errors.append("syntax error")
        if not builder.error_spans:
            root_span = _safe_span(root)
            if root_span is not None:
                builder.error_spans.append(root_span)
    return builder.build()


class _GraphBuilder:
    def __init__(
        self,
        *,
        language_id: str,
        file_path: str,
        source: str,
        source_bytes: bytes,
        grammar: Grammar,
        truncated: bool,
    ) -> None:
        self.language_id = language_id
        self.file_path = file_path
        self.source = source
        self.source_bytes = source_bytes
        self.grammar = grammar
        self.truncated = truncated
        self.lines = tuple(source.splitlines() or [""])
        self.imports: list[ParsedImport] = []
        self.entities: list[ParsedEntity] = []
        self.calls: list[CallSite] = []
        self.bindings: list[Binding] = []
        self.returns: list[ReturnSite] = []
        self.events: list[SyntaxEvent] = []
        self.scopes: list[Scope] = []
        self.symbols: list[Symbol] = []
        self.nodes: list[SemanticNode] = []
        self.errors: list[str] = []
        self.error_spans: list[SourceSpan] = []
        self._scope_stack: list[Scope] = [
            Scope(scope_id="module", kind=ScopeKind.MODULE, name="module")
        ]
        self.scopes.append(self._scope_stack[0])
        self._class_stack: list[str] = []
        self._visited = 0
        self._node_seq = 0
        self._param_sources: dict[str, tuple[str, ...]] = {}

    @property
    def current_scope(self) -> Scope:
        return self._scope_stack[-1]

    def build(self) -> SyntaxGraph:
        has_errors = bool(self.error_spans) or self.truncated
        if self.truncated and "truncated" not in " ".join(self.errors):
            self.errors.append("source truncated before parse")
        if (
            not has_errors
            and _looks_unparseable(self.source)
            and not (self.entities or self.calls or self.bindings or self.imports)
        ):
            self.errors.append("source produced no recoverable syntax nodes")
            has_errors = True
        return SyntaxGraph(
            language=self.language_id,
            file_path=self.file_path,
            source=self.source,
            lines=self.lines,
            imports=tuple(self.imports),
            entities=tuple(self.entities),
            calls=tuple(self.calls),
            bindings=tuple(self.bindings),
            errors=tuple(self.errors),
            parser_backend="tree_sitter",
            parser_tier=ParserTier.FULL_AST,
            diagnostics=ParserDiagnostics(
                has_errors=has_errors,
                error_count=len(self.error_spans),
                error_spans=tuple(self.error_spans),
                recoverable=True,
                truncated=self.truncated,
                message="; ".join(self.errors[:5]),
            ),
            scopes=tuple(self.scopes),
            symbols=tuple(self.symbols),
            nodes=tuple(self.nodes[:MAX_WALK_NODES]),
            returns=tuple(self.returns),
            events=tuple(self.events),
            file_context=_file_context(self.file_path),
        )

    def walk(self, node: object, *, depth: int = 0, in_data: bool = False) -> None:
        if self._visited >= MAX_WALK_NODES or depth > MAX_NESTING:
            self.truncated = True
            return
        self._visited += 1
        ntype = str(getattr(node, "type", ""))
        is_error = ntype == "ERROR" or bool(getattr(node, "is_missing", False))
        if is_error:
            try:
                self.error_spans.append(span_from_ts_node(node))
            except Exception:
                pass
            if not in_data:
                self._extract_recovered_calls(node)
        grammar = self.grammar
        data_node = ntype in grammar.string_types or ntype in grammar.comment_types
        # Interpolations are executable even though they sit inside strings.
        interpolating = ntype in grammar.interpolation_types
        child_in_data = (in_data or data_node) and not interpolating

        if not in_data:
            self._visit_code_node(node, ntype)

        if data_node and not interpolating:
            # Still walk interpolation children of template/encapsed strings.
            for child in getattr(node, "children", ()) or ():
                ctype = str(getattr(child, "type", ""))
                if ctype in grammar.interpolation_types:
                    self.walk(child, depth=depth + 1, in_data=False)
            return

        pushed = False
        if not in_data and ntype in grammar.function_types:
            pushed = self._enter_function(node, ntype)
        elif not in_data and ntype in grammar.class_types:
            pushed = self._enter_class(node, ntype)

        for child in getattr(node, "children", ()) or ():
            self.walk(child, depth=depth + 1, in_data=child_in_data)

        if pushed:
            self._scope_stack.pop()
            if ntype in grammar.class_types and self._class_stack:
                self._class_stack.pop()

    def _visit_code_node(self, node: object, ntype: str) -> None:
        grammar = self.grammar
        span = _safe_span(node)
        if ntype in grammar.import_types or (
            self.language_id == "ruby"
            and ntype == "call"
            and self._text(node).startswith("require")
        ):
            self._extract_import(node, ntype, span)
        if ntype in grammar.call_types or ntype in grammar.constructor_types:
            self._extract_call(node, ntype, span)
        if ntype == "jsx_attribute":
            self._extract_jsx_attribute(node, span)
        if ntype in grammar.assignment_types:
            self._extract_assignment(node, ntype, span)
        if ntype in grammar.return_types:
            self._extract_return(node, span)
        if ntype == "binary_expression":
            self._extract_binary(node, span)
        if ntype == "variable_declaration":
            text = self._text(node)
            if text.lstrip().startswith("var "):
                self.events.append(
                    SyntaxEvent(kind="var_decl", line=_line(span), text=text[:200], span=span)
                )
        if ntype == "with_statement":
            self.events.append(
                SyntaxEvent(
                    kind="with_stmt", line=_line(span), text=self._text(node)[:200], span=span
                )
            )
        if ntype in {"catch_clause", "catch_block", "except_clause", "rescue"}:
            self._extract_catch(node, ntype, span)
        if ntype in grammar.field_types:
            self._record_node(SemanticKind.PROPERTY, self._first_identifier(node), span, ntype)

    def _enter_function(self, node: object, ntype: str) -> bool:
        name = self._declared_name(node) or "anonymous"
        parent = self._class_stack[-1] if self._class_stack else None
        is_method = parent is not None
        kind = ScopeKind.METHOD if is_method else ScopeKind.FUNCTION
        scope_id = f"{self.current_scope.scope_id}/{kind.value}:{name}"
        span = _safe_span(node)
        scope = Scope(
            scope_id=scope_id,
            kind=kind,
            name=name,
            parent_id=self.current_scope.scope_id,
            span=span,
        )
        self._scope_stack.append(scope)
        self.scopes.append(scope)
        params = self._parameters(node)
        entity_type = "method" if is_method else "function"
        if "async" in self._text(node).split("{", 1)[0][:80]:
            entity_type = "async_method" if is_method else "async_function"
        qn = f"{parent}.{name}" if parent else name
        self.entities.append(
            ParsedEntity(
                entity_type=entity_type,
                name=name,
                qualified_name=qn,
                start_line=span.start_line if span else 1,
                end_line=span.end_line if span else 1,
                start_column=span.start_column if span else 1,
                end_column=span.end_column if span else 1,
                start_byte=span.start_byte if span else 0,
                end_byte=span.end_byte if span else 0,
                parameters=params,
                parent=parent,
                node_id=self._nid("function", span, name),
            )
        )
        self._record_node(
            SemanticKind.METHOD if is_method else SemanticKind.FUNCTION, name, span, ntype
        )
        for param in params:
            extras = self._param_sources.pop(param.name, ())
            self._bind_parameter(param.name, span, callees=extras)
        return True

    def _enter_class(self, node: object, ntype: str) -> bool:
        name = self._declared_name(node) or "anonymous"
        span = _safe_span(node)
        scope_id = f"{self.current_scope.scope_id}/class:{name}"
        scope = Scope(
            scope_id=scope_id,
            kind=ScopeKind.CLASS,
            name=name,
            parent_id=self.current_scope.scope_id,
            span=span,
        )
        self._scope_stack.append(scope)
        self.scopes.append(scope)
        self._class_stack.append(name)
        entity_type = _class_entity_type(ntype)
        self.entities.append(
            ParsedEntity(
                entity_type=entity_type,
                name=name,
                qualified_name=name,
                start_line=span.start_line if span else 1,
                end_line=span.end_line if span else 1,
                start_column=span.start_column if span else 1,
                end_column=span.end_column if span else 1,
                start_byte=span.start_byte if span else 0,
                end_byte=span.end_byte if span else 0,
                parent=self._class_stack[-2] if len(self._class_stack) > 1 else None,
                node_id=self._nid("class", span, name),
            )
        )
        self._record_node(SemanticKind.CLASS, name, span, ntype)
        return True

    def _extract_call(self, node: object, ntype: str, span: SourceSpan | None) -> None:
        grammar = self.grammar
        if ntype in {"echo_statement", "print_intrinsic"}:
            qualified = (
                "echo"
                if "echo" in ntype or self._text(node).lstrip().startswith("echo")
                else "print"
            )
            args_node = node
            kind = CallKind.BARE
        elif ntype == "command":
            qualified = self._command_name(node)
            args_node = node
            kind = CallKind.DIRECT
        elif ntype == "script_element":
            qualified = "script"
            args_node = node
            kind = CallKind.DIRECT
        elif ntype == "shell_command_expression":
            qualified = "backtick"
            args_node = node
            kind = CallKind.BARE
        elif ntype == "macro_invocation":
            qualified = self._qualified(node) or self._first_identifier(node)
            args_node = node
            kind = CallKind.MACRO
        elif ntype in grammar.constructor_types:
            qualified = self._constructor_name(node)
            args_node = _child_by_field(node, "arguments") or node
            kind = CallKind.CONSTRUCTOR
        else:
            qualified, kind = self._callee_qualified(node)
            args_node = _child_by_field(node, "arguments") or node
        name = qualified.rsplit(".", 1)[-1].rsplit("::", 1)[-1].rsplit("->", 1)[-1]
        if not name or name.lower() in _NON_CALL_NAMES:
            # Keywords such as ``new`` / ``catch`` / ``if`` are not calls, but
            # qualified method names (Command::new, .catch) and dynamic
            # ``import()`` / ``require()`` are real calls.
            keep_qualified = any(sep in qualified for sep in (".", "::", "->"))
            keep_import = name.lower() in {"import", "require"}
            keep_ctor = ntype in grammar.constructor_types or kind is CallKind.CONSTRUCTOR
            if (
                not keep_qualified
                and not keep_import
                and not keep_ctor
                and ntype
                not in {
                    "echo_statement",
                    "print_intrinsic",
                    "command",
                    "script_element",
                }
            ):
                return
        skip_callee = args_node is node
        args_meta = self._expression_meta(args_node, skip_callee=skip_callee)
        arg_text = self._argument_text(node)
        self.calls.append(
            CallSite(
                name=name or qualified,
                qualified=qualified or name,
                line=_line(span),
                argument_text=arg_text,
                dynamic=args_meta.dynamic,
                kind=kind,
                span=span,
                node_id=self._nid("call", span, qualified),
                scope_id=self.current_scope.scope_id,
                argument_is_literal=args_meta.is_literal,
                argument_idents=args_meta.idents,
                argument_accesses=args_meta.accesses + args_meta.callees,
            )
        )
        self._record_node(SemanticKind.CALL, qualified or name, span, ntype)
        if name in {"require", "import"} or qualified in {"require", "import"}:
            self._import_from_call(name or qualified, arg_text, span)

    def _extract_jsx_attribute(self, node: object, span: SourceSpan | None) -> None:
        name = ""
        value = None
        for child in getattr(node, "named_children", None) or getattr(node, "children", ()) or ():
            ctype = str(getattr(child, "type", ""))
            if ctype in {"property_identifier", "identifier", "jsx_attribute_name"} and not name:
                name = self._normalize_ident(self._text(child))
            elif ctype in {"jsx_expression", "string", "number"}:
                value = child
        if not name:
            return
        meta = self._expression_meta(value) if value is not None else _ExprMeta()
        self.calls.append(
            CallSite(
                name=name,
                qualified=name,
                line=_line(span),
                argument_text=self._text(value) if value is not None else "",
                dynamic=meta.dynamic,
                kind=CallKind.MEMBER_WRITE,
                span=span,
                node_id=self._nid("jsx", span, name),
                scope_id=self.current_scope.scope_id,
                argument_is_literal=meta.is_literal,
                argument_idents=meta.idents,
                argument_accesses=meta.accesses + meta.callees,
            )
        )

    def _import_from_call(self, callee: str, argument_text: str, span: SourceSpan | None) -> None:
        module = self._strip_quotes(argument_text.strip().strip("()").split(",")[0].strip())
        if not module or any(ch in module for ch in "(){};"):
            return
        kind = "require" if callee == "require" else "import"
        self.imports.append(
            ParsedImport(
                module=module,
                line_number=_line(span),
                import_type=kind,
                syntax_kind=kind,
                column=span.start_column if span else 1,
                start_byte=span.start_byte if span else 0,
                end_byte=span.end_byte if span else 0,
            )
        )

    def _extract_assignment(self, node: object, ntype: str, span: SourceSpan | None) -> None:
        left = _child_by_field(node, "left") or _child_by_field(node, "name") or _first_named(node)
        right = (
            _child_by_field(node, "right")
            or _child_by_field(node, "value")
            or _assignment_rhs(node)
        )
        names = self._assignment_names(left if left is not None else node)
        if not names:
            names = self._assignment_names(node)
        rhs_text = self._text(right) if right is not None else ""
        meta = self._expression_meta(right) if right is not None else _ExprMeta()
        # Member writes (el.innerHTML = q) are also sink-shaped CallSites.
        left_type = str(getattr(left, "type", "")) if left is not None else ""
        if left is not None and left_type in self.grammar.member_types:
            left_qual = self._qualified(left)
            prop = left_qual.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
            self.calls.append(
                CallSite(
                    name=prop,
                    qualified=left_qual or prop,
                    line=_line(span),
                    argument_text=rhs_text,
                    dynamic=meta.dynamic,
                    kind=CallKind.MEMBER_WRITE,
                    span=span,
                    node_id=self._nid("write", span, left_qual),
                    scope_id=self.current_scope.scope_id,
                    argument_is_literal=meta.is_literal,
                    argument_idents=meta.idents,
                    argument_accesses=meta.accesses + meta.callees,
                )
            )
        for name in names:
            kind = (
                SymbolKind.FIELD if self.current_scope.kind is ScopeKind.CLASS else SymbolKind.LOCAL
            )
            binding = Binding(
                name=name,
                line=_line(span),
                rhs=rhs_text[:500],
                scope_id=self.current_scope.scope_id,
                kind=kind,
                span=span,
                node_id=self._nid("bind", span, name),
                rhs_is_literal=meta.is_literal,
                rhs_callees=meta.callees,
                rhs_accesses=meta.accesses,
                rhs_idents=meta.idents,
            )
            self.bindings.append(binding)
            self.symbols.append(
                Symbol(
                    symbol_id=binding.symbol_id,
                    name=name,
                    scope_id=binding.scope_id,
                    kind=kind,
                    span=span,
                    node_id=binding.node_id,
                )
            )
        self._record_node(SemanticKind.ASSIGNMENT, ",".join(names), span, ntype)

    def _extract_import(self, node: object, ntype: str, span: SourceSpan | None) -> None:
        text = self._text(node)
        module = ""
        imported: str | None = None
        alias: str | None = None
        is_from = "from" in ntype or "from " in text
        syntax_kind = self.grammar.import_kind
        source_node = _child_by_field(node, "source")
        if source_node is not None:
            module = self._strip_quotes(self._text(source_node))
        if ntype in {"preproc_include"}:
            module = text.replace("#include", "").strip().strip('<>"')
            syntax_kind = "include"
        elif ntype in {"import_spec"}:
            module = self._strip_quotes(text)
        elif ntype == "using_directive":
            module = text.replace("using", "").replace(";", "").strip()
            syntax_kind = "using"
        elif ntype in {"use_declaration", "namespace_use_declaration", "import_header"}:
            module = (
                text.replace("use ", "")
                .replace("import ", "")
                .replace(";", "")
                .split(" as ")[0]
                .split("{")[0]
                .strip()
            )
            syntax_kind = "use" if "use" in ntype else "import"
        elif not module:
            # Generic: last string literal is the module path.
            strings = [
                self._strip_quotes(self._text(c))
                for c in _walk_named(node, 8)
                if str(getattr(c, "type", ""))
                in self.grammar.string_types | {"string", "interpreted_string_literal"}
            ]
            if strings:
                module = strings[-1]
            idents = [
                self._text(c)
                for c in _walk_named(node, 6)
                if str(getattr(c, "type", "")) in self.grammar.identifier_types
            ]
            if not module and idents:
                module = idents[0]
            if is_from and len(idents) > 1:
                imported = idents[-1]
        if "require" in text:
            syntax_kind = "require"
        relative = module.startswith(".") or module.startswith("./") or ntype.find("relative") >= 0
        import_type = "relative" if relative else syntax_kind
        if not module:
            return
        # Avoid duplicating import_statement's children if we also visit import_spec.
        if ntype == "import_declaration" and any(
            str(getattr(c, "type", "")) == "import_spec"
            for c in getattr(node, "children", ()) or ()
        ):
            return
        if ntype == "import_clause":
            return
        self.imports.append(
            ParsedImport(
                module=module,
                name=imported,
                alias=alias,
                line_number=_line(span),
                is_from_import=is_from,
                import_type=import_type,
                column=span.start_column if span else 1,
                start_byte=span.start_byte if span else 0,
                end_byte=span.end_byte if span else 0,
                syntax_kind=syntax_kind,
            )
        )
        self._record_node(SemanticKind.IMPORT, module, span, ntype)

    def _extract_return(self, node: object, span: SourceSpan | None) -> None:
        meta = self._expression_meta(node)
        self.returns.append(
            ReturnSite(
                scope_id=self.current_scope.scope_id,
                line=_line(span),
                text=self._text(node)[:300],
                idents=meta.idents,
                accesses=meta.accesses + meta.callees,
                span=span,
            )
        )
        self._record_node(SemanticKind.RETURN, "return", span, str(getattr(node, "type", "")))

    def _extract_binary(self, node: object, span: SourceSpan | None) -> None:
        text = self._text(node)
        op = None
        for child in getattr(node, "children", ()) or ():
            if not getattr(child, "is_named", True):
                tok = self._text(child).strip()
                if tok in {"==", "!=", "===", "!=="}:
                    op = tok
                    break
        if op in {"==", "!="}:
            self.events.append(
                SyntaxEvent(kind="loose_eq", line=_line(span), text=text[:200], span=span, extra=op)
            )

    def _extract_catch(self, node: object, ntype: str, span: SourceSpan | None) -> None:
        body = None
        for child in getattr(node, "children", ()) or ():
            if str(getattr(child, "type", "")) in {
                "statement_block",
                "block",
                "compound_statement",
                "function_body",
            }:
                body = child
                break
        text = self._text(body if body is not None else node)
        meaningful = [
            c
            for c in (getattr(body, "named_children", None) or getattr(body, "children", ()) or ())
            if getattr(c, "is_named", False)
            and str(getattr(c, "type", "")) not in self.grammar.comment_types
        ]
        comment_text = " ".join(
            self._text(c)
            for c in (getattr(body, "children", ()) or ())
            if str(getattr(c, "type", "")) in self.grammar.comment_types
        ).lower()
        intentional = any(
            token in comment_text
            for token in ("intentionally", "ignore", "expected", "noop", "no-op")
        )
        empty = body is not None and not meaningful
        self.events.append(
            SyntaxEvent(
                kind="empty_catch" if empty and not intentional else "catch",
                line=_line(span),
                text=text[:200],
                span=span,
                extra="intentional" if intentional else "",
            )
        )
        self._record_node(SemanticKind.EXCEPTION_HANDLER, "catch", span, ntype)

    def _bind_parameter(
        self, name: str, span: SourceSpan | None, *, callees: tuple[str, ...] = ()
    ) -> None:
        if not name:
            return
        binding = Binding(
            name=name,
            line=_line(span),
            rhs="",
            scope_id=self.current_scope.scope_id,
            kind=SymbolKind.PARAMETER,
            span=span,
            node_id=self._nid("param", span, name),
            rhs_callees=callees,
        )
        self.bindings.append(binding)
        self.symbols.append(
            Symbol(
                symbol_id=binding.symbol_id,
                name=name,
                scope_id=binding.scope_id,
                kind=SymbolKind.PARAMETER,
                span=span,
            )
        )

    def _decorator_names(self, node: object) -> tuple[str, ...]:
        names: list[str] = []
        for child in _walk_named(node, 12):
            ctype = str(getattr(child, "type", ""))
            if ctype == "decorator" or ctype in self.grammar.decorator_types:
                ident = self._first_identifier(child) or self._qualified(child)
                if ident:
                    names.append(ident.split("(")[0].lstrip("@"))
            elif ctype in self.grammar.call_types:
                parent_type = str(getattr(getattr(child, "parent", None), "type", ""))
                if parent_type in {"decorator", *self.grammar.decorator_types}:
                    ident = self._qualified(child) or self._first_identifier(child)
                    if ident:
                        names.append(ident)
        return _unique(names)

    def _extract_recovered_calls(self, node: object) -> None:
        children = list(getattr(node, "children", ()) or ())
        for index, child in enumerate(children):
            if str(getattr(child, "type", "")) not in self.grammar.identifier_types:
                continue
            nxt = children[index + 1] if index + 1 < len(children) else None
            if nxt is None or self._text(nxt).strip() != "(":
                continue
            name = self._normalize_ident(self._text(child))
            if not name or name.lower() in _NON_CALL_NAMES - {"import", "require"}:
                continue
            span = _safe_span(child)
            self.calls.append(
                CallSite(
                    name=name,
                    qualified=name,
                    line=_line(span),
                    argument_text=self._text(node)[:400],
                    dynamic=True,
                    kind=CallKind.DIRECT,
                    span=span,
                    node_id=self._nid("recover", span, name),
                    scope_id=self.current_scope.scope_id,
                    argument_is_literal=False,
                )
            )
            self._record_node(SemanticKind.CALL, name, span, "ERROR")

    def _parameters(self, node: object) -> list[ParsedParameter]:
        params: list[ParsedParameter] = []
        container = _child_by_field(node, "parameters") or node
        for child in _walk_named(container, 24):
            ctype = str(getattr(child, "type", ""))
            if ctype in {
                "required_parameter",
                "optional_parameter",
                "parameter",
                "simple_parameter",
                "parameter_declaration",
                "formal_parameter",
            }:
                name_node = _child_by_field(child, "name") or _child_by_field(child, "pattern")
                if name_node is not None:
                    name = self._normalize_ident(self._text(name_node))
                else:
                    idents = [
                        self._normalize_ident(self._text(c))
                        for c in _walk_named(child, 8)
                        if str(getattr(c, "type", "")) in self.grammar.identifier_types
                        and str(getattr(c, "type", "")) != "type_identifier"
                    ]
                    name = idents[-1] if idents else self._first_identifier(child)
                name = (name or "").lstrip("$").split(":")[0].split("=")[0].strip()
                if name and name not in _NON_CALL_NAMES:
                    params.append(ParsedParameter(name=name))
                    hints = self._decorator_names(child)
                    if hints:
                        self._param_sources[name] = hints
            elif (
                ctype in self.grammar.identifier_types
                and str(getattr(getattr(child, "parent", None), "type", ""))
                in self.grammar.parameter_container_types
                and ctype != "type_identifier"
            ):
                name = self._normalize_ident(self._text(child))
                if name and name not in _NON_CALL_NAMES:
                    params.append(ParsedParameter(name=name))
        # Dedup while preserving order
        seen: set[str] = set()
        unique: list[ParsedParameter] = []
        for p in params:
            if p.name in seen:
                continue
            seen.add(p.name)
            unique.append(p)
        return unique[:40]

    def _declared_name(self, node: object) -> str:
        ntype = str(getattr(node, "type", ""))
        parent = getattr(node, "parent", None)
        if (
            ntype
            in {
                "arrow_function",
                "function_expression",
                "generator_function",
                "generator_function_expression",
            }
            and parent is not None
            and str(getattr(parent, "type", "")) == "variable_declarator"
        ):
            decl = _child_by_field(parent, "name")
            if decl is not None and str(getattr(decl, "type", "")) in self.grammar.identifier_types:
                assigned = self._normalize_ident(self._text(decl))
                if assigned:
                    return assigned
        for field in (*self.grammar.name_fields, "declarator"):
            child = _child_by_field(node, field)
            if child is None:
                continue
            ntype = str(getattr(child, "type", ""))
            if ntype in self.grammar.identifier_types:
                text = self._normalize_ident(self._text(child))
                if text:
                    return text
            unwrapped = self._unwrap_declarator(child)
            if unwrapped:
                return unwrapped
            text = self._text(child).strip()
            if text:
                return text.split("(")[0].strip()
        for child in getattr(node, "named_children", None) or getattr(node, "children", ()) or ():
            if str(getattr(child, "type", "")) in self.grammar.identifier_types:
                return self._text(child).strip()
        return ""

    def _unwrap_declarator(self, node: object | None) -> str:
        current = node
        for _ in range(8):
            if current is None:
                return ""
            ntype = str(getattr(current, "type", ""))
            if ntype in self.grammar.identifier_types:
                return self._normalize_ident(self._text(current))
            inner = _child_by_field(current, "declarator") or _child_by_field(current, "name")
            if inner is None:
                if ntype in {
                    "function_declarator",
                    "pointer_declarator",
                    "parenthesized_declarator",
                    "array_declarator",
                    "reference_declarator",
                }:
                    current = _first_named(current)
                    continue
                return ""
            current = inner
        return ""

    def _assignment_names(self, node: object) -> list[str]:
        ntype = str(getattr(node, "type", ""))
        if ntype in self.grammar.identifier_types:
            name = self._normalize_ident(self._text(node))
            return [name] if name else []
        names: list[str] = []
        if ntype in {"object_pattern", "array_pattern", "destructuring_pattern", "tuple_pattern"}:
            for child in _walk_named(node, 8):
                if str(getattr(child, "type", "")) in self.grammar.identifier_types:
                    ident = self._normalize_ident(self._text(child))
                    if ident:
                        names.append(ident)
            return names
        if ntype in self.grammar.member_types:
            return []
        ident = self._first_identifier(node)
        if ident:
            names.append(self._normalize_ident(ident))
        return [n for n in names if n]

    def _expression_meta(self, node: object, *, skip_callee: bool = False) -> _ExprMeta:
        callees: list[str] = []
        accesses: list[str] = []
        idents: list[str] = []
        dynamic = False
        is_literal = True
        string_only = True
        first = True
        for child in _walk_named(node, 24):
            if first and skip_callee:
                first = False
                continue
            ctype = str(getattr(child, "type", ""))
            if ctype in self.grammar.comment_types:
                continue
            if ctype in self.grammar.string_types:
                continue
            if ctype in self.grammar.interpolation_types:
                dynamic = True
                string_only = False
                is_literal = False
                continue
            string_only = False
            if ctype in self.grammar.call_types or ctype in self.grammar.constructor_types:
                callees.append(self._qualified(child) or self._first_identifier(child))
                is_literal = False
            elif ctype in self.grammar.member_types:
                accesses.append(self._qualified(child))
                is_literal = False
            elif ctype in self.grammar.identifier_types:
                ident = self._normalize_ident(self._text(child))
                if ident and ident not in _NON_CALL_NAMES:
                    idents.append(ident)
                    is_literal = False
            elif ctype in {
                "binary_expression",
                "augmented_assignment_expression",
                "concatenated_string",
            }:
                dynamic = True
                is_literal = False
        if string_only:
            is_literal = True
        # concatenation operators as unnamed children
        for child in getattr(node, "children", ()) or ():
            if not getattr(child, "is_named", True) and self._text(child).strip() in {
                "+",
                "||",
                ".",
            }:
                dynamic = True
        return _ExprMeta(
            callees=tuple(x for x in callees if x),
            accesses=tuple(x for x in accesses if x),
            idents=_unique(idents),
            dynamic=dynamic,
            is_literal=is_literal,
        )

    def _callee_qualified(self, node: object) -> tuple[str, CallKind]:
        name_n = _child_by_field(node, "name")
        obj = _child_by_field(node, "object")
        func = _child_by_field(node, "function") or _child_by_field(node, "method")
        if name_n is not None:
            left = (
                self._qualified(obj)
                if obj is not None
                else (self._qualified(func) if func is not None else "")
            )
            right = self._normalize_ident(self._text(name_n))
            qualified = f"{left}.{right}" if left else right
            kind = CallKind.METHOD if left else CallKind.DIRECT
            return qualified, kind
        callee = func or _first_named(node)
        qualified = self._qualified(callee) if callee is not None else self._first_identifier(node)
        kind = (
            CallKind.METHOD
            if any(sep in qualified for sep in (".", "::", "->"))
            else CallKind.DIRECT
        )
        return qualified, kind

    def _qualified(self, node: object | None) -> str:
        if node is None:
            return ""
        ntype = str(getattr(node, "type", ""))
        if ntype in self.grammar.identifier_types:
            return self._normalize_ident(self._text(node))
        if ntype in self.grammar.string_types:
            return ""
        if ntype in self.grammar.call_types or ntype in self.grammar.constructor_types:
            func = _child_by_field(node, "function") or _child_by_field(node, "method")
            name_n = _child_by_field(node, "name")
            obj = _child_by_field(node, "object")
            if name_n is not None:
                left = (
                    self._qualified(obj)
                    if obj is not None
                    else (self._qualified(func) if func is not None else "")
                )
                right = self._normalize_ident(self._text(name_n))
                return f"{left}.{right}" if left else right
            if func is not None:
                return self._qualified(func)
        path = (
            _child_by_field(node, "path")
            or _child_by_field(node, "object")
            or _child_by_field(node, "expression")
            or _child_by_field(node, "value")
            or _child_by_field(node, "operand")
            or _child_by_field(node, "receiver")
            or _child_by_field(node, "target")
        )
        name = _child_by_field(node, "name") or _child_by_field(node, "field")
        if name is not None:
            left = self._qualified(path) if path is not None else ""
            right = (
                self._normalize_ident(self._text(name))
                if str(getattr(name, "type", "")) in self.grammar.identifier_types
                else self._qualified(name)
            )
            sep = _join_separator(node)
            if left and right:
                if sep == "::":
                    return f"{left}::{right}"
                if sep == "->":
                    return f"{left}->{right}"
                return f"{left}.{right}"
            return right or left
        parts: list[str] = []
        for child in getattr(node, "children", ()) or ():
            ctype = str(getattr(child, "type", ""))
            if ctype in self.grammar.comment_types or ctype in self.grammar.string_types:
                continue
            if ctype in {
                "arguments",
                "argument_list",
                "formal_parameters",
                "type_arguments",
                "type_annotation",
            }:
                continue
            if getattr(child, "is_named", False):
                piece = self._qualified(child)
            else:
                piece = self._text(child).strip()
            if piece and piece not in {"?", "!.", "?.", "(", ")", "[", "]"}:
                parts.append(piece)
        if parts:
            joined = parts[0]
            for piece in parts[1:]:
                if piece in {".", "::", "->"}:
                    if not joined.endswith(piece):
                        joined += piece
                elif joined.endswith((".", "::", "->")):
                    joined = f"{joined}{piece}"
                elif joined.endswith(":") or piece.startswith(":"):
                    joined = f"{joined}{piece}" if joined.endswith(":") else f"{joined}::{piece}"
                else:
                    joined = f"{joined}.{piece}"
            return joined.strip(".")
        return self._normalize_ident(self._text(node).split("(")[0])

    def _constructor_name(self, node: object) -> str:
        ctor = _child_by_field(node, "constructor") or _first_named(node)
        return self._qualified(ctor) or self._first_identifier(node)

    def _command_name(self, node: object) -> str:
        for child in getattr(node, "named_children", None) or getattr(node, "children", ()) or ():
            if str(getattr(child, "type", "")) in {"command_name", "word"}:
                return self._text(child).strip()
        return self._first_identifier(node)

    def _first_identifier(self, node: object) -> str:
        if str(getattr(node, "type", "")) in self.grammar.identifier_types:
            return self._normalize_ident(self._text(node))
        for child in _walk_named(node, 8):
            if str(getattr(child, "type", "")) in self.grammar.identifier_types:
                return self._normalize_ident(self._text(child))
        return ""

    def _normalize_ident(self, raw: str) -> str:
        text = raw.strip().strip("$")
        if self.grammar.dollar_idents:
            text = text.lstrip("$")
        return text.split("(")[0].strip()

    def _argument_text(self, node: object) -> str:
        args = _child_by_field(node, "arguments") or _child_by_field(node, "arguments")
        if args is None:
            text = self._text(node)
            if "(" in text and text.endswith(")"):
                return text[text.find("(") + 1 : -1]
            return text[:400]
        return self._text(args).strip("()")[:400]

    def _text(self, node: object | None) -> str:
        if node is None:
            return ""
        start = int(getattr(node, "start_byte", 0))
        end = int(getattr(node, "end_byte", 0))
        return self.source_bytes[start:end].decode("utf-8", errors="replace")

    def _strip_quotes(self, text: str) -> str:
        value = text.strip().strip(";")
        if len(value) >= 2 and value[0] in {'"', "'", "`"} and value[-1] == value[0]:
            return value[1:-1]
        return value.strip("<>")

    def _record_node(
        self, kind: SemanticKind, name: str, span: SourceSpan | None, language_type: str
    ) -> None:
        if span is None or len(self.nodes) >= MAX_WALK_NODES:
            return
        self.nodes.append(
            SemanticNode(
                node_id=self._nid(kind.value, span, name),
                kind=kind,
                name=name,
                span=span,
                parent_id=self.current_scope.scope_id,
                language_type=language_type,
            )
        )

    def _nid(self, kind: str, span: SourceSpan | None, name: str) -> str:
        self._node_seq += 1
        if span is None:
            return f"{self.language_id}:{kind}:{name}:{self._node_seq}"
        return f"{self.language_id}:{kind}:{span.start_byte}:{span.end_byte}:{name}"


class _ExprMeta:
    def __init__(
        self,
        callees: tuple[str, ...] = (),
        accesses: tuple[str, ...] = (),
        idents: tuple[str, ...] = (),
        dynamic: bool = False,
        is_literal: bool = True,
    ) -> None:
        self.callees = callees
        self.accesses = accesses
        self.idents = idents
        self.dynamic = dynamic
        self.is_literal = is_literal


def _join_separator(node: object) -> str:
    for child in getattr(node, "children", ()) or ():
        if getattr(child, "is_named", True):
            continue
        tok = str(getattr(child, "type", "") or "").strip()
        if tok in {"::", "->", "."}:
            return tok
    ntype = str(getattr(node, "type", ""))
    if ntype in {"scoped_identifier", "scoped_type_identifier"}:
        return "::"
    return "."


def _looks_like_php_code(source: str) -> bool:
    if "<?" in source:
        return False
    lowered = source.lower()
    return any(
        token in source or token in lowered
        for token in ("$", "$_GET", "$_POST", "echo ", "echo$", "eval(", "function ", "system(")
    )


def _looks_unparseable(source: str) -> bool:
    text = source.strip()
    if not text:
        return False
    pairs = {"(": ")", "[": "]", "{": "}"}
    closing = {")", "]", "}"}
    stack: list[str] = []
    for ch in text:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in closing:
            if not stack or stack.pop() != ch:
                return True
    if stack:
        return True
    return (not any(ch.isalnum() for ch in text)) and any(ch in "(){}[]" for ch in text)


def _safe_span(node: object) -> SourceSpan | None:
    try:
        return span_from_ts_node(node)
    except Exception:
        return None


def _line(span: SourceSpan | None) -> int:
    return span.start_line if span is not None else 1


def _child_by_field(node: object, field: str) -> object | None:
    fn = getattr(node, "child_by_field_name", None)
    if not callable(fn):
        return None
    try:
        return cast(object | None, fn(field))
    except Exception:
        return None


def _first_named(node: object) -> object | None:
    named = getattr(node, "named_children", None)
    if named:
        return cast(object, named[0])
    for child in getattr(node, "children", ()) or ():
        if getattr(child, "is_named", False):
            return cast(object, child)
    return None


def _assignment_rhs(node: object) -> object | None:
    children = [
        c for c in (getattr(node, "named_children", None) or ()) if getattr(c, "is_named", False)
    ]
    if len(children) >= 2:
        return cast(object, children[-1])
    return None


def _walk_named(node: object, limit: int) -> list[object]:
    out: list[object] = []
    stack = [node]
    while stack and len(out) < limit:
        cur = stack.pop()
        out.append(cur)
        children = list(getattr(cur, "named_children", None) or getattr(cur, "children", ()) or ())
        for child in reversed(children):
            if getattr(child, "is_named", True):
                stack.append(child)
    return out


def _unique(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return tuple(out)


def _class_entity_type(ntype: str) -> str:
    mapping = {
        "interface_declaration": "interface",
        "enum_declaration": "enum",
        "enum_item": "enum",
        "struct_item": "struct",
        "struct_specifier": "struct",
        "struct_declaration": "struct",
        "trait_item": "trait",
        "trait_declaration": "trait",
        "protocol_declaration": "interface",
        "actor_declaration": "class",
        "object_declaration": "class",
        "namespace_definition": "module",
        "mod_item": "module",
        "impl_item": "class",
        "type_alias_declaration": "type",
        "record_declaration": "class",
    }
    return mapping.get(ntype, "class")


def _file_context(path: str) -> str:
    lowered = path.replace("\\", "/").lower()
    if "/test" in lowered or lowered.startswith("test") or "/spec/" in lowered:
        return "test"
    if "generated" in lowered or "/vendor/" in lowered or "/node_modules/" in lowered:
        return "generated"
    if lowered.endswith((".html", ".htm")):
        return "template"
    return "unknown"


def attach_error_diagnostics(graph: SyntaxGraph, root: object) -> SyntaxGraph:
    spans = collect_error_spans(root)
    graph.diagnostics = ParserDiagnostics(
        has_errors=bool(spans) or graph.diagnostics.has_errors,
        error_count=len(spans),
        error_spans=spans,
        recoverable=True,
        truncated=graph.diagnostics.truncated,
        message=graph.diagnostics.message,
    )
    return graph
