"""Solidity syntax graph.

Tree-sitter is the graph builder. A regex profile is used only when that
parser is unavailable, and that graph is labeled PROFILE_FALLBACK. solc is
not required. When solc happens to be installed, compile success is recorded
as a diagnostic and does not replace this graph.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.domain.language import ParserTier
from app.domain.source import ParsedEntity, ParsedImport, ParsedParameter
from app.parsing.extract import parse_with_profile
from app.parsing.keccak import function_selector
from app.parsing.model import (
    CallKind,
    CallSite,
    LanguageProfile,
    ParserDiagnostics,
    ParserStatus,
    Scope,
    ScopeKind,
    SemanticKind,
    SemanticNode,
    Symbol,
    SymbolKind,
    SyntaxEvent,
    SyntaxGraph,
)
from app.parsing.profiles import profile_for
from app.parsing.span import span_from_ts_node

_PRIMITIVE = {
    "address": "address",
    "bool": "bool",
    "string": "string",
    "bytes": "bytes",
    "uint": "uint256",
    "int": "int256",
}
_LOW_LEVEL = frozenset({"call", "delegatecall", "staticcall", "transfer", "send"})


def parse_solidity_source(file_path: Path, source: str) -> SyntaxGraph:
    graph = _from_treesitter(file_path, source)
    if graph is not None:
        return graph
    return _profile_fallback(file_path, source, reason="native parser unavailable")


def _from_treesitter(file_path: Path, source: str) -> SyntaxGraph | None:
    try:
        import tree_sitter_language_pack as pack
        from tree_sitter import Parser
    except ImportError:
        return None
    try:
        language = pack.get_language("solidity")
    except (LookupError, OSError, ValueError):
        return None
    except Exception:
        return None
    parser = Parser(language)
    raw = source.encode("utf-8", errors="replace")
    tree = parser.parse(raw)
    builder = _Builder(file_path, source, raw)
    builder.consume(tree.root_node)
    has_error = bool(getattr(tree.root_node, "has_error", False))
    builder.graph.diagnostics = ParserDiagnostics(
        has_errors=has_error,
        error_count=1 if has_error else 0,
        recoverable=True,
        native_available=True,
        status=ParserStatus.NATIVE_AVAILABLE,
        message="tree-sitter solidity",
    )
    builder.graph.parser_backend = "tree_sitter"
    builder.graph.parser_tier = ParserTier.FULL_AST
    return builder.graph


def _profile_fallback(file_path: Path, source: str, *, reason: str) -> SyntaxGraph:
    profile = profile_for("solidity")
    if profile is None:
        profile = LanguageProfile(
            language_id="solidity", display_name="Solidity", extensions=frozenset({".sol"})
        )
    graph = parse_with_profile(profile, file_path, source)
    graph.parser_backend = "profile"
    graph.parser_tier = ParserTier.PROFILE_FALLBACK
    graph.diagnostics = ParserDiagnostics(
        native_available=False,
        status=ParserStatus.PROFILE_FALLBACK,
        fallback_reason=reason,
        message=reason,
    )
    return graph


class _Builder:
    def __init__(self, file_path: Path, source: str, raw: bytes) -> None:
        self.raw = raw
        self.graph = SyntaxGraph(
            language="solidity",
            file_path=str(file_path),
            source=source,
            lines=tuple(source.splitlines()),
            scopes=(Scope("module", ScopeKind.MODULE, "module"),),
        )
        self._imports: list[ParsedImport] = []
        self._entities: list[ParsedEntity] = []
        self._calls: list[CallSite] = []
        self._nodes: list[SemanticNode] = []
        self._symbols: list[Symbol] = []
        self._events: list[SyntaxEvent] = []
        self._scopes: list[Scope] = [self.graph.scopes[0]]
        self._node_index = 0
        self._floor: tuple[int, int, int] | None = None

    def consume(self, root: object) -> None:
        for child in _children(root):
            kind = _type(child)
            if kind == "pragma_directive":
                self._pragma(child)
            elif kind == "import_directive":
                self._import(child)
            elif kind in {"contract_declaration", "interface_declaration", "library_declaration"}:
                self._contract(child, kind)
            elif kind in {"struct_declaration", "enum_declaration"}:
                self._named(child, kind.removesuffix("_declaration"))
        context = ["solidity"]
        if self._floor is None:
            context.append("compiler_floor=unknown")
        else:
            context.append(f"compiler_floor={self._floor[0]}.{self._floor[1]}.{self._floor[2]}")
            context.append(
                "checked_arithmetic=" + ("true" if self._floor >= (0, 8, 0) else "false")
            )
        self.graph.semantic_context = tuple(context)
        self.graph.imports = tuple(self._imports)
        self.graph.entities = tuple(self._entities)
        self.graph.calls = tuple(self._calls)
        self.graph.nodes = tuple(self._nodes)
        self.graph.symbols = tuple(self._symbols)
        self.graph.events = tuple(self._events)
        self.graph.scopes = tuple(self._scopes)

    def _pragma(self, node: object) -> None:
        text = self._text(node)
        version = _child_text(self, node, "solidity_version")
        match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version or text)
        if match:
            self._floor = (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
        self._event("sol_pragma", node, text)
        if ">=" in text and "<" not in text:
            self._event("sol_pragma_unbounded", node, text)

    def _import(self, node: object) -> None:
        text = self._text(node)
        module = ""
        for child in _descendants(node):
            if _type(child) == "string":
                module = self._text(child).strip().strip('"').strip("'")
        span = span_from_ts_node(node)
        self._imports.append(
            ParsedImport(
                module=module or text,
                line_number=span.start_line,
                is_from_import=" from " in text,
                import_type="relative" if module.startswith(".") else "local",
                column=span.start_column,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
                syntax_kind="import",
            )
        )
        self._event("sol_import", node, module or text)

    def _contract(self, node: object, kind: str) -> None:
        name = _child_text(self, node, "identifier") or "contract"
        entity_kind = {
            "contract_declaration": "contract",
            "interface_declaration": "interface",
            "library_declaration": "library",
        }[kind]
        span = span_from_ts_node(node)
        scope_id = f"module::{name}"
        self._scopes.append(Scope(scope_id, ScopeKind.CLASS, name, parent_id="module", span=span))
        bases = [
            self._text(child)
            for child in _descendants(node)
            if _type(child) == "inheritance_specifier"
        ]
        state: dict[str, str] = {}
        body = _first(node, "contract_body")
        if body is not None:
            for child in _children(body):
                if _type(child) == "state_variable_declaration":
                    var_name, mutability = self._state_var(child, name, scope_id)
                    if var_name:
                        state[var_name] = mutability
                elif _type(child) == "using_directive":
                    self._event("sol_using", child, self._text(child), extra=f"contract={name}")
                elif _type(child) == "modifier_definition":
                    self._named(child, "modifier", parent=name)
                elif _type(child) in {
                    "event_definition",
                    "error_declaration",
                    "struct_declaration",
                    "enum_declaration",
                }:
                    self._named(child, _type(child).split("_", 1)[0], parent=name)
        self._entities.append(
            ParsedEntity(
                entity_type=entity_kind,
                name=name,
                qualified_name=name,
                start_line=span.start_line,
                end_line=span.end_line,
                parent=None,
                start_column=span.start_column,
                end_column=span.end_column,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
                node_id=self._add_node(entity_kind, name, node, extra=",".join(bases)),
            )
        )
        self._event(
            "sol_contract",
            node,
            name,
            extra=f"kind={entity_kind}|bases={','.join(bases)}",
        )
        if body is None:
            return
        for child in _children(body):
            if _type(child) in {
                "function_definition",
                "constructor_definition",
                "fallback_receive_definition",
                "modifier_definition",
            }:
                if _type(child) == "modifier_definition":
                    continue
                self._function(child, name, scope_id, state)

    def _function(
        self, node: object, contract: str, parent_scope: str, state: dict[str, str]
    ) -> None:
        name = _child_text(self, node, "identifier")
        label = _type(node)
        if label == "constructor_definition":
            name = "constructor"
        if label == "fallback_receive_definition":
            name = "receive" if "receive" in self._text(node).lstrip()[:12] else "fallback"
        name = name or "function"
        visibility = ""
        mutability = ""
        modifiers: list[str] = []
        override = False
        params: list[ParsedParameter] = []
        for child in _children(node):
            ctype = _type(child)
            if ctype == "visibility":
                visibility = self._text(child).strip()
            elif ctype == "state_mutability":
                mutability = self._text(child).strip()
            elif ctype == "modifier_invocation":
                modifiers.append(self._text(child).strip())
            elif ctype == "override_specifier":
                override = True
            elif ctype == "parameter" and _parent_is_return(child, node) is False:
                pname = _child_text(self, child, "identifier")
                ptype = _child_text(self, child, "type_name") or _child_text(
                    self, child, "primitive_type"
                )
                if pname:
                    params.append(ParsedParameter(name=pname, annotation=ptype))
        body = _first(node, "function_body")
        span = span_from_ts_node(node)
        scope_id = f"{parent_scope}::{name}:{span.start_line}"
        self._scopes.append(
            Scope(scope_id, ScopeKind.FUNCTION, name, parent_id=parent_scope, span=span)
        )
        selector = ""
        if name not in {"constructor", "fallback", "receive"} and params:
            types = [_canonical_type(param.annotation or "") for param in params]
            if all(types):
                selector = function_selector(f"{name}({','.join(types)})")
        self._entities.append(
            ParsedEntity(
                entity_type="function",
                name=name,
                qualified_name=f"{contract}.{name}",
                start_line=span.start_line,
                end_line=span.end_line,
                decorators=list(modifiers),
                parameters=params,
                parent=contract,
                start_column=span.start_column,
                end_column=span.end_column,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
                node_id=self._add_node(
                    SemanticKind.FUNCTION.value,
                    name,
                    node,
                    extra=selector,
                ),
            )
        )
        extra = "|".join(
            [
                f"contract={contract}",
                f"function={name}",
                f"visibility={visibility}",
                f"mutability={mutability}",
                f"modifiers={','.join(modifiers)}",
                f"override={str(override).lower()}",
                f"selector={selector}",
                f"payable={str(mutability == 'payable' or 'payable' in self._text(node)).lower()}",
            ]
        )
        self._event("sol_function", node, self._text(node), extra=extra)
        if override:
            self._event("sol_override", node, name, extra=f"contract={contract}")
        inner = "" if body is None else self._text(body).strip().strip("{}").strip()
        if not inner:
            if name in {"fallback", "receive"}:
                self._event("sol_empty_handler", node, name, extra=f"contract={contract}")
            return
        statements = [child for child in _descendants(body) if _type(child) == "statement"]
        # Direct statements only, so following-statement checks stay local.
        direct = [child for child in _children(body) if _type(child) == "statement"]
        for index, statement in enumerate(direct or statements):
            self._statement(
                statement,
                contract,
                name,
                scope_id,
                state,
                direct[index + 1 : index + 3] if direct else [],
            )

    def _statement(
        self,
        statement: object,
        contract: str,
        function: str,
        scope_id: str,
        state: dict[str, str],
        following: list[object],
    ) -> None:
        text = self._text(statement)
        prefix = f"contract={contract}|function={function}"
        for node in _descendants(statement):
            kind = _type(node)
            if kind == "call_expression":
                self._call(node, function, scope_id, prefix, text, following)
            elif kind in {"assignment_expression", "augmented_assignment_expression"}:
                self._write(node, state, prefix)
            elif kind == "unchecked":
                if re.search(r"[+\-*/]", text):
                    self._event("sol_unchecked", statement, text, extra=prefix)
            elif kind == "type_cast_expression":
                cast = self._text(node)
                if re.match(r"u?int(8|16|32|64|128)\s*\(", cast):
                    self._event("sol_downcast", node, cast, extra=prefix)
            elif kind == "for_statement":
                self._event("sol_loop", node, self._text(node), extra=prefix)
            elif kind == "assembly_statement":
                self._event("sol_assembly", node, self._text(node)[:180], extra=prefix)
            elif kind == "identifier" and self._text(node) == "ecrecover":
                self._event("sol_ecrecover", node, "ecrecover", extra=prefix)
            elif kind == "member_expression" and self._text(node) == "tx.origin":
                self._event("sol_tx_origin", node, "tx.origin", extra=prefix)
        if re.search(r"\w+\s*/\s*\w+\s*\*\s*\w+", text):
            self._event("sol_div_mul", statement, text, extra=prefix)
        if re.search(r"\b(throw|suicide)\b", text):
            self._event("sol_deprecated", statement, text, extra=prefix)

    def _call(
        self,
        node: object,
        function: str,
        scope_id: str,
        prefix: str,
        statement: str,
        following: list[object],
    ) -> None:
        text = self._text(node)
        head = re.split(r"[\(\{]", text, maxsplit=1)[0].strip()
        member = head.split(".")[-1].strip() if "." in head else ""
        target = head[: -len(member)].rstrip(".") if member else head
        checked = "require(" in statement or any(
            "require(" in self._text(item)
            or "if (" in self._text(item)
            or "if(" in self._text(item)
            for item in following
        )
        span = span_from_ts_node(node)
        self._calls.append(
            CallSite(
                name=member or target,
                qualified=text,
                line=span.start_line,
                argument_text=text,
                kind=CallKind.MEMBER if member else CallKind.DIRECT,
                span=span,
                scope_id=scope_id,
            )
        )
        extra = f"{prefix}|member={member}|target={target}|checked={str(checked).lower()}"
        if member in _LOW_LEVEL:
            self._event("sol_external_call", node, text, extra=extra + f"|kind={member}")
        if member in {"transfer", "transferFrom"} and "," in text:
            self._event("sol_erc20", node, text, extra=extra)
        if member == "delegatecall":
            self._event("sol_delegatecall", node, text, extra=extra)

    def _write(self, node: object, state: dict[str, str], prefix: str) -> None:
        text = self._text(node)
        lhs = re.split(r"\s*(?:=|\+=|-=|\*=|/=)\s*", text, maxsplit=1)[0]
        for name, mutability in state.items():
            if re.search(rf"\b{re.escape(name)}\b", lhs):
                self._event(
                    "sol_state_write",
                    node,
                    text,
                    extra=f"{prefix}|name={name}|mutability={mutability}",
                )

    def _state_var(self, node: object, contract: str, scope_id: str) -> tuple[str, str]:
        name = ""
        for child in _children(node):
            if _type(child) == "identifier":
                name = self._text(child)
        text = self._text(node)
        mutability = (
            "immutable" if "immutable" in text else "constant" if "constant" in text else "storage"
        )
        if name:
            self._symbols.append(
                Symbol(
                    Symbol.make_id(scope_id, name),
                    name,
                    scope_id,
                    SymbolKind.FIELD,
                    span_from_ts_node(node),
                )
            )
            self._event(
                "sol_state",
                node,
                text,
                extra=f"contract={contract}|name={name}|mutability={mutability}",
            )
        return name, mutability

    def _named(self, node: object, kind: str, parent: str | None = None) -> None:
        name = _child_text(self, node, "identifier") or kind
        span = span_from_ts_node(node)
        self._entities.append(
            ParsedEntity(
                entity_type=kind,
                name=name,
                qualified_name=f"{parent}.{name}" if parent else name,
                start_line=span.start_line,
                end_line=span.end_line,
                parent=parent,
                start_column=span.start_column,
                end_column=span.end_column,
                start_byte=span.start_byte,
                end_byte=span.end_byte,
                node_id=self._add_node(kind, name, node),
            )
        )
        self._event(f"sol_{kind}", node, name, extra=f"contract={parent or ''}")

    def _event(self, kind: str, node: object, text: str, extra: str = "") -> None:
        span = span_from_ts_node(node)
        self._events.append(
            SyntaxEvent(
                kind=kind, line=span.start_line, text=text[:400], span=span, extra=extra[:400]
            )
        )

    def _add_node(self, kind: str, name: str, node: object, extra: str = "") -> str:
        self._node_index += 1
        node_id = f"sol{self._node_index}"
        try:
            semantic = SemanticKind(kind)
        except ValueError:
            semantic = SemanticKind.TYPE
        self._nodes.append(
            SemanticNode(
                node_id=node_id,
                kind=semantic,
                name=name,
                span=span_from_ts_node(node),
                language_type=kind,
                extra=extra,
            )
        )
        return node_id

    def _text(self, node: object) -> str:
        return self.raw[int(getattr(node, "start_byte")) : int(getattr(node, "end_byte"))].decode(
            "utf-8", "replace"
        )


def _children(node: object) -> tuple[object, ...]:
    return tuple(getattr(node, "children", ()) or ())


def _type(node: object) -> str:
    return str(getattr(node, "type", ""))


def _descendants(node: object) -> list[object]:
    found: list[object] = []
    stack = list(_children(node))
    while stack:
        current = stack.pop()
        found.append(current)
        stack.extend(reversed(_children(current)))
    return found


def _first(node: object, kind: str) -> object | None:
    for child in _children(node):
        if _type(child) == kind:
            return child
    return None


def _child_text(builder: _Builder, node: object, kind: str) -> str:
    for child in _preorder(node):
        if child is not node and _type(child) == kind:
            return builder._text(child)
    return ""


def _preorder(node: object) -> list[object]:
    found: list[object] = []
    stack = [node]
    while stack:
        current = stack.pop()
        found.append(current)
        stack.extend(reversed(_children(current)))
    return found


def _parent_is_return(param: object, function: object) -> bool:
    """Parameters under return_type_definition are not inputs."""
    return_node = _first(function, "return_type_definition")
    if return_node is None:
        return False
    return param in _descendants(return_node) or param is return_node


def _canonical_type(annotation: str) -> str:
    text = (
        annotation.strip().replace(" memory", "").replace(" calldata", "").replace(" storage", "")
    )
    if not text or " " in text or text.endswith("]"):
        mapped = _PRIMITIVE.get(text)
        return mapped or ""
    if text in _PRIMITIVE:
        return _PRIMITIVE[text]
    if re.fullmatch(r"u?int\d+", text) or re.fullmatch(r"bytes\d+", text):
        return text
    return ""
