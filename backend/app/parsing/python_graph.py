"""Python AST → SyntaxGraph. More precise than the profile parser."""

from __future__ import annotations

import ast
from pathlib import Path

from app.domain.source import ParsedEntity, ParsedImport, ParsedParameter
from app.parsing.model import Binding, CallSite, SyntaxGraph


def parse_python_graph(file_path: Path, source: str) -> SyntaxGraph:
    lines = tuple(source.splitlines() or [""])
    errors: list[str] = []
    imports: list[ParsedImport] = []
    entities: list[ParsedEntity] = []
    calls: list[CallSite] = []
    bindings: list[Binding] = []
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as exc:
        errors.append(f"SyntaxError at line {exc.lineno}: {exc.msg}")
        return SyntaxGraph(
            language="python",
            file_path=str(file_path),
            source=source,
            lines=lines,
            errors=tuple(errors),
        )

    visitor = _PythonGraphVisitor(imports, entities, calls, bindings)
    visitor.visit(tree)
    return SyntaxGraph(
        language="python",
        file_path=str(file_path),
        source=source,
        lines=lines,
        imports=tuple(imports),
        entities=tuple(entities),
        calls=tuple(calls),
        bindings=tuple(bindings),
        errors=tuple(errors),
    )


class _PythonGraphVisitor(ast.NodeVisitor):
    def __init__(
        self,
        imports: list[ParsedImport],
        entities: list[ParsedEntity],
        calls: list[CallSite],
        bindings: list[Binding],
    ) -> None:
        self.imports = imports
        self.entities = entities
        self.calls = calls
        self.bindings = bindings
        self._class: str | None = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(
                ParsedImport(
                    module=alias.name,
                    alias=alias.asname,
                    line_number=node.lineno,
                    is_from_import=False,
                    import_type="unknown",
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append(
                ParsedImport(
                    module=module,
                    name=alias.name,
                    alias=alias.asname,
                    line_number=node.lineno,
                    is_from_import=True,
                    import_type="relative" if (node.level or 0) > 0 else "unknown",
                )
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.entities.append(
            ParsedEntity(
                entity_type="class",
                name=node.name,
                qualified_name=node.name,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                docstring=ast.get_docstring(node),
                parent=self._class,
            )
        )
        prev = self._class
        self._class = node.name
        self.generic_visit(node)
        self._class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        is_async = isinstance(node, ast.AsyncFunctionDef)
        entity_type = (
            "async_method"
            if self._class and is_async
            else ("method" if self._class else ("async_function" if is_async else "function"))
        )
        qn = f"{self._class}.{node.name}" if self._class else node.name
        params = [
            ParsedParameter(name=arg.arg)
            for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        ]
        self.entities.append(
            ParsedEntity(
                entity_type=entity_type,
                name=node.name,
                qualified_name=qn,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                docstring=ast.get_docstring(node),
                parameters=params,
                parent=self._class,
            )
        )
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

    def visit_Assign(self, node: ast.Assign) -> None:
        rhs = _expr(node.value)
        for target in node.targets:
            name = _name_of(target)
            if name:
                self.bindings.append(Binding(name=name, line=node.lineno, rhs=rhs))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            name = _name_of(node.target)
            if name:
                self.bindings.append(Binding(name=name, line=node.lineno, rhs=_expr(node.value)))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qualified = _expr(node.func)
        name = qualified.rsplit(".", 1)[-1]
        args = ", ".join(_expr(a) for a in node.args)
        dynamic = any(
            isinstance(a, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)) for a in node.args
        ) or any(isinstance(a, ast.BinOp) for a in ast.walk(node))
        if not dynamic:
            dynamic = "+" in args or "{" in args
        self.calls.append(
            CallSite(
                name=name,
                qualified=qualified,
                line=node.lineno,
                argument_text=args,
                dynamic=dynamic,
            )
        )
        self.generic_visit(node)


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _expr(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__
