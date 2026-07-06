"""Source transformation pipeline used during package builds."""

from __future__ import annotations

import ast
import base64
import os
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from .models import TransformationConfig


@dataclass(slots=True, frozen=True)
class TransformArtifact:
    """Result of transforming a single source file."""

    source: str
    transform_flags: dict[str, bool]


def transform_source(
    source: str,
    *,
    module_name: str,
    config: TransformationConfig,
    deterministic_key: str | None = None,
) -> TransformArtifact:
    """Transform a source module according to the provided flags."""
    tree = ast.parse(source, filename=module_name)
    transformer = _ModuleTransformer(config=config, deterministic_key=deterministic_key)
    tree = transformer.visit(tree)
    if not isinstance(tree, ast.Module):
        raise TypeError("module transform failed")  # pragma: no cover
    ast.fix_missing_locations(tree)
    return TransformArtifact(source=ast.unparse(tree), transform_flags=_as_flags(config))


def _as_flags(config: TransformationConfig) -> dict[str, bool]:
    return {
        "rename_identifiers": config.rename_identifiers,
        "encrypt_strings": config.encrypt_strings,
        "hide_constants": config.hide_constants,
        "insert_dead_code": config.insert_dead_code,
        "flatten_control_flow": config.flatten_control_flow,
        "rewrite_imports": config.rewrite_imports,
    }


class _ScopeNameCollector(ast.NodeVisitor):
    """Collect local names in a function scope."""

    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if isinstance(node.ctx, ast.Store) and not node.id.startswith("__psb_"):
            self.names.add(node.id)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.name and not node.name.startswith("__psb_"):
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_alias(self, node: ast.alias) -> None:  # noqa: N802
        if node.asname and not node.asname.startswith("__psb_"):
            self.names.add(node.asname)


def _collect_local_names(body: Iterable[ast.stmt], args: ast.arguments) -> set[str]:
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    collector = _ScopeNameCollector()
    for statement in body:
        collector.visit(statement)
    names.update(collector.names)
    return {
        name
        for name in names
        if name and not name.startswith("__psb_") and name not in {"self", "cls"}
    }


class _ModuleTransformer(ast.NodeTransformer):
    def __init__(
        self, *, config: TransformationConfig, deterministic_key: str | None = None
    ) -> None:
        self.config = config
        self._scope_stack: list[dict[str, str]] = []
        self._module_imports: dict[str, str] = {}
        self._rename_counter = 0
        self._string_key = deterministic_key or base64.b64encode(os.urandom(16)).decode("ascii")
        self._need_string_helper = config.encrypt_strings
        self._need_int_helper = config.hide_constants

    def visit_Module(self, node: ast.Module) -> ast.Module:
        statements: list[ast.stmt] = []
        for statement in node.body:
            visited = self.visit(statement)
            statements.extend(_expand_nodes(visited))
        helpers: list[ast.stmt] = []
        if self._need_string_helper:
            helpers.append(_make_decode_helper(self._string_key))
        if self._need_int_helper:
            helpers.append(_make_xor_helper())
        if self.config.insert_dead_code:
            helpers.append(_make_dead_helper())
        node.body = helpers + statements
        return node

    def visit_Import(self, node: ast.Import) -> ast.stmt:
        if self._scope_stack:
            current_scope = self._scope_stack[-1]
            for alias in node.names:
                target_name = alias.asname or alias.name
                replacement = current_scope.get(target_name)
                if replacement is not None:
                    alias.asname = replacement
            return node
        if not self.config.rewrite_imports:
            return node
        rewritten: list[ast.alias] = []
        for alias in node.names:
            if alias.asname is None and alias.name.isidentifier():
                temp_name = self._next_name("imp")
                self._module_imports[alias.name] = temp_name
                rewritten.append(ast.alias(name=alias.name, asname=temp_name))
            else:
                rewritten.append(alias)
        node.names = rewritten
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> ast.stmt | list[ast.stmt]:
        if (
            not self.config.rewrite_imports
            or self._scope_stack
            or any(alias.name == "*" for alias in node.names)
            or node.level
        ):
            return node
        module_name = node.module or ""
        temp_module = self._next_name("mod")
        import_stmt = ast.Import(names=[ast.alias(name=module_name, asname=temp_module)])
        assignments: list[ast.stmt] = []
        for alias in node.names:
            target_name = alias.asname or alias.name
            assignments.append(
                ast.Assign(
                    targets=[ast.Name(id=target_name, ctx=ast.Store())],
                    value=ast.Attribute(
                        value=ast.Name(id=temp_module, ctx=ast.Load()),
                        attr=alias.name,
                        ctx=ast.Load(),
                    ),
                )
            )
        return [import_stmt, *assignments]

    def visit_FunctionDef(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> ast.FunctionDef | ast.AsyncFunctionDef:
        mapping = self._build_scope_mapping(node.body, node.args)
        self._scope_stack.append(mapping)
        try:
            node.args = self._rename_arguments(node.args, mapping)
            node.body = self._visit_stmt_list(node.body)
            if self.config.flatten_control_flow and isinstance(node, ast.FunctionDef):
                node = self._maybe_flatten(node)
            if self.config.insert_dead_code:
                node.body = [self._dead_block(), *node.body]
        finally:
            self._scope_stack.pop()
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        return cast(ast.AsyncFunctionDef, self.visit_FunctionDef(node))

    def visit_Name(self, node: ast.Name) -> ast.AST:
        for scope in reversed(self._scope_stack):
            replacement = scope.get(node.id)
            if replacement is not None:
                return ast.copy_location(ast.Name(id=replacement, ctx=node.ctx), node)
        replacement = self._module_imports.get(node.id)
        if replacement is not None:
            return ast.copy_location(ast.Name(id=replacement, ctx=node.ctx), node)
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.ExceptHandler:
        if node.name is not None:
            for scope in reversed(self._scope_stack):
                replacement = scope.get(node.name)
                if replacement is not None:
                    node.name = replacement
                    break
        node.body = self._visit_stmt_list(node.body)
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if self.config.encrypt_strings and isinstance(node.value, str):
            return ast.copy_location(
                ast.Call(
                    func=ast.Name(id="__psb_decode", ctx=ast.Load()),
                    args=[ast.Constant(value=_xor_encode(node.value, self._string_key))],
                    keywords=[],
                ),
                node,
            )
        if (
            self.config.hide_constants
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            seed = abs(node.value) + self._rename_counter + 1
            return ast.copy_location(
                ast.Call(
                    func=ast.Name(id="__psb_xor", ctx=ast.Load()),
                    args=[ast.Constant(value=seed), ast.Constant(value=seed ^ node.value)],
                    keywords=[],
                ),
                node,
            )
        return node

    def _visit_stmt_list(self, statements: Iterable[ast.stmt]) -> list[ast.stmt]:
        result: list[ast.stmt] = []
        for statement in statements:
            visited = self.visit(statement)
            result.extend(_expand_nodes(visited))
        return result

    def _build_scope_mapping(self, body: Iterable[ast.stmt], args: ast.arguments) -> dict[str, str]:
        if not self.config.rename_identifiers:
            return {}
        names = _collect_local_names(body, args)
        mapping: dict[str, str] = {}
        for name in sorted(names):
            if name in self._module_imports:
                continue
            mapping[name] = self._next_name("var")
        return mapping

    def _rename_arguments(self, args: ast.arguments, mapping: dict[str, str]) -> ast.arguments:
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            if arg.arg in mapping:
                arg.arg = mapping[arg.arg]
        if args.vararg is not None and args.vararg.arg in mapping:
            args.vararg.arg = mapping[args.vararg.arg]
        if args.kwarg is not None and args.kwarg.arg in mapping:
            args.kwarg.arg = mapping[args.kwarg.arg]
        return args

    def _dead_block(self) -> ast.If:
        return ast.If(
            test=ast.Constant(value=0), body=[ast.Expr(value=ast.Constant(value=None))], orelse=[]
        )

    def _maybe_flatten(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if len(node.body) < 2 or not isinstance(node.body[-1], ast.Return):
            return node
        body = node.body[:-1]
        control_flow_nodes = (
            ast.If
            | ast.For
            | ast.While
            | ast.Try
            | ast.With
            | ast.Match
            | ast.Raise
            | ast.Return
        )
        if any(
            isinstance(inner, control_flow_nodes)
            for inner in ast.walk(ast.Module(body=body, type_ignores=[]))
        ):
            return node
        state_name = self._next_name("state")
        flattened: list[ast.stmt] = [
            ast.Assign(
                targets=[ast.Name(id=state_name, ctx=ast.Store())], value=ast.Constant(value=0)
            ),
            ast.While(
                test=ast.Constant(value=True),
                body=self._flatten_body(body, node.body[-1], state_name),
                orelse=[],
            ),
        ]
        node.body = flattened
        return node

    def _flatten_body(
        self, body: list[ast.stmt], tail: ast.Return, state_name: str
    ) -> list[ast.stmt]:
        blocks: list[ast.stmt] = []
        for index, statement in enumerate(body):
            blocks.append(
                ast.If(
                    test=ast.Compare(
                        left=ast.Name(id=state_name, ctx=ast.Load()),
                        ops=[ast.Eq()],
                        comparators=[ast.Constant(value=index)],
                    ),
                    body=[
                        statement,
                        ast.Assign(
                            targets=[ast.Name(id=state_name, ctx=ast.Store())],
                            value=ast.Constant(value=index + 1),
                        ),
                        ast.Continue(),
                    ],
                    orelse=[],
                )
            )
        blocks.append(
            ast.If(
                test=ast.Compare(
                    left=ast.Name(id=state_name, ctx=ast.Load()),
                    ops=[ast.Eq()],
                    comparators=[ast.Constant(value=len(body))],
                ),
                body=[tail, ast.Break()],
                orelse=[],
            )
        )
        return blocks

    def _next_name(self, prefix: str) -> str:
        self._rename_counter += 1
        return f"__psb_{prefix}_{self._rename_counter}"


def _expand_nodes(node: ast.AST | list[ast.stmt] | None) -> list[ast.stmt]:
    if node is None:
        return []
    if isinstance(node, list):
        expanded: list[ast.stmt] = []
        for item in node:
            expanded.extend(_expand_nodes(item))
        return expanded
    if isinstance(node, ast.stmt):
        return [node]
    raise TypeError(f"unexpected node type: {type(node)!r}")  # pragma: no cover


def _xor_encode(value: str, key: str) -> str:
    payload = value.encode("utf-8")
    key_bytes = key.encode("ascii")
    encoded = bytes(byte ^ key_bytes[index % len(key_bytes)] for index, byte in enumerate(payload))
    return base64.b64encode(encoded).decode("ascii")


def _make_decode_helper(key: str) -> ast.FunctionDef:
    return ast.FunctionDef(
        name="__psb_decode",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="value")],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
            vararg=None,
            kwarg=None,
        ),
        body=[
            ast.Import(names=[ast.alias(name="base64", asname=None)]),
            ast.Assign(
                targets=[ast.Name(id="data", ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="base64", ctx=ast.Load()),
                        attr="b64decode",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Name(id="value", ctx=ast.Load())],
                    keywords=[],
                ),
            ),
            ast.Assign(
                targets=[ast.Name(id="key", ctx=ast.Store())],
                value=ast.Constant(value=key.encode("ascii")),
            ),
            ast.Return(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Name(id="bytes", ctx=ast.Load()),
                            args=[
                                ast.GeneratorExp(
                                    elt=ast.BinOp(
                                        left=ast.Name(id="byte", ctx=ast.Load()),
                                        op=ast.BitXor(),
                                        right=ast.Subscript(
                                            value=ast.Name(id="key", ctx=ast.Load()),
                                            slice=ast.BinOp(
                                                left=ast.Name(id="index", ctx=ast.Load()),
                                                op=ast.Mod(),
                                                right=ast.Call(
                                                    func=ast.Name(id="len", ctx=ast.Load()),
                                                    args=[ast.Name(id="key", ctx=ast.Load())],
                                                    keywords=[],
                                                ),
                                            ),
                                            ctx=ast.Load(),
                                        ),
                                    ),
                                    generators=[
                                        ast.comprehension(
                                            target=ast.Tuple(
                                                elts=[
                                                    ast.Name(id="index", ctx=ast.Store()),
                                                    ast.Name(id="byte", ctx=ast.Store()),
                                                ],
                                                ctx=ast.Store(),
                                            ),
                                            iter=ast.Call(
                                                func=ast.Name(id="enumerate", ctx=ast.Load()),
                                                args=[ast.Name(id="data", ctx=ast.Load())],
                                                keywords=[],
                                            ),
                                            ifs=[],
                                            is_async=0,
                                        )
                                    ],
                                )
                            ],
                            keywords=[],
                        ),
                        attr="decode",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value="utf-8")],
                    keywords=[],
                )
            ),
        ],
        decorator_list=[],
        returns=None,
        type_comment=None,
        type_params=[],
    )


def _make_xor_helper() -> ast.FunctionDef:
    return ast.FunctionDef(
        name="__psb_xor",
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="left"), ast.arg(arg="right")],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
            vararg=None,
            kwarg=None,
        ),
        body=[
            ast.Return(
                value=ast.BinOp(
                    left=ast.Name(id="left", ctx=ast.Load()),
                    op=ast.BitXor(),
                    right=ast.Name(id="right", ctx=ast.Load()),
                )
            )
        ],
        decorator_list=[],
        returns=None,
        type_comment=None,
        type_params=[],
    )


def _make_dead_helper() -> ast.FunctionDef:
    return ast.FunctionDef(
        name="__psb_dead",
        args=ast.arguments(
            posonlyargs=[],
            args=[],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
            vararg=None,
            kwarg=None,
        ),
        body=[ast.Return(value=ast.Constant(value=None))],
        decorator_list=[],
        returns=None,
        type_comment=None,
        type_params=[],
    )
