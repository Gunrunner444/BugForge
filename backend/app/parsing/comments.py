"""Comment stripping that respects string literals."""

from __future__ import annotations


def strip_comments(
    source: str,
    *,
    line_comment: str | None,
    block_comment: tuple[str, str] | None,
    string_delims: tuple[str, ...] = ("'", '"', "`"),
) -> str:
    """Replace comments with spaces so line numbers stay aligned."""
    out: list[str] = []
    i = 0
    n = len(source)
    in_string: str | None = None
    escape = False
    block_start, block_end = block_comment or ("", "")

    while i < n:
        ch = source[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if block_start and source.startswith(block_start, i):
            end = source.find(block_end, i + len(block_start)) if block_end else -1
            chunk_end = end + len(block_end) if end != -1 else n
            for c in source[i:chunk_end]:
                out.append("\n" if c == "\n" else " ")
            i = chunk_end
            continue
        if line_comment and source.startswith(line_comment, i):
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch in string_delims:
            in_string = ch
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)
