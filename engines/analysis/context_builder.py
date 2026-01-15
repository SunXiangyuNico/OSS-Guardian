#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Context builder and redaction for agent requests.
"""

import re
from typing import Any, Dict, List, Tuple


def _redact_text(text: str, patterns: List[str]) -> str:
    redacted = text
    for pattern in patterns:
        try:
            redacted = re.sub(pattern, "<REDACTED>", redacted)
        except re.error:
            continue
    return redacted


def _get_snippet(lines: List[str], line: int, radius: int) -> Tuple[int, int, str]:
    if line <= 0:
        return 1, 1, ""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    snippet = "\n".join(lines[start - 1:end])
    return start, end, snippet


def build_context(
    project_index: Dict[str, Any],
    candidates: List[Dict[str, Any]],
    max_snippet_lines: int,
    max_snippets: int,
    redaction_enabled: bool,
    redaction_patterns: List[str]
) -> Dict[str, Any]:
    files = project_index.get("files", {})
    snippets: List[Dict[str, Any]] = []
    seen = set()

    radius = max(1, max_snippet_lines)
    for candidate in candidates:
        points = []
        source = candidate.get("source") or {}
        sink = candidate.get("sink") or {}
        points.append((source.get("file"), source.get("line")))
        points.append((sink.get("file"), sink.get("line")))
        for hop in candidate.get("path", []) or []:
            points.append((hop.get("file"), hop.get("line")))

        for file_path, line in points:
            if not file_path or not line:
                continue
            file_info = files.get(file_path)
            if not file_info:
                continue
            lines = file_info.get("lines", [])
            start, end, code = _get_snippet(lines, int(line), radius)
            key = (file_path, start, end)
            if key in seen:
                continue
            seen.add(key)
            if redaction_enabled and code:
                code = _redact_text(code, redaction_patterns)
            snippets.append({
                "file": file_path,
                "line_start": start,
                "line_end": end,
                "code": code
            })
            if max_snippets and len(snippets) >= max_snippets:
                break
        if max_snippets and len(snippets) >= max_snippets:
            break

    return {
        "snippets": snippets
    }
