#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Project index builder for multi-file analysis.
"""

import hashlib
import re
from typing import Any, Dict, List, Tuple

from engines.preprocessing.language_detector import detect_language
from engines.preprocessing.go_parser import parse_go_file
from engines.preprocessing.java_parser import parse_java_file


CALL_PATTERN = re.compile(r"([A-Za-z_][\w\.]*)\s*\(")


def _read_source(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="latin-1") as f:
            return f.read()


def _extract_calls(source_code: str, language: str) -> List[Dict[str, Any]]:
    calls: List[Dict[str, Any]] = []
    if not source_code:
        return calls

    keywords = {
        "if", "for", "while", "switch", "catch", "def", "class", "return",
        "new", "try", "except", "elif", "else", "package", "import", "func",
        "case", "go", "select", "range", "map"
    }

    lines = source_code.splitlines()
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if language == "python" and stripped.startswith("def "):
            continue
        if language == "go" and stripped.startswith("func "):
            continue
        if language == "java" and re.search(r"\b(class|interface|enum)\b", stripped):
            continue
        for match in CALL_PATTERN.finditer(line):
            full_name = match.group(1)
            name = full_name.split(".")[-1]
            if name in keywords:
                continue
            calls.append({
                "name": name,
                "full_name": full_name,
                "line": idx
            })
    return calls


def _extract_python_symbols(static_results: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    symbols = static_results.get("symbols", {}) or {}
    functions = symbols.get("functions", []) if isinstance(symbols, dict) else []
    classes = symbols.get("classes", []) if isinstance(symbols, dict) else []
    imports = symbols.get("imports", []) if isinstance(symbols, dict) else []

    symbol_list: List[Dict[str, Any]] = []
    for func in functions:
        symbol_list.append({
            "name": func.get("name"),
            "line": func.get("line"),
            "kind": "function"
        })
    for cls in classes:
        symbol_list.append({
            "name": cls.get("name"),
            "line": cls.get("line"),
            "kind": "class"
        })

    import_modules = []
    for item in imports:
        module = item.get("module") or item.get("name") or item.get("alias")
        if module:
            import_modules.append(module)

    return symbol_list, import_modules


def _hash_project(file_entries: List[Dict[str, Any]]) -> str:
    hasher = hashlib.sha256()
    for entry in sorted(file_entries, key=lambda x: x.get("file_path", "")):
        file_path = entry.get("file_path", "")
        source = entry.get("source_code", "")
        hasher.update(file_path.encode("utf-8", errors="ignore"))
        hasher.update(source.encode("utf-8", errors="ignore"))
    return hasher.hexdigest()


def build_project_index(file_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    files: Dict[str, Any] = {}
    symbols_index: Dict[str, List[Dict[str, Any]]] = {}

    for fr in file_results:
        if not fr.get("success"):
            continue
        result = fr.get("result", {}) or {}
        file_path = fr.get("file_path")
        if not file_path:
            continue

        language = result.get("language") or detect_language(file_path)
        source_code = _read_source(file_path)
        lines = source_code.splitlines()
        static_results = result.get("static_results", {}) or {}

        symbols: List[Dict[str, Any]] = []
        imports: List[str] = []
        if language == "python":
            symbols, imports = _extract_python_symbols(static_results)
        elif language == "go":
            parsed = parse_go_file(file_path)
            imports = parsed.get("imports", []) or []
            for func in parsed.get("functions", []) or []:
                symbols.append({"name": func.get("name"), "line": func.get("line"), "kind": "function"})
        elif language == "java":
            parsed = parse_java_file(file_path)
            imports = parsed.get("imports", []) or []
            for method in parsed.get("methods", []) or []:
                symbols.append({"name": method.get("name"), "line": method.get("line"), "kind": "method"})
            for cls in parsed.get("classes", []) or []:
                symbols.append({"name": cls.get("name"), "line": cls.get("line"), "kind": "class"})

        calls = _extract_calls(source_code, language)

        files[file_path] = {
            "language": language,
            "source_code": source_code,
            "lines": lines,
            "line_count": len(lines),
            "imports": imports,
            "symbols": symbols,
            "calls": calls,
            "pattern_matches": static_results.get("pattern_matches", []) or [],
            "taint_flows": static_results.get("taint_flows", []) or []
        }

        for symbol in symbols:
            name = symbol.get("name")
            if not name:
                continue
            symbols_index.setdefault(name, []).append({
                "file": file_path,
                "line": symbol.get("line"),
                "kind": symbol.get("kind")
            })

    call_edges: List[Dict[str, Any]] = []
    for file_path, info in files.items():
        for call in info.get("calls", []):
            name = call.get("name")
            if not name:
                continue
            for target in symbols_index.get(name, []):
                if target["file"] == file_path:
                    continue
                call_edges.append({
                    "from_file": file_path,
                    "to_file": target["file"],
                    "call_name": name,
                    "line": call.get("line", 0)
                })

    project_id = _hash_project([
        {"file_path": path, "source_code": info.get("source_code", "")}
        for path, info in files.items()
    ])

    return {
        "project_id": project_id,
        "files": files,
        "symbols_index": symbols_index,
        "call_edges": call_edges
    }
