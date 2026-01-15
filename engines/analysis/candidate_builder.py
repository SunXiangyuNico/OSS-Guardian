#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Build cross-file candidate chains for AI analysis.
"""

from typing import Any, Dict, List


SINK_RULE_KEYS = (
    "rce", "exec", "command", "cmd", "sql", "deserial",
    "deserialize", "network", "file_", "path_traversal",
    "webshell", "backdoor"
)


def _is_sink_match(match: Dict[str, Any]) -> bool:
    rule_id = (match.get("rule_id") or "").lower()
    rule_name = (match.get("rule_name") or "").lower()
    desc = (match.get("description") or "").lower()
    text = " ".join([rule_id, rule_name, desc])
    return any(key in text for key in SINK_RULE_KEYS)


def _extract_sources(file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    sources: List[Dict[str, Any]] = []
    for flow in file_info.get("taint_flows", []) or []:
        line = flow.get("source_line")
        if not line:
            continue
        sources.append({
            "file": file_info.get("file_path"),
            "line": line,
            "snippet": flow.get("source_code", ""),
            "kind": "taint_source"
        })
    return sources


def _extract_sinks(file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    sinks: List[Dict[str, Any]] = []
    for flow in file_info.get("taint_flows", []) or []:
        line = flow.get("sink_line") or flow.get("line")
        if not line:
            continue
        sinks.append({
            "file": file_info.get("file_path"),
            "line": line,
            "snippet": flow.get("sink_code", flow.get("matched_text", "")),
            "kind": "taint_sink",
            "rule_id": flow.get("rule_id")
        })

    for match in file_info.get("pattern_matches", []) or []:
        if not _is_sink_match(match):
            continue
        line = match.get("line")
        if not line:
            continue
        sinks.append({
            "file": file_info.get("file_path"),
            "line": line,
            "snippet": match.get("matched_text", ""),
            "kind": "pattern_sink",
            "rule_id": match.get("rule_id")
        })
    return sinks


def _select_closest(items: List[Dict[str, Any]], line: int) -> Dict[str, Any]:
    if not items:
        return {}
    return min(items, key=lambda x: abs((x.get("line") or 0) - line))


def build_candidates(project_index: Dict[str, Any], max_candidates: int) -> List[Dict[str, Any]]:
    files = project_index.get("files", {})
    call_edges = project_index.get("call_edges", [])

    sources_by_file: Dict[str, List[Dict[str, Any]]] = {}
    sinks_by_file: Dict[str, List[Dict[str, Any]]] = {}

    for file_path, info in files.items():
        info["file_path"] = file_path
        sources_by_file[file_path] = _extract_sources(info)
        sinks_by_file[file_path] = _extract_sinks(info)

    candidates: List[Dict[str, Any]] = []
    seen = set()
    counter = 1

    for edge in call_edges:
        from_file = edge.get("from_file")
        to_file = edge.get("to_file")
        call_line = edge.get("line", 0)

        sources = sources_by_file.get(from_file) or []
        sinks = sinks_by_file.get(to_file) or []
        if not sources or not sinks:
            continue

        source = _select_closest(sources, call_line)
        sink = sinks[0]
        if not source or not sink:
            continue

        key = (source.get("file"), source.get("line"), sink.get("file"), sink.get("line"), call_line)
        if key in seen:
            continue
        seen.add(key)

        candidates.append({
            "chain_id": f"c{counter}",
            "type": "cross_file_flow",
            "source": {
                "file": source.get("file"),
                "line": source.get("line")
            },
            "sink": {
                "file": sink.get("file"),
                "line": sink.get("line"),
                "rule_id": sink.get("rule_id")
            },
            "path": [
                {
                    "file": from_file,
                    "line": call_line,
                    "call": edge.get("call_name")
                }
            ]
        })
        counter += 1
        if max_candidates and len(candidates) >= max_candidates:
            break

    return candidates
