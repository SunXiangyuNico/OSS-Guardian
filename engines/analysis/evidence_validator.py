#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Validate AI evidence against project index.
"""

from typing import Any, Dict, List


def _line_contains_snippet(lines: List[str], line: int, snippet: str) -> bool:
    if not snippet:
        return True
    if "<REDACTED>" in snippet:
        return True
    if line <= 0 or line > len(lines):
        return False
    window_start = max(0, line - 2)
    window_end = min(len(lines), line + 1)
    window = "\n".join(lines[window_start:window_end])
    return snippet.strip() in window


def validate_findings(
    findings: List[Dict[str, Any]],
    project_index: Dict[str, Any],
    evidence_required: bool = True
) -> List[Dict[str, Any]]:
    files = project_index.get("files", {})
    validated: List[Dict[str, Any]] = []

    for finding in findings:
        evidence = finding.get("evidence", []) or []
        valid_evidence = []
        line_numbers = []

        for ev in evidence:
            file_path = ev.get("file") or finding.get("source_file")
            line = ev.get("line") or ev.get("line_number")
            snippet = ev.get("snippet", "")
            if not file_path or not line:
                continue
            info = files.get(file_path)
            if not info:
                continue
            lines = info.get("lines", [])
            if line <= 0 or line > len(lines):
                continue
            if snippet and not _line_contains_snippet(lines, line, snippet):
                continue
            valid_evidence.append({
                "file": file_path,
                "line": line,
                "snippet": snippet
            })
            line_numbers.append(line)

        if evidence_required and not valid_evidence:
            continue

        severity = (finding.get("severity") or "medium").lower()
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"

        validated.append({
            "threat_type": finding.get("threat_type") or "Unknown",
            "severity": severity,
            "description": finding.get("summary") or finding.get("description") or "",
            "source_file": finding.get("source_file") or (valid_evidence[0]["file"] if valid_evidence else ""),
            "line_numbers": sorted(set(line_numbers)),
            "evidence": valid_evidence,
            "ai_generated": True,
            "confidence": finding.get("confidence", 0.0),
            "chain_id": finding.get("chain_id")
        })

    return validated
