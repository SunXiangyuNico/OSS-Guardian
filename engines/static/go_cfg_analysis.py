#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go Control Flow Graph (CFG) Analysis
Extracts basic control-flow structures using brace matching.
"""

import re
from typing import List, Dict, Any


def _strip_comments(lines: List[str]) -> List[str]:
    cleaned: List[str] = []
    in_block = False
    for line in lines:
        current = line
        while True:
            if in_block:
                end = current.find('*/')
                if end == -1:
                    current = ''
                    break
                current = current[end + 2:]
                in_block = False
                continue
            start = current.find('/*')
            if start != -1:
                end = current.find('*/', start + 2)
                if end == -1:
                    current = current[:start]
                    in_block = True
                    break
                current = current[:start] + current[end + 2:]
                continue
            break
        current = current.split('//', 1)[0]
        cleaned.append(current)
    return cleaned


def _find_block_end(lines: List[str], start_idx: int) -> int:
    brace_count = 0
    started = False
    for idx in range(start_idx, len(lines)):
        brace_count += lines[idx].count('{')
        if lines[idx].count('{') > 0:
            started = True
        brace_count -= lines[idx].count('}')
        if started and brace_count == 0:
            return idx
    return len(lines) - 1


def _collect_body_lines(lines: List[str], start_idx: int, end_idx: int) -> List[int]:
    body_lines: List[int] = []
    for idx in range(start_idx + 1, end_idx):
        if lines[idx].strip():
            body_lines.append(idx + 1)
    return body_lines


def analyze(source_code: str) -> List[Dict[str, Any]]:
    """
    Analyze Go source code and extract basic control-flow structures.

    Args:
        source_code: Go source code as string

    Returns:
        List[Dict]: CFG-like structures with start/end line numbers
    """
    if not source_code:
        return []

    lines = _strip_comments(source_code.splitlines())
    structures: List[Dict[str, Any]] = []

    patterns = [
        ('if', re.compile(r'^\s*if\s+(.+?)\s*\{')),
        ('for', re.compile(r'^\s*for\s+(.+?)\s*\{')),
        ('switch', re.compile(r'^\s*switch\s*(.*?)\s*\{')),
        ('select', re.compile(r'^\s*select\s*\{'))
    ]

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('else'):
            continue

        for cfg_type, pattern in patterns:
            match = pattern.match(stripped)
            if not match:
                continue

            end_idx = _find_block_end(lines, idx)
            body_lines = _collect_body_lines(lines, idx, end_idx)
            condition = match.group(1).strip() if match.groups() else ""

            structures.append({
                'type': cfg_type,
                'start_line': idx + 1,
                'end_line': end_idx + 1,
                'condition': condition,
                'body_lines': body_lines
            })
            break

    return structures
