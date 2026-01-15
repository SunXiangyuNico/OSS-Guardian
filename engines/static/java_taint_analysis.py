#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java Taint Analysis
Tracks taint data flow in Java source code.
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from engines.preprocessing.java_parser import parse_java_file


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


def _extract_assigned_vars(line: str) -> Tuple[List[str], Optional[str]]:
    match = re.search(r'(?<![=!<>])=(?![=])', line)
    if not match:
        return [], None
    lhs = line[:match.start()].strip()
    rhs = line[match.end():].strip()

    vars_found: List[str] = []
    for part in lhs.split(','):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        var_name = tokens[-1] if tokens else ''
        if var_name == '_':
            continue
        vars_found.append(var_name)
    return vars_found, rhs


def _line_contains_var(text: str, var_name: str) -> bool:
    if not var_name:
        return False
    pattern = r'(?<![\w\.])' + re.escape(var_name) + r'(?![\w])'
    return re.search(pattern, text) is not None


def _find_taint_origin(rhs: str, tainted_vars: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for var_name, origin in tainted_vars.items():
        if _line_contains_var(rhs, var_name):
            return origin
    return None


def analyze(file_path: str) -> List[Dict[str, Any]]:
    """
    Perform taint analysis on Java source code.

    Args:
        file_path: Path to Java source file

    Returns:
        List[Dict]: Taint flow information
    """
    taint_flows: List[Dict[str, Any]] = []

    try:
        parsed_data = parse_java_file(file_path)
        source_code = parsed_data.get('source_code', '')
        lines = _strip_comments(source_code.split('\n'))
    except Exception:
        return taint_flows

    # Taint sources in Java
    taint_sources = [
        r'System\.in',
        r'args\s*\[',
        r'request\.getParameter\(',
        r'request\.getHeader\(',
        r'request\.getQueryString\(',
        r'request\.getCookies\(',
        r'session\.getAttribute\('
    ]

    sink_rules: List[Tuple[str, Dict[str, str]]] = [
        (r'Runtime\.getRuntime\(\)\.exec\(', {
            'rule_id': 'java_rce_runtime_exec',
            'rule_name': 'Java RCE - Runtime.exec()',
            'severity': 'critical'
        }),
        (r'new\s+ProcessBuilder\(|ProcessBuilder\(', {
            'rule_id': 'java_rce_processbuilder',
            'rule_name': 'Java RCE - ProcessBuilder',
            'severity': 'critical'
        }),
        (r'(Statement|PreparedStatement)\.execute(Query|Update|)\(', {
            'rule_id': 'java_sql_injection',
            'rule_name': 'Java SQL Injection - String Concatenation',
            'severity': 'high'
        }),
        (r'(FileWriter|FileOutputStream|PrintWriter)\(', {
            'rule_id': 'java_file_operation',
            'rule_name': 'Java File Operation',
            'severity': 'medium'
        }),
        (r'(Socket|URL|HttpURLConnection)\s*\(|\.connect\s*\(', {
            'rule_id': 'java_network_connection',
            'rule_name': 'Java Network Connection',
            'severity': 'medium'
        }),
        (r'(ObjectInputStream|readObject|readUnshared)\s*\(', {
            'rule_id': 'java_deserialization',
            'rule_name': 'Java Deserialization Risk',
            'severity': 'high'
        })
    ]

    sink_patterns = [pattern for pattern, _ in sink_rules]

    tainted_vars: Dict[str, Dict[str, Any]] = {}
    seen_flows = set()

    for i, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line:
            continue

        sources_present = [p for p in taint_sources if re.search(p, line)]
        assigned_vars, rhs = _extract_assigned_vars(line)

        if sources_present and assigned_vars:
            for var_name in assigned_vars:
                tainted_vars[var_name] = {
                    'source_line': i,
                    'source_code': line
                }
        elif assigned_vars and rhs:
            origin = _find_taint_origin(rhs, tainted_vars)
            if origin:
                for var_name in assigned_vars:
                    tainted_vars[var_name] = origin

        matched_sink = None
        matched_text = ''
        for pattern, info in sink_rules:
            match = re.search(pattern, line)
            if match:
                matched_sink = info
                matched_text = match.group(0)
                break
        if matched_sink is None and not any(re.search(pattern, line) for pattern in sink_patterns):
            continue

        # Direct source to sink on same line
        if matched_sink and sources_present:
            key = (i, i, 'direct', matched_sink['rule_id'])
            if key not in seen_flows:
                taint_flows.append({
                    'source_line': i,
                    'source_code': line,
                    'sink_line': i,
                    'sink_code': line,
                    'rule_id': matched_sink['rule_id'],
                    'rule_name': matched_sink['rule_name'],
                    'severity': matched_sink['severity'],
                    'line': i,
                    'matched_text': matched_text or line,
                    'description': f"Taint source on line {i} flows to sink on line {i}"
                })
                seen_flows.add(key)

        # Variable-based flows
        for var_name, origin in tainted_vars.items():
            if not _line_contains_var(line, var_name):
                continue
            if not matched_sink:
                continue
            key = (origin['source_line'], i, var_name, matched_sink['rule_id'])
            if key in seen_flows:
                continue
            taint_flows.append({
                'source_line': origin['source_line'],
                'source_code': origin['source_code'],
                'sink_line': i,
                'sink_code': line,
                'rule_id': matched_sink['rule_id'],
                'rule_name': matched_sink['rule_name'],
                'severity': matched_sink['severity'],
                'line': i,
                'matched_text': matched_text or line,
                'description': (
                    f"Taint data from line {origin['source_line']} flows to sink at line {i}"
                )
            })
            seen_flows.add(key)

    return taint_flows
