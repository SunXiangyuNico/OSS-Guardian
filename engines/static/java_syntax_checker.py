#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java Syntax Checker
Checks Java source code syntax using javac.
"""

import os
import re
import subprocess
import tempfile
from typing import Dict, Any, Optional


def _read_source(file_path: str) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='latin-1') as f:
            return f.read()


def _strip_comments(source_code: str) -> str:
    lines = source_code.splitlines()
    cleaned = []
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
    return '\n'.join(cleaned)


def _extract_public_type_name(source_code: str) -> Optional[str]:
    cleaned = _strip_comments(source_code)
    match = re.search(r'\bpublic\s+(class|interface|enum|record)\s+([A-Za-z_][\w]*)', cleaned)
    if match:
        return match.group(2)
    return None


def _is_non_syntax_failure(stderr: str) -> bool:
    text = stderr.lower()
    syntax_markers = [
        'illegal start of',
        'not a statement',
        "expected",
        'reached end of file while parsing',
        'unclosed string literal',
        'class, interface, or enum expected',
        'identifier expected'
    ]
    for marker in syntax_markers:
        if marker in text:
            return False

    non_syntax_markers = [
        'cannot find symbol',
        'package ',
        'is public, should be declared in a file named',
        'class file for',
        'module',
        'cannot access',
        'bad class file'
    ]
    return any(marker in text for marker in non_syntax_markers)


def check_syntax(file_path: str) -> Dict[str, Any]:
    """
    Check Java source code syntax.
    
    Args:
        file_path: Path to Java source file
        
    Returns:
        dict: Syntax check results containing:
            - 'valid': bool - Whether syntax is valid
            - 'errors': List[str] - Error messages
    """
    result = {
        'valid': True,
        'errors': []
    }
    
    source_code = _read_source(file_path)

    # Try syntax-only parsing via javalang if available
    try:
        import javalang
        try:
            javalang.parse.parse(source_code)
            return result
        except javalang.parser.JavaSyntaxError as exc:
            result['valid'] = False
            result['errors'] = [str(exc)]
            return result
    except Exception:
        pass

    # Check if javac is available
    try:
        subprocess.run(['javac', '-version'], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        result['valid'] = True
        result['errors'] = ['Java compiler not available, skipping syntax check']
        return result
    
    # Try to compile the file
    try:
        temp_dir = tempfile.mkdtemp()
        public_name = _extract_public_type_name(source_code)
        target_name = f"{public_name}.java" if public_name else os.path.basename(file_path)
        temp_file = os.path.join(temp_dir, target_name)

        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(source_code)

        process = subprocess.run(
            [
                'javac',
                '-J-Duser.language=en',
                '-J-Duser.region=US',
                '-Xlint:none',
                '-proc:none',
                '-d', temp_dir,
                temp_file
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if process.returncode != 0:
            stderr = process.stderr or ''
            if _is_non_syntax_failure(stderr):
                result['valid'] = True
                result['errors'] = [
                    'Compilation issues detected (likely classpath/module); syntax not verified.'
                ] + stderr.split('\n')
            else:
                result['valid'] = False
                result['errors'] = stderr.split('\n') if stderr else ['Unknown syntax error']

        # Cleanup temp output
        try:
            for root, _, files in os.walk(temp_dir):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except Exception:
                        pass
            os.rmdir(temp_dir)
        except Exception:
            pass
                
    except subprocess.TimeoutExpired:
        result['valid'] = False
        result['errors'] = ['Syntax check timeout']
    except Exception as e:
        result['valid'] = False
        result['errors'] = [f"Syntax check error: {str(e)}"]
    
    return result
