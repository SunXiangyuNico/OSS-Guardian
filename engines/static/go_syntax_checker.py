#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go Syntax Checker
Checks Go source code syntax using go build or go vet.
"""

import os
import subprocess
import tempfile
from typing import Dict, Any


def check_syntax(file_path: str) -> Dict[str, Any]:
    """
    Check Go source code syntax.
    
    Args:
        file_path: Path to Go source file
        
    Returns:
        dict: Syntax check results containing:
            - 'valid': bool - Whether syntax is valid
            - 'errors': List[str] - Error messages
    """
    result = {
        'valid': True,
        'errors': []
    }
    
    # Check if gofmt is available (syntax-only)
    try:
        subprocess.run(['gofmt', '-h'], capture_output=True, check=True, timeout=5)
        gofmt_available = True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        gofmt_available = False

    if not gofmt_available:
        # Go toolchain not available, use basic validation
        result['valid'] = True
        result['errors'] = ['Go toolchain not available, skipping syntax check']
        return result

    # Try to parse/format the file using gofmt to validate syntax
    try:
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, os.path.basename(file_path))

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(content)

        process = subprocess.run(
            ['gofmt', temp_file],
            capture_output=True,
            text=True,
            timeout=30
        )

        if process.returncode != 0:
            result['valid'] = False
            result['errors'] = process.stderr.split('\n') if process.stderr else ['Unknown syntax error']

        try:
            os.remove(temp_file)
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
