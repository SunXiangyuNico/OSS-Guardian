#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Go dynamic runner for single-file analysis.
Builds and executes a Go target, then samples process behavior via psutil.
"""

import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


SENSITIVE_PATH_MARKERS = [
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\users\\",
    "/etc/",
    "/var/",
    "/root/",
    "/home/",
    "/usr/"
]


def _now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_sensitive_path(path: str) -> bool:
    if not path:
        return False
    path_lower = path.lower()
    return any(marker in path_lower for marker in SENSITIVE_PATH_MARKERS)


def _addr_to_string(addr: Any) -> str:
    if not addr:
        return ""
    if hasattr(addr, "ip") and hasattr(addr, "port"):
        return f"{addr.ip}:{addr.port}"
    if isinstance(addr, tuple) and len(addr) >= 2:
        return f"{addr[0]}:{addr[1]}"
    return str(addr)


def _find_project_root(start_dir: str, markers: List[str]) -> str:
    current = os.path.abspath(start_dir)
    while True:
        for marker in markers:
            if os.path.exists(os.path.join(current, marker)):
                return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return os.path.abspath(start_dir)


def _resolve_go_project_root(file_path: str) -> str:
    start_dir = os.path.abspath(os.path.dirname(file_path))
    markers = ["go.mod", "go.work"]
    return _find_project_root(start_dir, markers)


def _log_lines(log_event, prefix: str, text: str, max_lines: int = 6) -> None:
    if not text:
        return
    lines = [line for line in text.splitlines() if line.strip()]
    for line in lines[:max_lines]:
        log_event(f"{prefix}: {line}")


def run_go_dynamic(
    file_path: str,
    args: Optional[List[str]] = None,
    timeout: int = 30,
    sample_interval: float = 0.1,
    project_root: Optional[str] = None
) -> Dict[str, Any]:
    if args is None:
        args = []

    results: Dict[str, Any] = {
        "syscalls": [],
        "network_activities": [],
        "file_activities": [],
        "memory_findings": [],
        "fuzz_results": [],
        "execution_log": ""
    }

    if psutil is None:
        results["note"] = "psutil is not installed; Go dynamic analysis skipped."
        return results

    go_path = shutil.which("go")
    if not go_path:
        results["note"] = "go toolchain not available; Go dynamic analysis skipped."
        results["go_result"] = {"go_path": go_path}
        return results

    if not os.path.exists(file_path):
        results["note"] = "Go file not found."
        return results

    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data",
        "logs"
    )
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(
        log_dir,
        f"go_dynamic_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log"
    )
    results["execution_log"] = log_file

    def log_event(message: str) -> None:
        entry = f"[{_now_ts()}] {message}"
        results["syscalls"].append(entry)
        try:
            with open(log_file, "a", encoding="utf-8") as log_fp:
                log_fp.write(entry + "\n")
        except Exception:
            pass

    exe_name = "go_target.exe" if os.name == "nt" else "go_target"

    with tempfile.TemporaryDirectory() as build_dir:
        exe_path = os.path.join(build_dir, exe_name)
        build_target = file_path
        build_cwd = os.path.dirname(file_path)

        root = project_root or _resolve_go_project_root(file_path)
        if root and os.path.isdir(root):
            build_cwd = root
            entry_dir = os.path.dirname(file_path)
            try:
                rel_dir = os.path.relpath(entry_dir, root)
                if not rel_dir.startswith(".."):
                    build_target = "." if rel_dir == "." else os.path.join(".", rel_dir)
                else:
                    build_cwd = os.path.dirname(file_path)
            except Exception:
                build_cwd = os.path.dirname(file_path)

        compile_result = subprocess.run(
            [go_path, "build", "-o", exe_path, build_target],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=build_cwd
        )

        if compile_result.returncode != 0:
            log_event("compile_failed: go build returned non-zero")
            _log_lines(log_event, "compile_stderr", compile_result.stderr)
            _log_lines(log_event, "compile_stdout", compile_result.stdout)
            results["go_result"] = {
                "compile_stdout": compile_result.stdout,
                "compile_stderr": compile_result.stderr,
                "compile_return_code": compile_result.returncode,
                "go_path": go_path,
                "source_path": file_path,
                "build_target": build_target,
                "build_cwd": build_cwd
            }
            return results

        cmd = [exe_path] + args
        log_event(f"process_start: cmd={' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=build_cwd
        )

        process = psutil.Process(proc.pid)
        seen_files = set()
        seen_connections = set()
        peak_rss = 0
        peak_vms = 0
        start_time = time.time()
        timed_out = False

        while True:
            if proc.poll() is not None:
                break

            if time.time() - start_time > timeout:
                timed_out = True
                proc.terminate()
                break

            try:
                mem_info = process.memory_info()
                peak_rss = max(peak_rss, mem_info.rss)
                peak_vms = max(peak_vms, mem_info.vms)
            except Exception:
                pass

            try:
                processes = [process]
                try:
                    processes.extend(process.children(recursive=True))
                except Exception:
                    pass

                for proc_item in processes:
                    try:
                        proc_name = proc_item.name()
                    except Exception:
                        proc_name = ""
                    is_child = proc_item.pid != process.pid
                    proc_label = f"pid={proc_item.pid}"
                    if proc_name:
                        proc_label = f"{proc_label} name={proc_name}"
                    if is_child:
                        proc_label = f"child {proc_label}"

                    try:
                        for open_file in proc_item.open_files():
                            file_key = (proc_item.pid, open_file.path, open_file.mode)
                            if file_key in seen_files:
                                continue
                            seen_files.add(file_key)
                            is_sensitive = _is_sensitive_path(open_file.path)
                            results["file_activities"].append({
                                "operation": "open",
                                "file_path": open_file.path,
                                "mode": open_file.mode,
                                "is_sensitive": is_sensitive,
                                "line_numbers": []
                            })
                            log_event(
                                f"file_open: {proc_label} path={open_file.path} mode={open_file.mode}"
                            )
                    except Exception:
                        pass

                    try:
                        for conn in proc_item.net_connections(kind="inet"):
                            laddr = _addr_to_string(conn.laddr)
                            raddr = _addr_to_string(conn.raddr)
                            conn_key = (proc_item.pid, laddr, raddr, conn.status)
                            if conn_key in seen_connections:
                                continue
                            seen_connections.add(conn_key)
                            if raddr:
                                activity_type = "connect"
                                target = raddr
                            else:
                                activity_type = "bind"
                                target = laddr

                            line = f"NETWORK {activity_type} {target}"
                            results["network_activities"].append({
                                "type": activity_type,
                                "target": target,
                                "timestamp": datetime.now().isoformat(),
                                "line": line,
                                "raw_address": {"laddr": laddr, "raddr": raddr, "status": conn.status}
                            })
                            log_event(f"socket_{activity_type}: {proc_label} target={target}")
                    except Exception:
                        pass
            except Exception:
                pass

            time.sleep(sample_interval)

        try:
            stdout, stderr = proc.communicate(timeout=2)
        except Exception:
            stdout, stderr = ("", "")

        if timed_out:
            try:
                proc.kill()
            except Exception:
                pass

        log_event(f"process_exit: return_code={proc.returncode} timed_out={timed_out}")

        if peak_rss or peak_vms:
            results["memory_findings"].append({
                "type": "memory_usage",
                "detail": f"peak_rss={peak_rss} bytes, peak_vms={peak_vms} bytes",
                "line_numbers": []
            })

        results["go_result"] = {
            "return_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "command": cmd,
            "source_path": file_path,
            "build_path": exe_path,
            "go_path": go_path,
            "build_target": build_target,
            "build_cwd": build_cwd
        }

    return results
