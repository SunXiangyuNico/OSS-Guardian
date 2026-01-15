#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Process Monitor
Runs a process and samples network/file/memory activity via psutil.
"""

import subprocess
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from engines.dynamic.file_monitor import FileMonitor


def _now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return ""


def run_process_with_monitor(
    command: List[str],
    cwd: Optional[str],
    timeout: int,
    poll_interval: float = 0.2,
    max_samples: Optional[int] = None
) -> Dict[str, Any]:
    """
    Run a process and sample runtime signals.

    Returns:
        dict: {
            return_code, stdout, stderr, execution_time, timed_out,
            network_activities, file_activities, memory_findings,
            monitor_error (optional)
        }
    """
    start_time = time.time()
    if max_samples is None:
        max_samples = max(1, int(max(timeout, 1) / max(poll_interval, 0.1)) + 1)

    try:
        import psutil  # type: ignore
    except Exception as exc:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            cwd=cwd or None
        )
        return {
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "execution_time": time.time() - start_time,
            "timed_out": False,
            "network_activities": [],
            "file_activities": [],
            "memory_findings": [],
            "syscalls": [],
            "monitor_error": f"psutil_not_installed: {exc}"
        }

    file_monitor = FileMonitor(None)
    network_seen = set()
    file_seen = set()
    network_activities: List[Dict[str, Any]] = []
    file_activities: List[Dict[str, Any]] = []
    memory_findings: List[Dict[str, Any]] = []
    syscalls: List[str] = []
    child_seen = set()

    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd or None
    )

    timed_out = False
    monitor_error = ""
    max_rss = 0
    max_vms = 0

    try:
        ps_proc = psutil.Process(proc.pid)
    except Exception as exc:
        ps_proc = None
        monitor_error = f"psutil_process_error: {exc}"

    samples = 0
    sampling_enabled = True
    while True:
        if proc.poll() is not None:
            break
        if time.time() - start_time > timeout:
            timed_out = True
            break
        if samples >= max_samples:
            sampling_enabled = False

        if sampling_enabled and ps_proc is not None:
            try:
                for conn in ps_proc.net_connections(kind="inet"):
                    laddr = getattr(conn, "laddr", None)
                    raddr = getattr(conn, "raddr", None)
                    if not laddr and not raddr:
                        continue
                    if raddr:
                        target = f"{getattr(raddr, 'ip', raddr[0])}:{getattr(raddr, 'port', raddr[1])}"
                        activity_type = "connect"
                    else:
                        target = f"{getattr(laddr, 'ip', laddr[0])}:{getattr(laddr, 'port', laddr[1])}"
                        activity_type = "bind"
                    key = (activity_type, target)
                    if key in network_seen:
                        continue
                    network_seen.add(key)
                    network_activities.append({
                        "type": activity_type,
                        "target": target,
                        "timestamp": _now_ts(),
                        "line": "",
                        "raw_address": _safe_str(raddr if raddr else laddr)
                    })
            except Exception as exc:
                if not monitor_error:
                    try:
                        if isinstance(exc, psutil.AccessDenied):
                            monitor_error = f"psutil_access_denied: {exc}"
                    except Exception:
                        pass

            try:
                for opened in ps_proc.open_files():
                    path = getattr(opened, "path", "")
                    if not path or path in file_seen:
                        continue
                    file_seen.add(path)
                    file_activities.append({
                        "operation": "open",
                        "file_path": path,
                        "mode": "",
                        "is_sensitive": file_monitor.is_sensitive_file(path),
                        "line_numbers": []
                    })
            except Exception as exc:
                if not monitor_error:
                    try:
                        if isinstance(exc, psutil.AccessDenied):
                            monitor_error = f"psutil_access_denied: {exc}"
                    except Exception:
                        pass

            try:
                mem_info = ps_proc.memory_info()
                max_rss = max(max_rss, int(getattr(mem_info, "rss", 0)))
                max_vms = max(max_vms, int(getattr(mem_info, "vms", 0)))
            except Exception as exc:
                if not monitor_error:
                    try:
                        if isinstance(exc, psutil.AccessDenied):
                            monitor_error = f"psutil_access_denied: {exc}"
                    except Exception:
                        pass

            try:
                for child in ps_proc.children(recursive=True):
                    if child.pid in child_seen:
                        continue
                    child_seen.add(child.pid)
                    try:
                        exe = child.exe()
                    except Exception:
                        exe = ""
                    syscalls.append(f"process_spawn: pid={child.pid} exe={exe}")
            except Exception as exc:
                if not monitor_error:
                    try:
                        if isinstance(exc, psutil.AccessDenied):
                            monitor_error = f"psutil_access_denied: {exc}"
                    except Exception:
                        pass

        if sampling_enabled:
            samples += 1
        time.sleep(poll_interval)

    if timed_out and proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        stdout, stderr = proc.communicate(timeout=2)
    except Exception:
        stdout, stderr = "", ""

    if max_rss or max_vms:
        memory_findings.append({
            "type": "memory_usage",
            "detail": f"rss={max_rss} bytes, vms={max_vms} bytes",
            "line_numbers": []
        })

    return {
        "return_code": proc.returncode if proc.returncode is not None else -1,
        "stdout": stdout,
        "stderr": stderr,
        "execution_time": time.time() - start_time,
        "timed_out": timed_out,
        "network_activities": network_activities,
        "file_activities": file_activities,
        "memory_findings": memory_findings,
        "syscalls": syscalls,
        "monitor_error": monitor_error
    }
