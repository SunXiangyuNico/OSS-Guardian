#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Java dynamic runner for single-file analysis.
Compiles and executes a Java target, then samples process behavior via psutil.
"""

import os
import re
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
    path_lower = (path or "").lower()
    return any(marker in path_lower for marker in SENSITIVE_PATH_MARKERS)


def _resolve_java_entrypoint(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w\.]*)\s*;", code, re.MULTILINE)
    package_name = package_match.group(1) if package_match else None

    class_match = re.search(
        r"^\s*(public\s+)?(final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)",
        code,
        re.MULTILINE
    )
    class_name = class_match.group(3) if class_match else os.path.splitext(os.path.basename(file_path))[0]

    if package_name:
        return f"{package_name}.{class_name}"
    return class_name


def _extract_java_package(file_path: str) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception:
        return ""
    package_match = re.search(r"^\s*package\s+([a-zA-Z_][\w\.]*)\s*;", code, re.MULTILINE)
    return package_match.group(1) if package_match else ""


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


def _resolve_java_project_root(file_path: str) -> str:
    start_dir = os.path.abspath(os.path.dirname(file_path))
    markers = ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew", "mvnw"]
    return _find_project_root(start_dir, markers)


def _collect_java_classpath(
    project_root: str,
    dependency_dirs: Optional[List[str]],
    extra_classpath: Any
) -> str:
    jar_paths: List[str] = []
    if dependency_dirs:
        for rel_dir in dependency_dirs:
            if not rel_dir:
                continue
            dir_path = os.path.join(project_root, rel_dir)
            if not os.path.isdir(dir_path):
                continue
            for root, _, files in os.walk(dir_path):
                for name in files:
                    if name.lower().endswith(".jar"):
                        jar_paths.append(os.path.join(root, name))

    extra_entries: List[str] = []
    if isinstance(extra_classpath, str):
        for part in extra_classpath.split(os.pathsep):
            part = part.strip()
            if part:
                extra_entries.append(part)
    elif isinstance(extra_classpath, list):
        for item in extra_classpath:
            if item:
                extra_entries.append(str(item))

    entries: List[str] = []
    seen = set()
    for path in jar_paths + extra_entries:
        if not path or path in seen or not os.path.exists(path):
            continue
        seen.add(path)
        entries.append(path)
    return os.pathsep.join(entries)


def _log_lines(log_event, prefix: str, text: str, max_lines: int = 6) -> None:
    if not text:
        return
    lines = [line for line in text.splitlines() if line.strip()]
    for line in lines[:max_lines]:
        log_event(f"{prefix}: {line}")


def run_java_dynamic(
    file_path: str,
    args: Optional[List[str]] = None,
    timeout: int = 30,
    sample_interval: float = 0.1,
    project_root: Optional[str] = None,
    dependency_dirs: Optional[List[str]] = None,
    extra_classpath: Any = None
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
        results["note"] = "psutil is not installed; Java dynamic analysis skipped."
        return results

    javac_path = shutil.which("javac")
    java_path = shutil.which("java")
    if not javac_path or not java_path:
        results["note"] = "javac/java not available; Java dynamic analysis skipped."
        results["java_result"] = {
            "javac_path": javac_path,
            "java_path": java_path
        }
        return results

    if not os.path.exists(file_path):
        results["note"] = "Java file not found."
        return results

    log_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data",
        "logs"
    )
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(
        log_dir,
        f"java_dynamic_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log"
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

    root = project_root or _resolve_java_project_root(file_path)
    classpath = ""
    if root and os.path.isdir(root):
        classpath = _collect_java_classpath(root, dependency_dirs, extra_classpath)
    sourcepath_root = root if root and os.path.isdir(root) else None

    with tempfile.TemporaryDirectory() as build_dir:
        entry_class = _resolve_java_entrypoint(file_path)
        package_name = _extract_java_package(file_path)
        simple_class = entry_class.split(".")[-1]
        class_name = f"{package_name}.{simple_class}" if package_name else simple_class
        source_path = file_path
        source_basename = os.path.splitext(os.path.basename(file_path))[0]

        with open(file_path, "r", encoding="utf-8", errors="replace") as src_fp:
            source_code = src_fp.read()

        if package_name:
            pkg_dir = os.path.join(build_dir, "src", *package_name.split("."))
            os.makedirs(pkg_dir, exist_ok=True)
            source_path = os.path.join(pkg_dir, f"{simple_class}.java")
        elif source_basename != simple_class:
            source_path = os.path.join(build_dir, f"{simple_class}.java")

        if source_path != file_path:
            with open(source_path, "w", encoding="utf-8") as out_fp:
                out_fp.write(source_code)

        compile_cmd = [javac_path, "-d", build_dir]
        if sourcepath_root:
            compile_cmd.extend(["-sourcepath", sourcepath_root])
        if classpath:
            compile_cmd.extend(["-cp", classpath])
        compile_cmd.append(source_path)

        compile_result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=sourcepath_root or build_dir
        )

        if compile_result.returncode != 0:
            log_event("compile_failed: javac returned non-zero")
            _log_lines(log_event, "compile_stderr", compile_result.stderr)
            _log_lines(log_event, "compile_stdout", compile_result.stdout)
            results["java_result"] = {
                "compile_stdout": compile_result.stdout,
                "compile_stderr": compile_result.stderr,
                "compile_return_code": compile_result.returncode,
                "class_name": class_name,
                "package_name": package_name,
                "source_path": source_path,
                "sourcepath_root": sourcepath_root,
                "javac_path": javac_path,
                "java_path": java_path
            }
            return results

        run_classpath = build_dir if not classpath else f"{build_dir}{os.pathsep}{classpath}"
        cmd = [java_path, "-cp", run_classpath, class_name] + args
        log_event(f"process_start: cmd={' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=sourcepath_root or os.path.dirname(file_path)
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
                            laddr = conn.laddr if conn.laddr else None
                            raddr = conn.raddr if conn.raddr else None
                            laddr_str = f"{laddr.ip}:{laddr.port}" if laddr else ""
                            raddr_str = f"{raddr.ip}:{raddr.port}" if raddr else ""
                            conn_key = (proc_item.pid, laddr_str, raddr_str, conn.status)
                            if conn_key in seen_connections:
                                continue
                            seen_connections.add(conn_key)
                            if raddr_str:
                                activity_type = "connect"
                                target = raddr_str
                            else:
                                activity_type = "bind"
                                target = laddr_str

                            line = f"NETWORK {activity_type} {target}"
                            results["network_activities"].append({
                                "type": activity_type,
                                "target": target,
                                "timestamp": datetime.now().isoformat(),
                                "line": line,
                                "raw_address": {"laddr": laddr_str, "raddr": raddr_str, "status": conn.status}
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

        results["java_result"] = {
            "return_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "command": cmd,
            "class_name": class_name,
            "package_name": package_name,
            "source_path": source_path,
            "sourcepath_root": sourcepath_root,
            "javac_path": javac_path,
            "java_path": java_path
        }

    return results
