import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import yaml
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("linux-autopilot")

ACTION_ALLOWLIST_ENV = "PROCESS_MONITOR_ACTION_ALLOWLIST"
SYSTEM_ACTION_ALLOWLIST_ENV = "PROCESS_MONITOR_SYSTEM_ACTION_ALLOWLIST"
AUDIT_LOG_ENV = "PROCESS_MONITOR_AUDIT_LOG"
DEFAULT_AUDIT_LOG = Path.home() / ".local" / "state" / "process-monitor-mcp" / "actions.jsonl"
STATE_DIR = Path(os.environ.get("PROCESS_MONITOR_STATE_DIR", Path.home() / ".local" / "state" / "process-monitor-mcp")).expanduser()
METRICS_DB = STATE_DIR / "metrics.db"
HOSTS_FILE = STATE_DIR / "hosts.json"
JOBS_FILE = STATE_DIR / "jobs.json"
MANIFEST_FILE = Path(os.environ.get("PROCESS_MONITOR_JOBS_FILE", Path.home() / ".config" / "process-monitor-mcp" / "jobs.json")).expanduser()
PROTECTED_PROCESS_NAMES = {
    "systemd",
    "init",
    "kthreadd",
    "sshd",
    "login",
    "gdm",
    "sddm",
    "lightdm",
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "plasmashell",
}


def _run_command(command: List[str], timeout: float = 30.0, check: bool = False) -> Dict[str, Any]:
    executable = shutil.which(command[0])
    if executable is None:
        return {"success": False, "command": command, "returncode": 127, "stdout": "", "stderr": f"comando não encontrado: {command[0]}"}
    try:
        completed = subprocess.run(
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
        return {
            "success": completed.returncode == 0,
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except subprocess.TimeoutExpired as error:
        return {"success": False, "command": command, "returncode": None, "stdout": error.stdout or "", "stderr": "timeout"}
    except (OSError, subprocess.CalledProcessError) as error:
        return {"success": False, "command": command, "returncode": getattr(error, "returncode", None), "stdout": "", "stderr": str(error)}


def _read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return default


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return default


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _parse_psi(resource: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for line in _read_text(Path(f"/proc/pressure/{resource}")).splitlines():
        fields = line.split()
        if not fields:
            continue
        result[fields[0]] = {
            key: float(value) if key != "total" else int(value)
            for key, value in (field.split("=", 1) for field in fields[1:])
        }
    return result


def _system_action(action: str, parameters: Dict[str, Any], command: List[str], dry_run: bool = True, timeout: float = 120.0) -> Dict[str, Any]:
    target = {"scope": "system", "command": command}
    if dry_run:
        result: Any = {"command": command, "executed": False}
        _audit_action(action, target, parameters, True, True, json.dumps(result, ensure_ascii=False))
        return {"action": action, "parameters": parameters, "dry_run": True, "success": True, "result": result}
    entries = {entry.strip() for entry in os.environ.get(SYSTEM_ACTION_ALLOWLIST_ENV, "").split(",") if entry.strip()}
    if not {"*", action}.intersection(entries):
        raise PermissionError(f"ação {action} não está em {SYSTEM_ACTION_ALLOWLIST_ENV}")
    outcome = _run_command(command, timeout=timeout)
    _audit_action(action, target, parameters, False, outcome["success"], json.dumps(outcome, ensure_ascii=False))
    if not outcome["success"]:
        raise RuntimeError(f"falha ao executar {action}: {outcome['stderr']}")
    return {"action": action, "parameters": parameters, "dry_run": False, "success": True, "result": outcome}


def _state_action(action: str, parameters: Dict[str, Any], dry_run: bool, operation: Any) -> Dict[str, Any]:
    target = {"scope": "state"}
    if dry_run:
        _audit_action(action, target, parameters, True, True, "ação validada e não executada")
        return {"action": action, "parameters": parameters, "dry_run": True, "success": True}
    entries = {entry.strip() for entry in os.environ.get(SYSTEM_ACTION_ALLOWLIST_ENV, "").split(",") if entry.strip()}
    if not {"*", action}.intersection(entries):
        raise PermissionError(f"ação {action} não está em {SYSTEM_ACTION_ALLOWLIST_ENV}")
    try:
        result = operation()
        _audit_action(action, target, parameters, False, True, json.dumps(result, ensure_ascii=False))
        return {"action": action, "parameters": parameters, "dry_run": False, "success": True, "result": result}
    except (OSError, ValueError) as error:
        _audit_action(action, target, parameters, False, False, str(error))
        raise


def _init_metrics_db() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(METRICS_DB) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY, created_at REAL NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL)")


def _snapshot_payload() -> Dict[str, Any]:
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "timestamp": time.time(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "load_average": list(os.getloadavg()),
        "memory_percent": memory.percent,
        "memory_available": memory.available,
        "swap_percent": psutil.swap_memory().percent,
        "disk_percent": disk.percent,
        "disk_free": disk.free,
        "process_count": len(psutil.pids()),
        "memory_psi": _parse_psi("memory"),
        "cpu_psi": _parse_psi("cpu"),
        "io_psi": _parse_psi("io"),
    }


def _load_hosts() -> List[Dict[str, Any]]:
    hosts = _read_json(HOSTS_FILE, [])
    return hosts if isinstance(hosts, list) else []


def _save_hosts(hosts: List[Dict[str, Any]]) -> None:
    _write_json(HOSTS_FILE, hosts)


def _ssh(host: Dict[str, Any], remote_command: str, timeout: float = 30.0) -> Dict[str, Any]:
    target = f"{host.get('user', os.environ.get('USER', ''))}@{host['hostname']}"
    return _run_command(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", str(host.get("port", 22)), target, remote_command], timeout)


# Processos


def _get_process(pid: int) -> psutil.Process:
    if pid <= 0:
        raise ValueError("pid deve ser maior que zero")
    try:
        return psutil.Process(pid)
    except psutil.NoSuchProcess as error:
        raise ValueError(f"processo {pid} não existe") from error


def _action_target(process: psutil.Process) -> Dict[str, Any]:
    with process.oneshot():
        return {
            "pid": process.pid,
            "name": process.name(),
            "username": process.username(),
            "cmdline": process.cmdline(),
            "create_time": process.create_time(),
        }


def _validate_action_target(process: psutil.Process, dry_run: bool) -> Dict[str, Any]:
    target = _action_target(process)
    if target["pid"] in {1, os.getpid(), os.getppid()}:
        raise PermissionError(f"processo {target['pid']} é protegido")
    if target["name"] in PROTECTED_PROCESS_NAMES or not target["cmdline"]:
        raise PermissionError(f"processo {target['name']} é protegido")
    if dry_run:
        return target
    entries = {
        entry.strip()
        for entry in os.environ.get(ACTION_ALLOWLIST_ENV, "").split(",")
        if entry.strip()
    }
    identities = {
        "*",
        str(target["pid"]),
        target["name"],
        f"{target['username']}:{target['name']}",
    }
    if not entries.intersection(identities):
        raise PermissionError(
            f"processo {target['pid']} não está em {ACTION_ALLOWLIST_ENV}"
        )
    return target


def _audit_action(
    action: str,
    target: Dict[str, Any],
    parameters: Dict[str, Any],
    dry_run: bool,
    success: bool,
    result: str,
) -> None:
    path = Path(os.environ.get(AUDIT_LOG_ENV, str(DEFAULT_AUDIT_LOG))).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": time.time(),
        "action": action,
        "target": target,
        "parameters": parameters,
        "dry_run": dry_run,
        "success": success,
        "result": result,
        "executor_pid": os.getpid(),
        "executor_uid": os.getuid(),
    }
    with path.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _run_action(
    action: str,
    pid: int,
    parameters: Dict[str, Any],
    dry_run: bool,
    operation: Any,
) -> Dict[str, Any]:
    process = _get_process(pid)
    target = _validate_action_target(process, dry_run)
    if dry_run:
        result = "ação validada e não executada"
        _audit_action(action, target, parameters, True, True, result)
        return {
            "action": action,
            "target": target,
            "parameters": parameters,
            "dry_run": True,
            "success": True,
            "result": result,
        }
    try:
        result = operation(process)
        _audit_action(action, target, parameters, False, True, str(result))
        return {
            "action": action,
            "target": target,
            "parameters": parameters,
            "dry_run": False,
            "success": True,
            "result": result,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError) as error:
        _audit_action(action, target, parameters, False, False, str(error))
        raise RuntimeError(f"falha ao executar {action}: {error}") from error


def _collect_process_metrics(process: psutil.Process) -> Dict[str, Any]:
    with process.oneshot():
        memory = process.memory_info()
        io_counters = process.io_counters()
        return {
            "timestamp": time.time(),
            "cpu_percent": round(process.cpu_percent(None), 2),
            "rss_bytes": memory.rss,
            "read_bytes": io_counters.read_bytes,
            "write_bytes": io_counters.write_bytes,
            "threads": process.num_threads(),
            "file_descriptors": process.num_fds(),
        }


def _sample_process_metrics(pid: int, duration_seconds: float, interval_seconds: float) -> List[Dict[str, Any]]:
    if not 0.2 <= duration_seconds <= 60:
        raise ValueError("duration_seconds deve estar entre 0.2 e 60")
    if not 0.1 <= interval_seconds <= duration_seconds:
        raise ValueError("interval_seconds deve estar entre 0.1 e duration_seconds")
    process = _get_process(pid)
    process.cpu_percent(None)
    samples = []
    deadline = time.monotonic() + duration_seconds
    while True:
        time.sleep(min(interval_seconds, max(0.0, deadline - time.monotonic())))
        samples.append(_collect_process_metrics(process))
        if time.monotonic() >= deadline:
            break
    return samples


def _metric_trend(samples: List[Dict[str, Any]], field: str) -> Dict[str, Any]:
    first = samples[0]
    last = samples[-1]
    elapsed = max(last["timestamp"] - first["timestamp"], 0.000001)
    values = [sample[field] for sample in samples]
    change = last[field] - first[field]
    return {
        "first": first[field],
        "last": last[field],
        "minimum": min(values),
        "maximum": max(values),
        "average": round(sum(values) / len(values), 2),
        "change": round(change, 2),
        "change_per_second": round(change / elapsed, 2),
    }


def _format_address(address: Any) -> Optional[Dict[str, Any]]:
    if not address:
        return None
    if hasattr(address, "ip"):
        return {"ip": address.ip, "port": address.port}
    return {"path": str(address)}


def _read_cgroups(pid: int) -> List[Dict[str, str]]:
    cgroups = []
    with open(f"/proc/{pid}/cgroup", encoding="utf-8") as cgroup_file:
        for line in cgroup_file:
            hierarchy, controllers, path = line.rstrip().split(":", 2)
            cgroups.append({
                "hierarchy": hierarchy,
                "controllers": controllers,
                "path": path,
            })
    return cgroups


def _process_summary(process: psutil.Process, now: float) -> Dict[str, Any]:
    with process.oneshot():
        create_time = process.create_time()
        memory = process.memory_info()
        return {
            "pid": process.pid,
            "name": process.name(),
            "username": process.username(),
            "cpu_percent": round(process.cpu_percent(None), 2),
            "rss_bytes": memory.rss,
            "rss_mb": round(memory.rss / 1024 / 1024, 2),
            "status": process.status(),
            "uptime_seconds": round(max(0.0, now - create_time), 2),
            "cmdline": process.cmdline(),
        }


def _sample_processes(sample_seconds: float) -> List[psutil.Process]:
    processes = list(psutil.process_iter())
    for process in processes:
        try:
            process.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if sample_seconds > 0:
        time.sleep(sample_seconds)
    return processes


@mcp.tool()
def list_processes(
    limit: int = 100,
    sort_by: str = "cpu_percent",
    descending: bool = True,
    sample_seconds: float = 0.1,
) -> Dict[str, Any]:
    """Lista processos com PID, nome, usuário, CPU%, RSS, estado, uptime e cmdline."""
    valid_sort_fields = {"pid", "name", "username", "cpu_percent", "rss_bytes", "status", "uptime_seconds"}
    if sort_by not in valid_sort_fields:
        raise ValueError(f"sort_by deve ser um de: {', '.join(sorted(valid_sort_fields))}")
    if limit < 1:
        raise ValueError("limit deve ser maior que zero")
    if not 0 <= sample_seconds <= 5:
        raise ValueError("sample_seconds deve estar entre 0 e 5")

    now = time.time()
    results = []
    skipped = 0
    for process in _sample_processes(sample_seconds):
        try:
            results.append(_process_summary(process, now))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            skipped += 1

    results.sort(key=lambda item: item[sort_by], reverse=descending)
    return {
        "processes": results[:limit],
        "returned": min(limit, len(results)),
        "total_accessible": len(results),
        "skipped": skipped,
    }


@mcp.tool()
def get_process_details(pid: int) -> Dict[str, Any]:
    """Obtém threads, file descriptors, conexões, cgroup e filhos de um processo."""
    try:
        process = psutil.Process(pid)
        now = time.time()
        result = _process_summary(process, now)
    except psutil.NoSuchProcess as error:
        raise ValueError(f"processo {pid} não existe") from error
    except psutil.AccessDenied as error:
        raise PermissionError(f"acesso negado ao processo {pid}") from error

    errors = {}
    try:
        result["threads"] = [thread._asdict() for thread in process.threads()]
    except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
        result["threads"] = []
        errors["threads"] = str(error)

    try:
        result["file_descriptors"] = process.num_fds()
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as error:
        result["file_descriptors"] = None
        errors["file_descriptors"] = str(error)

    try:
        result["connections"] = [
            {
                "fd": connection.fd,
                "family": connection.family.name,
                "type": connection.type.name,
                "local_address": _format_address(connection.laddr),
                "remote_address": _format_address(connection.raddr),
                "status": connection.status,
            }
            for connection in process.net_connections(kind="inet")
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
        result["connections"] = []
        errors["connections"] = str(error)

    try:
        result["cgroups"] = _read_cgroups(pid)
    except (FileNotFoundError, PermissionError, ValueError) as error:
        result["cgroups"] = []
        errors["cgroups"] = str(error)

    try:
        result["children"] = [
            {"pid": child.pid, "name": child.name(), "status": child.status()}
            for child in process.children(recursive=False)
        ]
    except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
        result["children"] = []
        errors["children"] = str(error)

    result["partial_errors"] = errors
    return result


@mcp.tool()
def get_process_tree(root_pid: int = 0, max_depth: int = 20) -> Dict[str, Any]:
    """Retorna a hierarquia pai e filho de todos os processos ou de um PID raiz."""
    if root_pid < 0:
        raise ValueError("root_pid não pode ser negativo")
    if not 0 <= max_depth <= 100:
        raise ValueError("max_depth deve estar entre 0 e 100")

    processes = {}
    children_by_parent: Dict[int, List[int]] = {}
    for process in psutil.process_iter(["pid", "ppid", "name", "username", "status", "cmdline"]):
        try:
            info = process.info
            processes[info["pid"]] = info
            children_by_parent.setdefault(info["ppid"], []).append(info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if root_pid and root_pid not in processes:
        raise ValueError(f"processo {root_pid} não existe ou não está acessível")

    def build_node(pid: int, depth: int, visited: set[int]) -> Dict[str, Any]:
        info = processes[pid]
        node = {
            "pid": pid,
            "ppid": info["ppid"],
            "name": info["name"],
            "username": info["username"],
            "status": info["status"],
            "cmdline": info["cmdline"],
            "children": [],
        }
        if depth >= max_depth or pid in visited:
            node["truncated"] = bool(children_by_parent.get(pid))
            return node
        next_visited = visited | {pid}
        node["children"] = [
            build_node(child_pid, depth + 1, next_visited)
            for child_pid in sorted(children_by_parent.get(pid, []))
            if child_pid in processes
        ]
        return node

    if root_pid:
        roots = [root_pid]
    else:
        roots = sorted(
            pid for pid, info in processes.items()
            if info["ppid"] not in processes or info["ppid"] == pid
        )

    return {
        "roots": [build_node(pid, 0, set()) for pid in roots],
        "total_processes": len(processes),
        "root_pid": root_pid or None,
        "max_depth": max_depth,
    }


@mcp.tool()
def find_resource_hogs(
    resource: str = "cpu",
    limit: int = 10,
    sample_seconds: float = 0.5,
) -> Dict[str, Any]:
    """Encontra os maiores consumidores de CPU, RAM, I/O ou file descriptors."""
    resource = resource.lower()
    if resource not in {"cpu", "ram", "io", "fds"}:
        raise ValueError("resource deve ser cpu, ram, io ou fds")
    if limit < 1:
        raise ValueError("limit deve ser maior que zero")
    if not 0 <= sample_seconds <= 5:
        raise ValueError("sample_seconds deve estar entre 0 e 5")

    processes = list(psutil.process_iter())
    io_before = {}
    for process in processes:
        try:
            process.cpu_percent(None)
            counters = process.io_counters()
            io_before[process.pid] = counters.read_bytes + counters.write_bytes
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue
    if sample_seconds > 0:
        time.sleep(sample_seconds)

    results = []
    for process in processes:
        try:
            with process.oneshot():
                memory = process.memory_info()
                counters = process.io_counters()
                io_total = counters.read_bytes + counters.write_bytes
                io_rate = max(0, io_total - io_before.get(process.pid, io_total)) / sample_seconds if sample_seconds else 0.0
                try:
                    file_descriptors = process.num_fds()
                except (psutil.AccessDenied, AttributeError):
                    file_descriptors = None
                results.append({
                    "pid": process.pid,
                    "name": process.name(),
                    "username": process.username(),
                    "cpu_percent": round(process.cpu_percent(None), 2),
                    "rss_bytes": memory.rss,
                    "rss_mb": round(memory.rss / 1024 / 1024, 2),
                    "io_bytes_per_second": round(io_rate, 2),
                    "io_total_bytes": io_total,
                    "file_descriptors": file_descriptors,
                    "cmdline": process.cmdline(),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    sort_field = {
        "cpu": "cpu_percent",
        "ram": "rss_bytes",
        "io": "io_bytes_per_second",
        "fds": "file_descriptors",
    }[resource]
    results.sort(key=lambda item: item[sort_field] if item[sort_field] is not None else -1, reverse=True)
    return {
        "resource": resource,
        "processes": results[:limit],
        "sample_seconds": sample_seconds,
    }


@mcp.tool()
def detect_zombie_processes(
    include_orphans: bool = True,
    include_uninterruptible: bool = True,
) -> Dict[str, Any]:
    """Detecta processos zumbis, processos adotados pelo PID 1 e processos em estado D."""
    findings = []
    counts = {"zombie": 0, "orphan": 0, "uninterruptible": 0}
    for process in psutil.process_iter(["pid", "ppid", "name", "username", "status", "create_time", "cmdline"]):
        try:
            info = process.info
            finding_types = []
            if info["status"] == psutil.STATUS_ZOMBIE:
                finding_types.append("zombie")
            if include_uninterruptible and info["status"] == psutil.STATUS_DISK_SLEEP:
                finding_types.append("uninterruptible")
            if include_orphans and info["ppid"] == 1 and info["pid"] != 1:
                try:
                    if os.getsid(info["pid"]) != info["pid"]:
                        finding_types.append("orphan")
                except (ProcessLookupError, PermissionError):
                    pass
            if not finding_types:
                continue
            for finding_type in finding_types:
                counts[finding_type] += 1
            findings.append({
                "types": finding_types,
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"],
                "username": info["username"],
                "status": info["status"],
                "uptime_seconds": round(max(0.0, time.time() - info["create_time"]), 2),
                "cmdline": info["cmdline"],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return {"findings": findings, "counts": counts, "total": len(findings)}


@mcp.tool()
def analyze_process_behavior(
    pid: int,
    duration_seconds: float = 5.0,
    interval_seconds: float = 1.0,
) -> Dict[str, Any]:
    """Analisa a evolução de CPU, memória, I/O, threads e file descriptors de um processo."""
    process = _get_process(pid)
    target = _action_target(process)
    samples = _sample_process_metrics(pid, duration_seconds, interval_seconds)
    return {
        "process": target,
        "duration_seconds": duration_seconds,
        "interval_seconds": interval_seconds,
        "sample_count": len(samples),
        "trends": {
            field: _metric_trend(samples, field)
            for field in (
                "cpu_percent",
                "rss_bytes",
                "read_bytes",
                "write_bytes",
                "threads",
                "file_descriptors",
            )
        },
        "samples": samples,
    }


@mcp.tool()
def identify_runaway_process(
    pid: int,
    duration_seconds: float = 10.0,
    interval_seconds: float = 1.0,
    cpu_threshold: float = 90.0,
    memory_growth_mb_per_second: float = 10.0,
) -> Dict[str, Any]:
    """Identifica crescimento persistente de CPU, memória, threads, FDs ou I/O sem convergência."""
    if not 0 <= cpu_threshold <= 100 * (psutil.cpu_count() or 1):
        raise ValueError("cpu_threshold está fora do intervalo válido")
    if memory_growth_mb_per_second < 0:
        raise ValueError("memory_growth_mb_per_second não pode ser negativo")
    process = _get_process(pid)
    target = _action_target(process)
    samples = _sample_process_metrics(pid, duration_seconds, interval_seconds)
    trends = {
        field: _metric_trend(samples, field)
        for field in (
            "cpu_percent",
            "rss_bytes",
            "read_bytes",
            "write_bytes",
            "threads",
            "file_descriptors",
        )
    }
    recent_cpu = [sample["cpu_percent"] for sample in samples[-3:]]
    rss_growth = trends["rss_bytes"]["change_per_second"] / 1024 / 1024
    reasons = []
    if recent_cpu and all(value >= cpu_threshold for value in recent_cpu):
        reasons.append("cpu persistentemente acima do limite")
    if rss_growth >= memory_growth_mb_per_second:
        reasons.append("rss cresce acima do limite sem convergência")
    if trends["threads"]["change"] > 0 and trends["threads"]["last"] == trends["threads"]["maximum"]:
        reasons.append("quantidade de threads continua crescendo")
    if trends["file_descriptors"]["change"] > 0 and trends["file_descriptors"]["last"] == trends["file_descriptors"]["maximum"]:
        reasons.append("quantidade de file descriptors continua crescendo")
    return {
        "process": target,
        "runaway": bool(reasons),
        "reasons": reasons,
        "thresholds": {
            "cpu_percent": cpu_threshold,
            "memory_growth_mb_per_second": memory_growth_mb_per_second,
        },
        "observed_memory_growth_mb_per_second": round(rss_growth, 2),
        "trends": trends,
        "samples": samples,
    }


@mcp.tool()
def classify_process_criticality(pid: int) -> Dict[str, Any]:
    """Classifica um processo como essencial, descartável ou interativo."""
    process = _get_process(pid)
    with process.oneshot():
        target = _action_target(process)
        parent_pid = process.ppid()
        terminal = process.terminal()
        status = process.status()
    name = target["name"].lower()
    command = " ".join(target["cmdline"]).lower()
    evidence = []
    disposable_markers = {
        "make",
        "ninja",
        "cargo",
        "gcc",
        "clang",
        "pytest",
        "ffmpeg",
        "tar",
        "gzip",
    }
    interactive_markers = {
        "bash",
        "zsh",
        "fish",
        "code",
        "vim",
        "nvim",
        "firefox",
        "chrome",
        "chromium",
    }
    if pid == 1 or target["name"] in PROTECTED_PROCESS_NAMES or not target["cmdline"]:
        classification = "essential"
        evidence.append("processo integra a base do sistema ou da sessão")
    elif terminal or name in interactive_markers:
        classification = "interactive"
        evidence.append("processo possui terminal ou aplicação interativa conhecida")
    elif any(marker in name or marker in command for marker in disposable_markers):
        classification = "disposable"
        evidence.append("processo corresponde a uma carga relançável conhecida")
    elif target["username"] == psutil.Process().username():
        classification = "interactive"
        evidence.append("processo pertence ao usuário da sessão atual")
    else:
        classification = "essential"
        evidence.append("processo não interativo de outro usuário")
    return {
        "process": target,
        "classification": classification,
        "evidence": evidence,
        "parent_pid": parent_pid,
        "terminal": terminal,
        "status": status,
    }


@mcp.tool()
def limit_process_resources(
    pid: int,
    cpu_percent: Optional[float] = None,
    memory_high_mb: Optional[int] = None,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Aplica cpu.max e memory.high a um processo usando cgroup v2."""
    if cpu_percent is None and memory_high_mb is None:
        raise ValueError("informe cpu_percent ou memory_high_mb")
    if cpu_percent is not None and not 1 <= cpu_percent <= 100:
        raise ValueError("cpu_percent deve estar entre 1 e 100")
    if memory_high_mb is not None and memory_high_mb < 16:
        raise ValueError("memory_high_mb deve ser pelo menos 16")
    parameters = {"cpu_percent": cpu_percent, "memory_high_mb": memory_high_mb}

    def operation(process: psutil.Process) -> Dict[str, Any]:
        root = Path(os.environ.get("PROCESS_MONITOR_CGROUP_ROOT", "/sys/fs/cgroup"))
        if not (root / "cgroup.controllers").exists():
            raise OSError("cgroup v2 não está disponível")
        group = root / "process-monitor-mcp" / str(process.pid)
        group.mkdir(parents=True, exist_ok=True)
        if cpu_percent is not None:
            quota = round(100000 * cpu_percent / 100)
            (group / "cpu.max").write_text(f"{quota} 100000\n", encoding="utf-8")
        if memory_high_mb is not None:
            (group / "memory.high").write_text(
                f"{memory_high_mb * 1024 * 1024}\n",
                encoding="utf-8",
            )
        (group / "cgroup.procs").write_text(f"{process.pid}\n", encoding="utf-8")
        return {"cgroup": str(group), "limits": parameters}

    return _run_action("limit_process_resources", pid, parameters, dry_run, operation)


@mcp.tool()
def set_process_priority(
    pid: int,
    nice: Optional[int] = None,
    io_class: Optional[str] = None,
    io_priority: int = 4,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Ajusta as prioridades de CPU e I/O de um processo."""
    if nice is None and io_class is None:
        raise ValueError("informe nice ou io_class")
    if nice is not None and not -20 <= nice <= 19:
        raise ValueError("nice deve estar entre -20 e 19")
    io_classes = {
        "none": psutil.IOPRIO_CLASS_NONE,
        "realtime": psutil.IOPRIO_CLASS_RT,
        "best_effort": psutil.IOPRIO_CLASS_BE,
        "idle": psutil.IOPRIO_CLASS_IDLE,
    }
    if io_class is not None and io_class not in io_classes:
        raise ValueError("io_class deve ser none, realtime, best_effort ou idle")
    if not 0 <= io_priority <= 7:
        raise ValueError("io_priority deve estar entre 0 e 7")
    parameters = {"nice": nice, "io_class": io_class, "io_priority": io_priority}

    def operation(process: psutil.Process) -> Dict[str, Any]:
        if nice is not None:
            process.nice(nice)
        if io_class is not None:
            priority = 0 if io_class in {"none", "idle"} else io_priority
            process.ionice(io_classes[io_class], priority)
        current_io = process.ionice()
        return {
            "nice": process.nice(),
            "io_class": current_io.ioclass,
            "io_priority": current_io.value,
        }

    return _run_action("set_process_priority", pid, parameters, dry_run, operation)


@mcp.tool()
def protect_process(
    pid: int,
    oom_score_adj: int = -500,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Ajusta oom_score_adj para reduzir ou aumentar a preferência do OOM killer."""
    if not -1000 <= oom_score_adj <= 1000:
        raise ValueError("oom_score_adj deve estar entre -1000 e 1000")
    parameters = {"oom_score_adj": oom_score_adj}

    def operation(process: psutil.Process) -> Dict[str, Any]:
        path = Path(f"/proc/{process.pid}/oom_score_adj")
        path.write_text(f"{oom_score_adj}\n", encoding="utf-8")
        return {"oom_score_adj": int(path.read_text(encoding="utf-8").strip())}

    return _run_action("protect_process", pid, parameters, dry_run, operation)


@mcp.tool()
def suspend_process(pid: int, dry_run: bool = True) -> Dict[str, Any]:
    """Suspende um processo com SIGSTOP."""
    return _run_action(
        "suspend_process",
        pid,
        {},
        dry_run,
        lambda process: process.suspend() or {"status": "suspended"},
    )


@mcp.tool()
def resume_process(pid: int, dry_run: bool = True) -> Dict[str, Any]:
    """Retoma um processo suspenso com SIGCONT."""
    return _run_action(
        "resume_process",
        pid,
        {},
        dry_run,
        lambda process: process.resume() or {"status": "resumed"},
    )


@mcp.tool()
def kill_process(
    pid: int,
    timeout_seconds: float = 10.0,
    force_after_timeout: bool = True,
    dry_run: bool = True,
) -> Dict[str, Any]:
    """Envia SIGTERM e, opcionalmente, SIGKILL após o timeout."""
    if not 0.1 <= timeout_seconds <= 60:
        raise ValueError("timeout_seconds deve estar entre 0.1 e 60")
    parameters = {
        "timeout_seconds": timeout_seconds,
        "force_after_timeout": force_after_timeout,
    }

    def operation(process: psutil.Process) -> Dict[str, Any]:
        process.terminate()
        try:
            exit_code = process.wait(timeout=timeout_seconds)
            return {"signal": "SIGTERM", "exit_code": exit_code}
        except psutil.TimeoutExpired:
            if not force_after_timeout:
                raise OSError("processo não encerrou antes do timeout")
            process.kill()
            exit_code = process.wait(timeout=timeout_seconds)
            return {"signal": "SIGKILL", "exit_code": exit_code}

    return _run_action("kill_process", pid, parameters, dry_run, operation)


# Memória

@mcp.tool()
def get_memory_status() -> Dict[str, Any]:
    """Retorna memória física, cache, buffers e swap."""
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {"memory": memory._asdict(), "swap": swap._asdict()}


@mcp.tool()
def get_memory_by_process(limit: int = 20) -> Dict[str, Any]:
    """Ordena processos por RSS, PSS e USS."""
    if limit < 1:
        raise ValueError("limit deve ser maior que zero")
    rows = []
    for process in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        try:
            full = process.memory_full_info()
            rows.append({"pid": process.pid, "name": process.info["name"], "username": process.info["username"], "rss_bytes": process.info["memory_info"].rss, "pss_bytes": getattr(full, "pss", None), "uss_bytes": getattr(full, "uss", None)})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    rows.sort(key=lambda row: row["rss_bytes"], reverse=True)
    return {"processes": rows[:limit], "total_accessible": len(rows)}


@mcp.tool()
def get_swap_activity(sample_seconds: float = 1.0) -> Dict[str, Any]:
    """Mede swap in e swap out no intervalo informado."""
    if not 0.1 <= sample_seconds <= 10:
        raise ValueError("sample_seconds deve estar entre 0.1 e 10")
    before = psutil.swap_memory()
    time.sleep(sample_seconds)
    after = psutil.swap_memory()
    return {"sample_seconds": sample_seconds, "sin_bytes_per_second": round(max(0, after.sin - before.sin) / sample_seconds, 2), "sout_bytes_per_second": round(max(0, after.sout - before.sout) / sample_seconds, 2), "swap": after._asdict()}


@mcp.tool()
def get_oom_history(hours: int = 24, limit: int = 100) -> Dict[str, Any]:
    """Busca eventos do OOM killer no journal e no kernel."""
    result = _run_command(["journalctl", "-k", "--since", f"{hours} hours ago", "--no-pager", "-g", "oom|out of memory|killed process"], 30)
    lines = result["stdout"].splitlines()[-limit:]
    return {"events": lines, "count": len(lines), "source": "journalctl", "errors": result["stderr"]}


@mcp.tool()
def analyze_memory_pressure(sample_seconds: float = 1.0) -> Dict[str, Any]:
    """Analisa PSI de memória e sua variação."""
    before = _parse_psi("memory")
    time.sleep(max(0.1, min(sample_seconds, 10.0)))
    after = _parse_psi("memory")
    return {"before": before, "after": after, "memory": psutil.virtual_memory()._asdict(), "pressure": after.get("some", {}).get("avg10", 0) > 1.0 or after.get("full", {}).get("avg10", 0) > 0.1}


@mcp.tool()
def detect_memory_leaks(duration_seconds: float = 5.0, interval_seconds: float = 1.0, limit: int = 20) -> Dict[str, Any]:
    """Detecta crescimento monotônico de RSS por processo."""
    if not 1 <= duration_seconds <= 60 or not 0.2 <= interval_seconds <= duration_seconds:
        raise ValueError("intervalos inválidos")
    histories: Dict[int, List[int]] = defaultdict(list)
    identities: Dict[int, Dict[str, Any]] = {}
    deadline = time.monotonic() + duration_seconds
    while time.monotonic() < deadline:
        for process in psutil.process_iter(["pid", "name", "username", "memory_info"]):
            try:
                histories[process.pid].append(process.info["memory_info"].rss)
                identities[process.pid] = {"pid": process.pid, "name": process.info["name"], "username": process.info["username"]}
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        time.sleep(min(interval_seconds, max(0, deadline - time.monotonic())))
    findings = []
    for pid, values in histories.items():
        if len(values) >= 3 and all(left <= right for left, right in zip(values, values[1:])) and values[-1] > values[0]:
            findings.append({**identities[pid], "growth_bytes": values[-1] - values[0], "samples": values})
    findings.sort(key=lambda row: row["growth_bytes"], reverse=True)
    return {"findings": findings[:limit], "duration_seconds": duration_seconds}


@mcp.tool()
def diagnose_oom_risk() -> Dict[str, Any]:
    """Estima o risco atual de OOM usando disponibilidade, swap e PSI."""
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    psi = _parse_psi("memory")
    score = min(100, round((100 - memory.available * 100 / memory.total) * 0.6 + swap.percent * 0.25 + min(15, psi.get("some", {}).get("avg10", 0) * 3), 2))
    return {"risk_score": score, "risk": "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 50 else "low", "available_bytes": memory.available, "swap_percent": swap.percent, "psi": psi}


@mcp.tool()
def apply_memory_limit(pid: int, memory_high_mb: int, dry_run: bool = True) -> Dict[str, Any]:
    """Aplica memory.high a um processo em cgroup v2."""
    if memory_high_mb < 16:
        raise ValueError("memory_high_mb deve ser pelo menos 16")
    parameters = {"memory_high_mb": memory_high_mb}
    def operation(process: psutil.Process) -> Dict[str, Any]:
        group = Path(os.environ.get("PROCESS_MONITOR_CGROUP_ROOT", "/sys/fs/cgroup")) / "process-monitor-mcp" / str(process.pid)
        group.mkdir(parents=True, exist_ok=True)
        (group / "memory.high").write_text(f"{memory_high_mb * 1024 * 1024}\n", encoding="utf-8")
        (group / "cgroup.procs").write_text(f"{process.pid}\n", encoding="utf-8")
        return {"cgroup": str(group), **parameters}
    return _run_action("apply_memory_limit", pid, parameters, dry_run, operation)


@mcp.tool()
def adjust_swappiness(value: int, dry_run: bool = True) -> Dict[str, Any]:
    """Altera vm.swappiness."""
    if not 0 <= value <= 200:
        raise ValueError("value deve estar entre 0 e 200")
    return _system_action("adjust_swappiness", {"value": value}, ["sysctl", "-w", f"vm.swappiness={value}"], dry_run)


@mcp.tool()
def drop_caches(level: int = 3, dry_run: bool = True) -> Dict[str, Any]:
    """Libera page cache, dentries e inodes."""
    if level not in {1, 2, 3}:
        raise ValueError("level deve ser 1, 2 ou 3")
    return _system_action("drop_caches", {"level": level}, ["sh", "-c", f"sync && printf {level} > /proc/sys/vm/drop_caches"], dry_run)


@mcp.tool()
def clear_swap(dry_run: bool = True) -> Dict[str, Any]:
    """Desativa e reativa todas as áreas de swap."""
    return _system_action("clear_swap", {}, ["sh", "-c", "swapoff -a && swapon -a"], dry_run, 300)


# CPU, térmico e energia

@mcp.tool()
def get_cpu_status(sample_seconds: float = 0.5) -> Dict[str, Any]:
    """Retorna uso por core, load, tempos e frequência."""
    return {"per_core_percent": psutil.cpu_percent(interval=max(0.1, min(sample_seconds, 5)), percpu=True), "total_percent": psutil.cpu_percent(None), "load_average": list(os.getloadavg()), "times_percent": psutil.cpu_times_percent()._asdict(), "frequency": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None, "logical_cpus": psutil.cpu_count(), "physical_cpus": psutil.cpu_count(logical=False)}


@mcp.tool()
def get_thermal_status() -> Dict[str, Any]:
    """Retorna sensores térmicos e estado de throttling disponível."""
    sensors = {name: [entry._asdict() for entry in entries] for name, entries in getattr(psutil, "sensors_temperatures", lambda: {})().items()}
    throttling = {path.parent.name: _read_text(path) for path in Path("/sys/devices/system/cpu").glob("cpu*/thermal_throttle/*")}
    return {"sensors": sensors, "throttling": throttling}


@mcp.tool()
def get_cpu_governor() -> Dict[str, Any]:
    """Retorna governors e frequências por CPU."""
    cpus = []
    for directory in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*")):
        cpus.append({"cpu": directory.name, "governor": _read_text(directory / "cpufreq" / "scaling_governor"), "available_governors": _read_text(directory / "cpufreq" / "scaling_available_governors").split(), "current_khz": _read_text(directory / "cpufreq" / "scaling_cur_freq")})
    return {"cpus": cpus}


@mcp.tool()
def get_battery_status() -> Dict[str, Any]:
    """Retorna carga, autonomia, ciclos e capacidade da bateria."""
    battery = psutil.sensors_battery()
    devices = []
    for path in Path("/sys/class/power_supply").glob("BAT*"):
        devices.append({"name": path.name, "status": _read_text(path / "status"), "capacity_percent": _read_text(path / "capacity"), "cycle_count": _read_text(path / "cycle_count"), "energy_full": _read_text(path / "energy_full"), "energy_full_design": _read_text(path / "energy_full_design"), "power_now": _read_text(path / "power_now")})
    return {"summary": battery._asdict() if battery else None, "batteries": devices}


@mcp.tool()
def get_power_consumption() -> Dict[str, Any]:
    """Estima consumo atual usando RAPL ou bateria."""
    domains = []
    for path in Path("/sys/class/powercap").glob("intel-rapl*/energy_uj"):
        before = int(_read_text(path, "0")); time.sleep(0.1); after = int(_read_text(path, "0"))
        domains.append({"domain": _read_text(path.parent / "name", path.parent.name), "watts": round(max(0, after - before) / 100000, 3)})
    battery = get_battery_status()
    return {"rapl": domains, "battery": battery, "source": "rapl" if domains else "battery"}


@mcp.tool()
def get_power_profile() -> Dict[str, Any]:
    """Retorna o perfil de energia ativo."""
    result = _run_command(["powerprofilesctl", "get"])
    return {"profile": result["stdout"] or None, "available": result["success"], "error": result["stderr"]}


@mcp.tool()
def diagnose_cpu_saturation() -> Dict[str, Any]:
    """Separa uso de CPU, iowait, steal, PSI e carga."""
    times = psutil.cpu_times_percent(interval=1)
    load = os.getloadavg()
    cpus = psutil.cpu_count() or 1
    dominant = "iowait" if getattr(times, "iowait", 0) > 10 else "steal" if getattr(times, "steal", 0) > 5 else "cpu" if load[0] > cpus else "none"
    return {"dominant": dominant, "saturated": dominant != "none", "times_percent": times._asdict(), "load_average": list(load), "cpu_count": cpus, "psi": _parse_psi("cpu")}


@mcp.tool()
def diagnose_battery_drain() -> Dict[str, Any]:
    """Correlaciona bateria, perfil e processos com maior CPU."""
    battery = get_battery_status()
    hogs = find_resource_hogs("cpu", 10, 0.5)
    return {"battery": battery, "power_profile": get_power_profile(), "top_cpu_processes": hogs["processes"], "draining": bool(battery["summary"] and not battery["summary"]["power_plugged"])}


@mcp.tool()
def diagnose_thermal_throttling() -> Dict[str, Any]:
    """Correlaciona temperatura, frequência e throttling."""
    thermal = get_thermal_status()
    temperatures = [entry["current"] for entries in thermal["sensors"].values() for entry in entries if entry.get("current") is not None]
    maximum = max(temperatures, default=None)
    return {"thermal": thermal, "frequency": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None, "maximum_temperature": maximum, "risk": "high" if maximum and maximum >= 90 else "medium" if maximum and maximum >= 80 else "low"}


@mcp.tool()
def estimate_battery_runtime() -> Dict[str, Any]:
    """Estima autonomia a partir da telemetria da bateria."""
    battery = psutil.sensors_battery()
    return {"seconds_left": battery.secsleft if battery else None, "hours_left": round(battery.secsleft / 3600, 2) if battery and battery.secsleft >= 0 else None, "percent": battery.percent if battery else None, "power_plugged": battery.power_plugged if battery else None}


@mcp.tool()
def set_screen_brightness(percent: int, dry_run: bool = True) -> Dict[str, Any]:
    """Ajusta o brilho da tela."""
    if not 1 <= percent <= 100:
        raise ValueError("percent deve estar entre 1 e 100")
    return _system_action("set_screen_brightness", {"percent": percent}, ["brightnessctl", "set", f"{percent}%"], dry_run)


@mcp.tool()
def set_power_profile(profile: str, dry_run: bool = True) -> Dict[str, Any]:
    """Troca o perfil de energia."""
    if profile not in {"power-saver", "balanced", "performance"}:
        raise ValueError("profile inválido")
    return _system_action("set_power_profile", {"profile": profile}, ["powerprofilesctl", "set", profile], dry_run)


@mcp.tool()
def set_cpu_governor(governor: str, dry_run: bool = True) -> Dict[str, Any]:
    """Define o governor para todas as CPUs."""
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", governor):
        raise ValueError("governor inválido")
    return _system_action("set_cpu_governor", {"governor": governor}, ["cpupower", "frequency-set", "-g", governor], dry_run)


@mcp.tool()
def apply_cpu_quota(pid: int, cpu_percent: float, dry_run: bool = True) -> Dict[str, Any]:
    """Aplica quota de CPU a um processo."""
    return limit_process_resources(pid=pid, cpu_percent=cpu_percent, memory_high_mb=None, dry_run=dry_run)


@mcp.tool()
def toggle_device(device: str, enabled: bool, dry_run: bool = True) -> Dict[str, Any]:
    """Liga ou desliga Wi-Fi, Bluetooth ou webcam."""
    commands = {"wifi": ["nmcli", "radio", "wifi", "on" if enabled else "off"], "bluetooth": ["rfkill", "unblock" if enabled else "block", "bluetooth"], "webcam": ["modprobe", "uvcvideo"] if enabled else ["modprobe", "-r", "uvcvideo"]}
    if device not in commands:
        raise ValueError("device deve ser wifi, bluetooth ou webcam")
    return _system_action("toggle_device", {"device": device, "enabled": enabled}, commands[device], dry_run)


# Disco e I/O

@mcp.tool()
def get_disk_usage() -> Dict[str, Any]:
    """Retorna espaço e inodes por ponto de montagem."""
    rows = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            stats = os.statvfs(partition.mountpoint)
            rows.append({**partition._asdict(), **usage._asdict(), "inode_total": stats.f_files, "inode_free": stats.f_ffree})
        except (OSError, PermissionError):
            continue
    return {"filesystems": rows}


@mcp.tool()
def get_io_stats(sample_seconds: float = 1.0) -> Dict[str, Any]:
    """Mede throughput e operações por dispositivo."""
    before = psutil.disk_io_counters(perdisk=True); time.sleep(max(0.1, min(sample_seconds, 10))); after = psutil.disk_io_counters(perdisk=True)
    devices = []
    for name, current in after.items():
        previous = before.get(name, current)
        devices.append({"device": name, "read_bytes_per_second": round((current.read_bytes - previous.read_bytes) / sample_seconds, 2), "write_bytes_per_second": round((current.write_bytes - previous.write_bytes) / sample_seconds, 2), "read_time_ms": current.read_time, "write_time_ms": current.write_time})
    return {"devices": devices, "psi": _parse_psi("io")}


@mcp.tool()
def get_disk_health(device: str = "") -> Dict[str, Any]:
    """Obtém atributos SMART dos discos."""
    devices = [device] if device else [str(path) for path in Path("/dev").glob("sd[a-z]")] + [str(path) for path in Path("/dev").glob("nvme[0-9]n[0-9]")]
    return {"devices": [{"device": item, "smart": _run_command(["smartctl", "-a", "-j", item], 30)} for item in devices]}


def _find_files(path: str, limit: int, predicate: Any, key: Any) -> List[Dict[str, Any]]:
    rows = []
    for root, _, files in os.walk(Path(path).expanduser()):
        for name in files:
            candidate = Path(root) / name
            try:
                stat = candidate.stat()
                if predicate(stat): rows.append({"path": str(candidate), "size_bytes": stat.st_size, "atime": stat.st_atime, "mtime": stat.st_mtime})
            except (OSError, PermissionError): continue
    rows.sort(key=key, reverse=True)
    return rows[:limit]


@mcp.tool()
def find_large_files(path: str = "~", limit: int = 20, minimum_mb: int = 100) -> Dict[str, Any]:
    """Encontra os maiores arquivos sob um diretório."""
    return {"files": _find_files(path, limit, lambda stat: stat.st_size >= minimum_mb * 1024 * 1024, lambda row: row["size_bytes"])}


@mcp.tool()
def find_old_files(path: str = "~", days: int = 90, limit: int = 100) -> Dict[str, Any]:
    """Encontra arquivos sem acesso há N dias."""
    threshold = time.time() - days * 86400
    return {"files": _find_files(path, limit, lambda stat: stat.st_atime < threshold, lambda row: time.time() - row["atime"])}


@mcp.tool()
def get_cache_sizes() -> Dict[str, Any]:
    """Mede caches do usuário, pacotes, journal, Docker e lixeira."""
    paths = {"user_cache": Path.home() / ".cache", "trash": Path.home() / ".local/share/Trash", "apt": Path("/var/cache/apt"), "journal": Path("/var/log/journal"), "docker": Path("/var/lib/docker")}
    def size(path: Path) -> int:
        return sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.exists() else 0
    return {name: {"path": str(path), "bytes": size(path)} for name, path in paths.items()}


@mcp.tool()
def diagnose_disk_full() -> Dict[str, Any]:
    """Identifica filesystems cheios e diretórios grandes."""
    usage = get_disk_usage()["filesystems"]
    critical = [row for row in usage if row["percent"] >= 85 or row["inode_free"] / max(1, row["inode_total"]) < 0.1]
    return {"critical_filesystems": critical, "cache_sizes": get_cache_sizes(), "findings": len(critical)}


@mcp.tool()
def analyze_io_pressure() -> Dict[str, Any]:
    """Analisa PSI de I/O e processos com maior volume."""
    return {"psi": _parse_psi("io"), "top_processes": find_resource_hogs("io", 10, 1.0)["processes"]}


@mcp.tool()
def predict_disk_exhaustion(days_window: int = 30) -> Dict[str, Any]:
    """Projeta esgotamento com base nos snapshots históricos."""
    history = get_metrics_history(hours=days_window * 24, limit=10000)
    points = [(row["created_at"], row["payload"].get("disk_free")) for row in history["snapshots"] if row["payload"].get("disk_free") is not None]
    if len(points) < 2: return {"predictable": False, "reason": "histórico insuficiente"}
    elapsed = points[-1][0] - points[0][0]; consumed = points[0][1] - points[-1][1]
    rate = consumed / elapsed if elapsed > 0 else 0
    return {"predictable": rate > 0, "growth_bytes_per_second": round(rate, 2), "seconds_remaining": round(points[-1][1] / rate, 2) if rate > 0 else None}


@mcp.tool()
def assess_disk_failure_risk(device: str = "") -> Dict[str, Any]:
    """Classifica risco a partir do resultado SMART."""
    health = get_disk_health(device)
    for row in health["devices"]:
        text = row["smart"]["stdout"].lower()
        row["risk"] = "high" if "failed" in text or "prefail" in text else "unknown" if not row["smart"]["success"] else "low"
    return health


@mcp.tool()
def throttle_process_io(pid: int, read_bps: Optional[int] = None, write_bps: Optional[int] = None, device: str = "8:0", dry_run: bool = True) -> Dict[str, Any]:
    """Aplica io.max a um processo via cgroup v2."""
    if read_bps is None and write_bps is None: raise ValueError("informe read_bps ou write_bps")
    parameters = {"read_bps": read_bps, "write_bps": write_bps, "device": device}
    def operation(process: psutil.Process) -> Dict[str, Any]:
        group = Path(os.environ.get("PROCESS_MONITOR_CGROUP_ROOT", "/sys/fs/cgroup")) / "process-monitor-mcp" / str(process.pid); group.mkdir(parents=True, exist_ok=True)
        limits = [device] + ([f"rbps={read_bps}"] if read_bps else []) + ([f"wbps={write_bps}"] if write_bps else [])
        (group / "io.max").write_text(" ".join(limits) + "\n", encoding="utf-8"); (group / "cgroup.procs").write_text(f"{process.pid}\n", encoding="utf-8")
        return {"cgroup": str(group), "limits": limits}
    return _run_action("throttle_process_io", pid, parameters, dry_run, operation)


@mcp.tool()
def cleanup_package_cache(dry_run: bool = True) -> Dict[str, Any]:
    """Limpa o cache do gerenciador de pacotes."""
    command = ["apt-get", "clean"] if shutil.which("apt-get") else ["dnf", "clean", "all"] if shutil.which("dnf") else ["pacman", "-Scc", "--noconfirm"]
    return _system_action("cleanup_package_cache", {}, command, dry_run, 300)


@mcp.tool()
def cleanup_journal_logs(max_size: str = "500M", max_age: str = "30d", dry_run: bool = True) -> Dict[str, Any]:
    """Remove logs antigos do journal por tamanho e idade."""
    return _system_action("cleanup_journal_logs", {"max_size": max_size, "max_age": max_age}, ["journalctl", f"--vacuum-size={max_size}", f"--vacuum-time={max_age}"], dry_run, 300)


@mcp.tool()
def cleanup_temp_files(older_than_days: int = 7, dry_run: bool = True) -> Dict[str, Any]:
    """Remove arquivos temporários antigos."""
    return _system_action("cleanup_temp_files", {"older_than_days": older_than_days}, ["find", "/tmp", "/var/tmp", "-xdev", "-type", "f", "-atime", f"+{older_than_days}", "-delete"], dry_run, 300)


@mcp.tool()
def clear_app_caches(dry_run: bool = True) -> Dict[str, Any]:
    """Limpa caches de aplicações do usuário."""
    return _system_action("clear_app_caches", {}, ["find", str(Path.home() / ".cache"), "-mindepth", "1", "-delete"], dry_run, 300)


@mcp.tool()
def cleanup_docker(dry_run: bool = True) -> Dict[str, Any]:
    """Remove recursos Docker não utilizados."""
    return _system_action("cleanup_docker", {}, ["docker", "system", "prune", "-af", "--volumes"], dry_run, 600)


@mcp.tool()
def remove_old_kernels(keep: int = 2, dry_run: bool = True) -> Dict[str, Any]:
    """Remove kernels antigos preservando os mais recentes."""
    if keep < 1: raise ValueError("keep deve ser maior que zero")
    return _system_action("remove_old_kernels", {"keep": keep}, ["apt-get", "autoremove", "--purge", "-y"], dry_run, 600)


# Sistema e serviços

@mcp.tool()
def get_system_overview() -> Dict[str, Any]:
    """Retorna distribuição, kernel, uptime, desktop e init."""
    os_release = {}
    for line in _read_text(Path("/etc/os-release")).splitlines():
        if "=" in line:
            key, value = line.split("=", 1); os_release[key.lower()] = value.strip('"')
    return {"hostname": socket.gethostname(), "distribution": os_release, "kernel": platform.release(), "architecture": platform.machine(), "uptime_seconds": time.time() - psutil.boot_time(), "desktop": os.environ.get("XDG_CURRENT_DESKTOP"), "init": _read_text(Path("/proc/1/comm"))}


@mcp.tool()
def list_services(state: str = "all", user: bool = False) -> Dict[str, Any]:
    """Lista unidades de serviço systemd."""
    command = ["systemctl"] + (["--user"] if user else []) + ["list-units", "--type=service", "--all", "--no-legend", "--no-pager"]
    result = _run_command(command)
    services = []
    for line in result["stdout"].splitlines():
        fields = line.split(None, 4)
        if len(fields) >= 4 and (state == "all" or fields[3] == state): services.append({"unit": fields[0], "load": fields[1], "active": fields[2], "sub": fields[3], "description": fields[4] if len(fields) > 4 else ""})
    return {"services": services, "error": result["stderr"]}


@mcp.tool()
def get_failed_units() -> Dict[str, Any]:
    """Retorna unidades systemd em falha."""
    return list_services("failed")


@mcp.tool()
def get_boot_analysis() -> Dict[str, Any]:
    """Retorna tempos e cadeia crítica do boot."""
    return {"time": _run_command(["systemd-analyze"]), "blame": _run_command(["systemd-analyze", "blame"]), "critical_chain": _run_command(["systemd-analyze", "critical-chain"])}


@mcp.tool()
def list_startup_apps() -> Dict[str, Any]:
    """Lista entradas XDG autostart e serviços habilitados do usuário."""
    entries = []
    for root in [Path("/etc/xdg/autostart"), Path.home() / ".config/autostart"]:
        for path in root.glob("*.desktop") if root.exists() else []:
            entries.append({"path": str(path), "name": next((line.split("=", 1)[1] for line in _read_text(path).splitlines() if line.startswith("Name=")), path.stem), "enabled": "Hidden=true" not in _read_text(path)})
    return {"desktop_entries": entries, "user_services": _run_command(["systemctl", "--user", "list-unit-files", "--state=enabled", "--no-pager"])}


@mcp.tool()
def get_kernel_messages(priority: str = "err", limit: int = 100) -> Dict[str, Any]:
    """Retorna mensagens recentes do kernel filtradas por prioridade."""
    result = _run_command(["journalctl", "-k", "-p", priority, "-n", str(limit), "--no-pager"])
    return {"messages": result["stdout"].splitlines(), "error": result["stderr"]}


@mcp.tool()
def diagnose_boot_slowness(limit: int = 20) -> Dict[str, Any]:
    """Identifica as unidades mais lentas e a cadeia crítica."""
    analysis = get_boot_analysis()
    return {"slowest_units": analysis["blame"]["stdout"].splitlines()[:limit], "critical_chain": analysis["critical_chain"]}


@mcp.tool()
def diagnose_service_failure(service: str) -> Dict[str, Any]:
    """Cruza estado, logs e dependências de uma unidade."""
    if not re.fullmatch(r"[A-Za-z0-9@_.:-]+", service): raise ValueError("service inválido")
    return {"status": _run_command(["systemctl", "status", service, "--no-pager"]), "logs": _run_command(["journalctl", "-u", service, "-n", "200", "--no-pager"]), "dependencies": _run_command(["systemctl", "list-dependencies", service, "--no-pager"])}


@mcp.tool()
def detect_restart_loops(hours: int = 1, threshold: int = 5) -> Dict[str, Any]:
    """Detecta serviços reiniciados repetidamente."""
    result = _run_command(["journalctl", "--since", f"{hours} hours ago", "--no-pager", "-o", "json"])
    counts: Counter[str] = Counter()
    for line in result["stdout"].splitlines():
        try:
            row = json.loads(line)
            if "start" in str(row.get("MESSAGE", "")).lower(): counts[row.get("_SYSTEMD_UNIT", "unknown")] += 1
        except json.JSONDecodeError: continue
    return {"services": [{"unit": unit, "starts": count} for unit, count in counts.most_common() if count >= threshold]}


@mcp.tool()
def audit_startup_impact() -> Dict[str, Any]:
    """Relaciona tempos de boot com itens de inicialização."""
    return {"boot": get_boot_analysis(), "startup_apps": list_startup_apps()}


def _service_action(action: str, service: str, verb: str, dry_run: bool) -> Dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9@_.:-]+", service): raise ValueError("service inválido")
    return _system_action(action, {"service": service}, ["systemctl", verb, service], dry_run, 120)


@mcp.tool()
def reload_daemon(dry_run: bool = True) -> Dict[str, Any]:
    """Recarrega a configuração do systemd."""
    return _system_action("reload_daemon", {}, ["systemctl", "daemon-reload"], dry_run)


@mcp.tool()
def disable_startup_app(path: str, dry_run: bool = True) -> Dict[str, Any]:
    """Desabilita uma entrada XDG autostart do usuário."""
    source = Path(path).expanduser().resolve()
    allowed = [Path("/etc/xdg/autostart").resolve(), (Path.home() / ".config/autostart").resolve()]
    if source.suffix != ".desktop" or not any(root == source.parent for root in allowed): raise ValueError("entrada de autostart inválida")
    target = Path.home() / ".config/autostart" / source.name
    parameters = {"path": str(source), "target": str(target)}
    def operation() -> Dict[str, Any]:
        target.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_text(encoding="utf-8")
        target.write_text(content + "\nHidden=true\n", encoding="utf-8")
        return {"target": str(target)}
    return _state_action("disable_startup_app", parameters, dry_run, operation)


@mcp.tool()
def start_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("start_service", service, "start", dry_run)
@mcp.tool()
def restart_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("restart_service", service, "restart", dry_run)
@mcp.tool()
def stop_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("stop_service", service, "stop", dry_run)
@mcp.tool()
def enable_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("enable_service", service, "enable", dry_run)
@mcp.tool()
def disable_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("disable_service", service, "disable", dry_run)
@mcp.tool()
def mask_service(service: str, dry_run: bool = True) -> Dict[str, Any]: return _service_action("mask_service", service, "mask", dry_run)


# Rede

@mcp.tool()
def get_network_status() -> Dict[str, Any]:
    """Retorna interfaces, endereços, rotas e Wi-Fi."""
    interfaces = {}
    stats = psutil.net_if_stats()
    for name, addresses in psutil.net_if_addrs().items(): interfaces[name] = {"addresses": [address._asdict() for address in addresses], "stats": stats[name]._asdict() if name in stats else None}
    return {"interfaces": interfaces, "routes": _run_command(["ip", "-j", "route"]), "wifi": _run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN", "dev", "wifi"])}


@mcp.tool()
def list_connections(kind: str = "inet") -> Dict[str, Any]:
    """Lista conexões com PID e processo associado."""
    connections = []
    for connection in psutil.net_connections(kind=kind):
        name = None
        if connection.pid:
            try: name = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        connections.append({"fd": connection.fd, "family": connection.family.name, "type": connection.type.name, "local_address": _format_address(connection.laddr), "remote_address": _format_address(connection.raddr), "status": connection.status, "pid": connection.pid, "process": name})
    return {"connections": connections, "count": len(connections)}


@mcp.tool()
def get_bandwidth_by_process(sample_seconds: float = 1.0) -> Dict[str, Any]:
    """Estima banda por processo usando contadores disponíveis no procfs."""
    before = {}
    for process in psutil.process_iter(["pid", "name"]):
        text = _read_text(Path(f"/proc/{process.pid}/net/dev")); before[process.pid] = sum(int(parts[1]) + int(parts[9]) for line in text.splitlines()[2:] if len(parts := line.replace(":", " ").split()) >= 10)
    time.sleep(max(0.1, min(sample_seconds, 10)))
    rows = []
    for pid, initial in before.items():
        text = _read_text(Path(f"/proc/{pid}/net/dev")); current = sum(int(parts[1]) + int(parts[9]) for line in text.splitlines()[2:] if len(parts := line.replace(":", " ").split()) >= 10)
        try: rows.append({"pid": pid, "name": psutil.Process(pid).name(), "bytes_per_second": round(max(0, current - initial) / sample_seconds, 2)})
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
    rows.sort(key=lambda row: row["bytes_per_second"], reverse=True)
    return {"processes": rows, "note": "contadores de /proc/net podem ser compartilhados por namespace"}


@mcp.tool()
def test_connectivity(host: str = "1.1.1.1", dns_name: str = "example.com") -> Dict[str, Any]:
    """Testa DNS, gateway, latência e perda de pacotes."""
    try: dns = {"success": True, "addresses": sorted({item[4][0] for item in socket.getaddrinfo(dns_name, 443)})}
    except socket.gaierror as error: dns = {"success": False, "error": str(error)}
    return {"dns": dns, "ping": _run_command(["ping", "-c", "3", "-W", "2", host], 10), "routes": _run_command(["ip", "route"])}


@mcp.tool()
def get_dns_config() -> Dict[str, Any]:
    """Retorna resolvers configurados e em uso."""
    return {"resolv_conf": _read_text(Path("/etc/resolv.conf")), "resolved": _run_command(["resolvectl", "status"])}


@mcp.tool()
def diagnose_network_issue(host: str = "1.1.1.1", dns_name: str = "example.com") -> Dict[str, Any]:
    """Diagnostica link, IP, rota, DNS e internet."""
    status = get_network_status(); connectivity = test_connectivity(host, dns_name)
    active = [name for name, row in status["interfaces"].items() if row["stats"] and row["stats"]["isup"] and name != "lo"]
    layer = "link" if not active else "route" if not status["routes"]["stdout"] else "dns" if not connectivity["dns"]["success"] else "internet" if not connectivity["ping"]["success"] else "healthy"
    return {"failing_layer": layer, "active_interfaces": active, "connectivity": connectivity}


@mcp.tool()
def diagnose_slow_connection(host: str = "1.1.1.1") -> Dict[str, Any]:
    """Separa latência, DNS e saturação local."""
    before = psutil.net_io_counters(); ping = _run_command(["ping", "-c", "5", host], 15); after = psutil.net_io_counters()
    return {"ping": ping, "bytes_during_test": {"sent": after.bytes_sent - before.bytes_sent, "received": after.bytes_recv - before.bytes_recv}, "interface_errors": {"errin": after.errin, "errout": after.errout, "dropin": after.dropin, "dropout": after.dropout}}


@mcp.tool()
def detect_bandwidth_abuse(sample_seconds: float = 1.0, threshold_bps: int = 10000000) -> Dict[str, Any]:
    """Sinaliza processos acima do limite de banda."""
    data = get_bandwidth_by_process(sample_seconds)
    return {"threshold_bps": threshold_bps, "findings": [row for row in data["processes"] if row["bytes_per_second"] >= threshold_bps], "processes": data["processes"]}


@mcp.tool()
def analyze_wifi_quality() -> Dict[str, Any]:
    """Analisa sinal, taxa, canal e retransmissões Wi-Fi."""
    return {"links": _run_command(["iw", "dev"]), "stations": _run_command(["nmcli", "-f", "IN-USE,SSID,SIGNAL,RATE,CHAN", "dev", "wifi", "list"])}


@mcp.tool()
def flush_dns_cache(dry_run: bool = True) -> Dict[str, Any]: return _system_action("flush_dns_cache", {}, ["resolvectl", "flush-caches"], dry_run)
@mcp.tool()
def limit_process_bandwidth(pid: int, rate_kbit: int, dry_run: bool = True) -> Dict[str, Any]:
    """Limita banda de um processo usando systemd e tc quando disponíveis."""
    return _system_action("limit_process_bandwidth", {"pid": pid, "rate_kbit": rate_kbit}, ["systemd-run", "--scope", "-p", f"IPIngressBandwidthMax=any {rate_kbit}K", "--pid", str(pid)], dry_run)
@mcp.tool()
def set_dns_servers(interface: str, servers: List[str], dry_run: bool = True) -> Dict[str, Any]:
    """Define resolvers para uma interface."""
    if not servers: raise ValueError("servers não pode ser vazio")
    return _system_action("set_dns_servers", {"interface": interface, "servers": servers}, ["resolvectl", "dns", interface, *servers], dry_run)
@mcp.tool()
def reconnect_wifi(dry_run: bool = True) -> Dict[str, Any]: return _system_action("reconnect_wifi", {}, ["sh", "-c", "nmcli radio wifi off && nmcli radio wifi on"], dry_run)
@mcp.tool()
def restart_network(dry_run: bool = True) -> Dict[str, Any]: return _system_action("restart_network", {}, ["systemctl", "restart", "NetworkManager"], dry_run)


# Pacotes e atualizações

def _package_manager() -> str:
    return next((name for name in ("apt", "dnf", "pacman") if shutil.which(name)), "")


@mcp.tool()
def list_outdated_packages() -> Dict[str, Any]:
    """Lista pacotes desatualizados dos gerenciadores disponíveis."""
    manager = _package_manager()
    command = ["apt", "list", "--upgradable"] if manager == "apt" else ["dnf", "check-update"] if manager == "dnf" else ["pacman", "-Qu"]
    return {"system": _run_command(command, 120), "snap": _run_command(["snap", "refresh", "--list"], 120), "flatpak": _run_command(["flatpak", "remote-ls", "--updates"], 120)}


@mcp.tool()
def check_security_updates() -> Dict[str, Any]:
    """Lista atualizações de segurança."""
    manager = _package_manager(); command = ["apt-get", "-s", "upgrade"] if manager == "apt" else ["dnf", "updateinfo", "list", "security"] if manager == "dnf" else ["arch-audit"]
    result = _run_command(command, 120)
    lines = [line for line in result["stdout"].splitlines() if manager != "apt" or "security" in line.lower()]
    return {"manager": manager, "updates": lines, "raw": result}


@mcp.tool()
def find_orphan_packages() -> Dict[str, Any]:
    """Lista pacotes candidatos a autoremove."""
    manager = _package_manager(); command = ["apt-get", "-s", "autoremove"] if manager == "apt" else ["dnf", "repoquery", "--unneeded"] if manager == "dnf" else ["pacman", "-Qtdq"]
    return {"manager": manager, "result": _run_command(command, 120)}


@mcp.tool()
def get_package_info(package: str) -> Dict[str, Any]:
    """Retorna versão, origem e dependências de um pacote."""
    if not re.fullmatch(r"[A-Za-z0-9+_.:@-]+", package): raise ValueError("package inválido")
    manager = _package_manager(); command = ["apt-cache", "show", package] if manager == "apt" else ["dnf", "info", package] if manager == "dnf" else ["pacman", "-Si", package]
    return {"manager": manager, "result": _run_command(command, 60)}


@mcp.tool()
def assess_update_risk(package: str) -> Dict[str, Any]:
    """Avalia risco de atualização pelo tipo e dependências."""
    info = get_package_info(package); name = package.lower()
    critical = any(marker in name for marker in ("linux", "kernel", "nvidia", "mesa", "systemd", "gnome", "plasma"))
    return {"package": package, "risk": "high" if critical else "medium", "requires_reboot_likely": any(marker in name for marker in ("linux", "kernel", "systemd")), "info": info}


@mcp.tool()
def detect_broken_dependencies() -> Dict[str, Any]:
    """Detecta dependências quebradas e pacotes semiconfigurados."""
    manager = _package_manager(); command = ["apt-get", "check"] if manager == "apt" else ["dnf", "check"] if manager == "dnf" else ["pacman", "-Dk"]
    return {"manager": manager, "result": _run_command(command, 120)}


@mcp.tool()
def correlate_update_with_regression(hours: int = 48) -> Dict[str, Any]:
    """Relaciona instalações recentes com erros do período."""
    since = datetime.now() - timedelta(hours=hours)
    apt_history = _read_text(Path("/var/log/apt/history.log"))
    return {"since": since.isoformat(), "apt_history": apt_history[-20000:], "errors": get_error_summary(hours)}


def _package_action(action: str, package: str, verb: str, dry_run: bool, version: str = "") -> Dict[str, Any]:
    if package and not re.fullmatch(r"[A-Za-z0-9+_.:@=-]+", package): raise ValueError("package inválido")
    manager = _package_manager()
    if manager == "apt": command = ["apt-get", verb, "-y"] + ([f"{package}={version}" if version else package] if package else [])
    elif manager == "dnf": command = ["dnf", verb, "-y"] + ([package] if package else [])
    else: command = ["pacman", "-S" if verb == "install" else "-R", "--noconfirm"] + ([package] if package else [])
    return _system_action(action, {"package": package, "version": version, "manager": manager}, command, dry_run, 900)


@mcp.tool()
def update_packages(security_only: bool = False, dry_run: bool = True) -> Dict[str, Any]:
    """Atualiza pacotes, opcionalmente apenas segurança."""
    manager = _package_manager(); command = ["apt-get", "upgrade", "-y"] if manager == "apt" else ["dnf", "upgrade", "-y"] + (["--security"] if security_only else []) if manager == "dnf" else ["pacman", "-Syu", "--noconfirm"]
    return _system_action("update_packages", {"security_only": security_only}, command, dry_run, 1800)
@mcp.tool()
def install_package(package: str, dry_run: bool = True) -> Dict[str, Any]: return _package_action("install_package", package, "install", dry_run)
@mcp.tool()
def rollback_package(package: str, version: str, dry_run: bool = True) -> Dict[str, Any]: return _package_action("rollback_package", package, "install", dry_run, version)
@mcp.tool()
def fix_broken_packages(dry_run: bool = True) -> Dict[str, Any]:
    manager = _package_manager(); command = ["apt-get", "-f", "install", "-y"] if manager == "apt" else ["dnf", "distro-sync", "-y"] if manager == "dnf" else ["pacman", "-Dk"]
    return _system_action("fix_broken_packages", {"manager": manager}, command, dry_run, 900)
@mcp.tool()
def remove_package(package: str, dry_run: bool = True) -> Dict[str, Any]: return _package_action("remove_package", package, "remove", dry_run)


# Logs e eventos

@mcp.tool()
def search_logs(query: str = "", unit: str = "", priority: str = "", hours: int = 24, limit: int = 500) -> Dict[str, Any]:
    """Busca eventos no journald por unidade, prioridade e janela."""
    command = ["journalctl", "--since", f"{hours} hours ago", "-n", str(limit), "--no-pager", "-o", "short-iso"]
    if unit: command += ["-u", unit]
    if priority: command += ["-p", priority]
    if query: command += ["-g", query]
    result = _run_command(command, 60)
    return {"events": result["stdout"].splitlines(), "error": result["stderr"]}


@mcp.tool()
def get_error_summary(hours: int = 24) -> Dict[str, Any]:
    """Agrega erros recentes por unidade."""
    result = _run_command(["journalctl", "--since", f"{hours} hours ago", "-p", "err", "-o", "json", "--no-pager"], 60)
    counts: Counter[str] = Counter()
    samples = {}
    for line in result["stdout"].splitlines():
        try:
            row = json.loads(line); unit = row.get("_SYSTEMD_UNIT") or row.get("SYSLOG_IDENTIFIER") or "unknown"; counts[unit] += 1; samples.setdefault(unit, row.get("MESSAGE", ""))
        except json.JSONDecodeError: continue
    return {"errors": [{"unit": unit, "count": count, "sample": samples[unit]} for unit, count in counts.most_common()], "total": sum(counts.values())}


@mcp.tool()
def get_crash_reports(limit: int = 50) -> Dict[str, Any]:
    """Retorna coredumps e relatórios de crash."""
    return {"coredumps": _run_command(["coredumpctl", "list", "--no-pager", "-n", str(limit)]), "apport": [str(path) for path in Path("/var/crash").glob("*")][:limit]}


@mcp.tool()
def tail_logs(unit: str = "", lines: int = 100) -> Dict[str, Any]:
    """Retorna as últimas linhas do journal sem bloquear a chamada."""
    return search_logs(unit=unit, hours=24 * 365, limit=lines)


@mcp.tool()
def build_event_timeline(hours: int = 24, limit: int = 1000) -> Dict[str, Any]:
    """Constrói linha do tempo de eventos correlacionados."""
    result = _run_command(["journalctl", "--since", f"{hours} hours ago", "-n", str(limit), "--no-pager", "-o", "json"])
    events = []
    for line in result["stdout"].splitlines():
        try:
            row = json.loads(line); events.append({"timestamp": int(row.get("__REALTIME_TIMESTAMP", 0)) / 1000000, "unit": row.get("_SYSTEMD_UNIT"), "priority": row.get("PRIORITY"), "message": row.get("MESSAGE")})
        except json.JSONDecodeError: continue
    return {"events": sorted(events, key=lambda event: event["timestamp"])}


@mcp.tool()
def detect_log_anomalies(hours: int = 24) -> Dict[str, Any]:
    """Detecta mensagens raras e unidades com picos de erro."""
    timeline = build_event_timeline(hours)
    signatures: Counter[str] = Counter(re.sub(r"\b\d+\b", "#", str(event["message"]))[:200] for event in timeline["events"])
    return {"rare_messages": [{"signature": signature, "count": count} for signature, count in signatures.items() if count == 1][:100], "event_count": len(timeline["events"])}


@mcp.tool()
def find_error_patterns(hours: int = 24) -> Dict[str, Any]:
    """Agrupa erros recorrentes por assinatura normalizada."""
    events = search_logs(priority="err", hours=hours, limit=5000)["events"]
    patterns: Counter[str] = Counter(re.sub(r"\b(?:0x[0-9a-fA-F]+|\d+)\b", "#", line) for line in events)
    return {"patterns": [{"signature": signature, "count": count} for signature, count in patterns.most_common(100)]}


@mcp.tool()
def set_log_level(service: str, level: str, dry_run: bool = True) -> Dict[str, Any]:
    """Define nível de log temporário de uma unidade."""
    if level not in {"debug", "info", "notice", "warning", "err"}: raise ValueError("level inválido")
    return _system_action("set_log_level", {"service": service, "level": level}, ["systemctl", "set-property", service, f"LogLevelMax={level}"], dry_run)


@mcp.tool()
def export_diagnostic_bundle(hours: int = 24, output_path: str = "/tmp/process-monitor-diagnostics.tar.gz", dry_run: bool = True) -> Dict[str, Any]:
    """Exporta logs e métricas em um arquivo compactado."""
    parameters = {"hours": hours, "output_path": output_path}
    if dry_run: return _system_action("export_diagnostic_bundle", parameters, ["journalctl", "--since", f"{hours} hours ago"], True)
    target = Path(output_path).expanduser().resolve()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); (root / "system.json").write_text(json.dumps(_snapshot_payload(), indent=2), encoding="utf-8")
        logs = _run_command(["journalctl", "--since", f"{hours} hours ago", "--no-pager"], 120); (root / "journal.log").write_text(logs["stdout"], encoding="utf-8")
        with tarfile.open(target, "w:gz") as archive: archive.add(root, arcname="diagnostics")
    _audit_action("export_diagnostic_bundle", {"scope": "system"}, parameters, False, True, str(target))
    return {"success": True, "path": str(target), "size_bytes": target.stat().st_size}


# Diagnóstico combinado

@mcp.tool()
def health_check_full() -> Dict[str, Any]:
    """Executa uma varredura completa e calcula um score de saúde."""
    snapshot = _snapshot_payload()
    findings = []
    checks = [("cpu", snapshot["cpu_percent"], 90), ("memory", snapshot["memory_percent"], 90), ("swap", snapshot["swap_percent"], 80), ("disk", snapshot["disk_percent"], 90)]
    for area, value, threshold in checks:
        if value >= threshold: findings.append({"area": area, "severity": "critical", "value": value, "threshold": threshold})
        elif value >= threshold * 0.75: findings.append({"area": area, "severity": "warning", "value": value, "threshold": threshold})
    failed = get_failed_units().get("services", [])
    if failed: findings.append({"area": "services", "severity": "warning", "count": len(failed)})
    zombies = detect_zombie_processes()
    if zombies["counts"]["zombie"]: findings.append({"area": "processes", "severity": "warning", "zombies": zombies["counts"]["zombie"]})
    penalty = sum(25 if item["severity"] == "critical" else 10 for item in findings)
    return {"score": max(0, 100 - penalty), "findings": findings, "snapshot": snapshot, "failed_units": failed}


@mcp.tool()
def diagnose_slowness() -> Dict[str, Any]:
    """Correlaciona CPU, memória, I/O, PSI e temperatura."""
    cpu = diagnose_cpu_saturation(); memory = diagnose_oom_risk(); io = analyze_io_pressure(); thermal = diagnose_thermal_throttling()
    candidates = {"cpu": 100 if cpu["saturated"] else cpu["times_percent"].get("user", 0), "memory": memory["risk_score"], "io": io["psi"].get("some", {}).get("avg10", 0) * 10, "thermal": 100 if thermal["risk"] == "high" else 50 if thermal["risk"] == "medium" else 0}
    return {"dominant_bottleneck": max(candidates, key=candidates.get), "scores": candidates, "cpu": cpu, "memory": memory, "io": io, "thermal": thermal}


@mcp.tool()
def root_cause_analysis(symptom: str, hours: int = 24) -> Dict[str, Any]:
    """Monta uma timeline causal para um sintoma."""
    terms = [term for term in re.findall(r"[\w.-]+", symptom.lower()) if len(term) > 2]
    timeline = build_event_timeline(hours)["events"]
    related = [event for event in timeline if any(term in str(event["message"]).lower() for term in terms)]
    health = health_check_full()
    return {"symptom": symptom, "related_events": related[-200:], "current_findings": health["findings"], "hypothesis": related[-1]["message"] if related else "nenhum evento diretamente relacionado"}


@mcp.tool()
def detect_anomalies() -> Dict[str, Any]:
    """Compara o estado atual com a baseline mais recente."""
    comparison = compare_with_baseline()
    anomalies = [{"metric": key, "baseline": value["baseline"], "current": value["current"], "change_percent": value["change_percent"]} for key, value in comparison.get("differences", {}).items() if abs(value["change_percent"] or 0) >= 25]
    return {"anomalies": anomalies, "comparison": comparison}


@mcp.tool()
def recommend_actions() -> Dict[str, Any]:
    """Gera plano de remediação ordenado por risco e impacto."""
    diagnosis = diagnose_slowness(); actions = []
    if diagnosis["memory"]["risk_score"] >= 70: actions.append({"tool": "find_resource_hogs", "parameters": {"resource": "ram"}, "risk": "none", "reversible": True, "impact": "identifica consumidores de memória"})
    if diagnosis["scores"]["disk"] > 10: actions.append({"tool": "cleanup_package_cache", "parameters": {"dry_run": True}, "risk": "low", "reversible": False, "impact": "libera cache de pacotes"})
    if diagnosis["cpu"]["saturated"]: actions.append({"tool": "find_resource_hogs", "parameters": {"resource": "cpu"}, "risk": "none", "reversible": True, "impact": "identifica consumidores de CPU"})
    return {"actions": actions, "diagnosis": diagnosis["dominant_bottleneck"]}


@mcp.tool()
def explain_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Reescreve um achado técnico em linguagem acessível."""
    area = finding.get("area", finding.get("metric", "sistema")); severity = finding.get("severity", "informativa")
    return {"summary": f"Foi detectada uma condição {severity} em {area}.", "details": finding, "next_step": "execute recommend_actions para obter opções de correção"}


# Histórico e auditoria

@mcp.tool()
def record_baseline(label: str = "healthy") -> Dict[str, Any]:
    """Registra um snapshot considerado saudável em SQLite."""
    _init_metrics_db(); payload = _snapshot_payload()
    with sqlite3.connect(METRICS_DB) as connection:
        cursor = connection.execute("INSERT INTO snapshots(created_at, kind, payload) VALUES (?, ?, ?)", (payload["timestamp"], f"baseline:{label}", json.dumps(payload)))
    return {"id": cursor.lastrowid, "label": label, "snapshot": payload}


@mcp.tool()
def get_metrics_history(hours: int = 24, limit: int = 1000, kind: str = "") -> Dict[str, Any]:
    """Consulta snapshots armazenados em SQLite."""
    _init_metrics_db(); since = time.time() - hours * 3600
    query = "SELECT id, created_at, kind, payload FROM snapshots WHERE created_at >= ?"; parameters: List[Any] = [since]
    if kind: query += " AND kind = ?"; parameters.append(kind)
    query += " ORDER BY created_at DESC LIMIT ?"; parameters.append(limit)
    with sqlite3.connect(METRICS_DB) as connection: rows = connection.execute(query, parameters).fetchall()
    return {"snapshots": [{"id": row[0], "created_at": row[1], "kind": row[2], "payload": json.loads(row[3])} for row in rows]}


@mcp.tool()
def compare_with_baseline(label: str = "healthy") -> Dict[str, Any]:
    """Compara estado atual com a baseline mais recente."""
    _init_metrics_db()
    with sqlite3.connect(METRICS_DB) as connection: row = connection.execute("SELECT id, created_at, payload FROM snapshots WHERE kind = ? ORDER BY created_at DESC LIMIT 1", (f"baseline:{label}",)).fetchone()
    if row is None: return {"available": False, "reason": "baseline não encontrada"}
    baseline = json.loads(row[2]); current = _snapshot_payload(); differences = {}
    for key in ("cpu_percent", "memory_percent", "swap_percent", "disk_percent", "process_count"):
        old, new = baseline.get(key), current.get(key); differences[key] = {"baseline": old, "current": new, "change": new - old, "change_percent": round((new - old) * 100 / old, 2) if old else None}
    return {"available": True, "baseline_id": row[0], "baseline_created_at": row[1], "differences": differences, "current": current}


def _watch_worker(watch_id: str, metric: str, threshold: float, comparison: str, interval_seconds: float, samples: int) -> None:
    jobs = _read_json(JOBS_FILE, {}); jobs[watch_id] = {"type": "watch", "status": "running", "metric": metric, "results": []}; _write_json(JOBS_FILE, jobs)
    for _ in range(samples):
        snapshot = _snapshot_payload(); value = snapshot.get(metric); triggered = value is not None and (value >= threshold if comparison == "gte" else value <= threshold)
        jobs = _read_json(JOBS_FILE, {}); jobs[watch_id]["results"].append({"timestamp": time.time(), "value": value, "triggered": triggered}); _write_json(JOBS_FILE, jobs); time.sleep(interval_seconds)
    jobs = _read_json(JOBS_FILE, {}); jobs[watch_id]["status"] = "completed"; _write_json(JOBS_FILE, jobs)


@mcp.tool()
def watch_metric(metric: str, threshold: float, comparison: str = "gte", interval_seconds: float = 5.0, samples: int = 12) -> Dict[str, Any]:
    """Inicia monitor em background com disparo por threshold."""
    allowed = {"cpu_percent", "memory_percent", "swap_percent", "disk_percent", "process_count"}
    if metric not in allowed or comparison not in {"gte", "lte"} or samples < 1: raise ValueError("parâmetros inválidos")
    watch_id = str(uuid.uuid4()); threading.Thread(target=_watch_worker, args=(watch_id, metric, threshold, comparison, interval_seconds, samples), daemon=True).start()
    return {"watch_id": watch_id, "status": "started"}


@mcp.tool()
def get_action_log(limit: int = 100, action: str = "") -> Dict[str, Any]:
    """Consulta o registro append-only das ações."""
    path = Path(os.environ.get(AUDIT_LOG_ENV, str(DEFAULT_AUDIT_LOG))).expanduser(); records = []
    for line in _read_text(path).splitlines():
        try:
            record = json.loads(line)
            if not action or record.get("action") == action: records.append(record)
        except json.JSONDecodeError: continue
    return {"records": records[-limit:], "count": len(records)}


# Reversão

@mcp.tool()
def create_snapshot(name: str = "", dry_run: bool = True) -> Dict[str, Any]:
    """Cria snapshot com Timeshift, btrfs ou restic."""
    label = name or datetime.now().strftime("process-monitor-%Y%m%d-%H%M%S")
    if shutil.which("timeshift"): command = ["timeshift", "--create", "--comments", label]
    elif shutil.which("btrfs"): command = ["btrfs", "subvolume", "snapshot", "-r", "/", f"/.snapshots/{label}"]
    elif shutil.which("restic"): command = ["restic", "backup", "/", "--tag", label]
    else: command = ["false"]
    return _system_action("create_snapshot", {"name": label}, command, dry_run, 3600)


@mcp.tool()
def list_snapshots() -> Dict[str, Any]:
    """Lista snapshots disponíveis nos backends suportados."""
    return {"timeshift": _run_command(["timeshift", "--list"], 60), "btrfs": _run_command(["btrfs", "subvolume", "list", "/"], 60), "restic": _run_command(["restic", "snapshots", "--json"], 60)}


@mcp.tool()
def rollback_snapshot(snapshot: str, backend: str = "timeshift", dry_run: bool = True) -> Dict[str, Any]:
    """Restaura um snapshot existente."""
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]+", snapshot) or backend not in {"timeshift", "btrfs", "restic"}: raise ValueError("snapshot ou backend inválido")
    commands = {"timeshift": ["timeshift", "--restore", "--snapshot", snapshot, "--yes"], "btrfs": ["btrfs", "subvolume", "snapshot", snapshot, "/"], "restic": ["restic", "restore", snapshot, "--target", "/"]}
    return _system_action("rollback_snapshot", {"snapshot": snapshot, "backend": backend}, commands[backend], dry_run, 3600)


@mcp.tool()
def undo_last_action(dry_run: bool = True) -> Dict[str, Any]:
    """Desfaz a última ação reversível conhecida."""
    records = get_action_log(500)["records"]
    reversible = {"suspend_process": "resume_process", "start_service": "stop_service", "stop_service": "start_service", "enable_service": "disable_service", "disable_service": "enable_service"}
    record = next((item for item in reversed(records) if not item.get("dry_run") and item.get("success") and item.get("action") in reversible), None)
    if record is None: return {"success": False, "reason": "nenhuma ação reversível encontrada"}
    inverse = reversible[record["action"]]; target = record["target"]
    if "pid" in target: return globals()[inverse](target["pid"], dry_run=dry_run)
    return globals()[inverse](record["parameters"]["service"], dry_run=dry_run)


@mcp.tool()
def simulate_action(action: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Executa qualquer ação registrada em modo dry-run."""
    function = globals().get(action)
    if not callable(function) or "dry_run" not in function.__annotations__: return {"success": False, "reason": "ação desconhecida ou não simulável"}
    return function(**parameters, dry_run=True)


# Máquinas remotas

@mcp.tool()
def list_hosts() -> Dict[str, Any]:
    """Lista o inventário de máquinas remotas."""
    return {"hosts": _load_hosts()}


def _find_host(host_id: str) -> Dict[str, Any]:
    host = next((item for item in _load_hosts() if item["id"] == host_id), None)
    if host is None: raise ValueError("host não encontrado")
    return host


@mcp.tool()
def ping_host(host_id: str) -> Dict[str, Any]:
    """Mede latência, clock drift e versão do agente remoto."""
    host = _find_host(host_id); ping = _run_command(["ping", "-c", "2", "-W", "2", host["hostname"]], 10); remote = _ssh(host, "date +%s; uname -sr", 10)
    lines = remote["stdout"].splitlines(); remote_time = int(lines[0]) if lines and lines[0].isdigit() else None
    return {"host": host, "reachable": ping["success"], "ping": ping, "agent": lines[1] if len(lines) > 1 else None, "clock_drift_seconds": abs(time.time() - remote_time) if remote_time else None}


@mcp.tool()
def fleet_dashboard() -> Dict[str, Any]:
    """Retorna estado consolidado dos nós."""
    hosts = _load_hosts()
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as executor: rows = list(executor.map(lambda host: ping_host(host["id"]), hosts))
    return {"hosts": rows, "total": len(rows), "online": sum(row["reachable"] for row in rows)}


@mcp.tool()
def fleet_health_check() -> Dict[str, Any]:
    """Executa health check remoto em paralelo."""
    hosts = _load_hosts(); rows = []
    def check(host: Dict[str, Any]) -> Dict[str, Any]:
        result = _ssh(host, "python3 -c 'import psutil,json; print(json.dumps({\"cpu\":psutil.cpu_percent(interval=0.2),\"memory\":psutil.virtual_memory().percent,\"disk\":psutil.disk_usage(\"/\").percent}))'", 20)
        try: metrics = json.loads(result["stdout"])
        except json.JSONDecodeError: metrics = None
        return {"host": host, "success": result["success"], "metrics": metrics, "error": result["stderr"]}
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts)))) as executor: rows = list(executor.map(check, hosts))
    rows.sort(key=lambda row: max(row["metrics"].values()) if row["metrics"] else 101, reverse=True)
    return {"results": rows}


@mcp.tool()
def fleet_compare() -> Dict[str, Any]:
    """Compara kernel, distribuição e pacotes entre máquinas."""
    rows = []
    for host in _load_hosts(): rows.append({"host": host, "configuration": _ssh(host, "uname -r; . /etc/os-release && echo $ID:$VERSION_ID; nproc", 15)})
    return {"hosts": rows}


@mcp.tool()
def detect_config_drift() -> Dict[str, Any]:
    """Detecta divergências em relação à configuração majoritária."""
    comparison = fleet_compare()["hosts"]; signatures = Counter(row["configuration"]["stdout"] for row in comparison if row["configuration"]["success"]); baseline = signatures.most_common(1)[0][0] if signatures else ""
    return {"baseline": baseline, "drift": [row for row in comparison if row["configuration"]["stdout"] != baseline]}


@mcp.tool()
def find_common_issues() -> Dict[str, Any]:
    """Encontra problemas presentes em múltiplos nós."""
    health = fleet_health_check()["results"]; issues: Counter[str] = Counter()
    for row in health:
        if not row["success"]: issues["unreachable"] += 1
        for metric, value in (row["metrics"] or {}).items():
            if value >= 90: issues[f"{metric}_critical"] += 1
    return {"issues": [{"issue": issue, "hosts": count} for issue, count in issues.most_common() if count > 1]}


@mcp.tool()
def collect_logs(host_ids: List[str], hours: int = 24) -> Dict[str, Any]:
    """Agrega logs de vários nós em uma timeline única."""
    events = []
    for host_id in host_ids:
        host = _find_host(host_id); result = _ssh(host, f"journalctl --since {shlex.quote(str(hours) + ' hours ago')} -p err -o short-iso --no-pager", 60)
        events.extend({"host_id": host_id, "line": line} for line in result["stdout"].splitlines())
    return {"events": sorted(events, key=lambda row: row["line"])}


@mcp.tool()
def tag_host(host_id: str, tags: List[str], dry_run: bool = True) -> Dict[str, Any]:
    """Atualiza tags lógicas de um host."""
    host = _find_host(host_id)
    parameters = {"host_id": host_id, "new_tags": sorted(set(tags))}
    def operation() -> Dict[str, Any]:
        hosts = _load_hosts(); next(item for item in hosts if item["id"] == host_id)["tags"] = parameters["new_tags"]; _save_hosts(hosts)
        return {"host": host, "tags": parameters["new_tags"]}
    return _state_action("tag_host", parameters, dry_run, operation)


@mcp.tool()
def register_host(hostname: str, user: str = "", port: int = 22, enrollment_token: str = "", dry_run: bool = True) -> Dict[str, Any]:
    """Registra um host com token de enrollment de uso único."""
    record = {"id": str(uuid.uuid4()), "hostname": hostname, "user": user or os.environ.get("USER", ""), "port": port, "tags": [], "registered_at": time.time(), "token_fingerprint": hashlib.sha256(enrollment_token.encode()).hexdigest() if enrollment_token else None}
    def operation() -> Dict[str, Any]:
        hosts = _load_hosts()
        if any(item["hostname"] == hostname for item in hosts): raise ValueError("host já registrado")
        hosts.append(record); _save_hosts(hosts); return {"host": record}
    return _state_action("register_host", {"host": record}, dry_run, operation)


@mcp.tool()
def remove_host(host_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """Revoga e remove um host do inventário."""
    host = _find_host(host_id)
    def operation() -> Dict[str, Any]:
        _save_hosts([item for item in _load_hosts() if item["id"] != host_id]); return {"removed": host}
    return _state_action("remove_host", {"host_id": host_id}, dry_run, operation)


@mcp.tool()
def sync_config(host_ids: List[str], local_path: str, remote_path: str, dry_run: bool = True) -> Dict[str, Any]:
    """Propaga um arquivo de configuração para vários hosts."""
    source = Path(local_path).expanduser().resolve()
    if not source.is_file(): raise ValueError("arquivo local não encontrado")
    plans = []
    for host_id in host_ids:
        host = _find_host(host_id); target = f"{host['user']}@{host['hostname']}:{remote_path}"; command = ["scp", "-P", str(host.get("port", 22)), str(source), target]
        plans.append(_system_action("sync_config", {"host_id": host_id, "local_path": str(source), "remote_path": remote_path}, command, dry_run, 300))
    return {"results": plans}


@mcp.tool()
def update_agent(host_id: str, package: str = "process-monitor-mcp", dry_run: bool = True) -> Dict[str, Any]:
    """Atualiza o agente de um nó remoto."""
    host = _find_host(host_id); command = ["ssh", "-p", str(host.get("port", 22)), f"{host['user']}@{host['hostname']}", "python3", "-m", "pip", "install", "--upgrade", package]
    return _system_action("update_agent", {"host_id": host_id, "package": package}, command, dry_run, 600)


@mcp.tool()
def restart_agent(host_id: str, service: str = "process-monitor-mcp", dry_run: bool = True) -> Dict[str, Any]:
    """Reinicia o agente de um nó remoto."""
    host = _find_host(host_id); command = ["ssh", "-p", str(host.get("port", 22)), f"{host['user']}@{host['hostname']}", "systemctl", "restart", service]
    return _system_action("restart_agent", {"host_id": host_id, "service": service}, command, dry_run)


@mcp.tool()
def fleet_rollout(host_ids: List[str], command: List[str], wave_size: int = 2, abort_on_failure: bool = True, dry_run: bool = True) -> Dict[str, Any]:
    """Executa comando remoto em ondas com interrupção opcional."""
    if not command or wave_size < 1: raise ValueError("command e wave_size inválidos")
    results = []
    for offset in range(0, len(host_ids), wave_size):
        wave = host_ids[offset:offset + wave_size]
        for host_id in wave:
            host = _find_host(host_id); ssh_command = ["ssh", "-p", str(host.get("port", 22)), f"{host['user']}@{host['hostname']}", *command]
            result = _system_action("fleet_rollout", {"host_id": host_id, "command": command}, ssh_command, dry_run, 600); results.append(result)
            if abort_on_failure and not result["success"]: return {"results": results, "aborted": True}
    return {"results": results, "aborted": False}


# Realocação de carga

def _load_manifest_jobs() -> List[Dict[str, Any]]:
    try:
        data = yaml.safe_load(MANIFEST_FILE.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError):
        data = {}
    return data.get("jobs", []) if isinstance(data, dict) else []


@mcp.tool()
def classify_process(pid: int) -> Dict[str, Any]:
    """Classifica processo nas classes A, B ou C."""
    process = _get_process(pid); target = _action_target(process); command = " ".join(target["cmdline"]).lower()
    if any(marker in command for marker in ("docker", "podman", "containerd")): workload_class = "B"
    elif process.terminal() or any(marker in command for marker in ("firefox", "chrome", "code", "postgres", "mysql")): workload_class = "C"
    else: workload_class = "A"
    return {"process": target, "class": workload_class}


@mcp.tool()
def check_offloadable(pid: int) -> Dict[str, Any]:
    """Verifica elegibilidade e encontra definição de job."""
    classification = classify_process(pid); command = " ".join(classification["process"]["cmdline"])
    job = next((item for item in _load_manifest_jobs() if any(pattern in command for pattern in item.get("match", []))), None)
    eligible = classification["class"] in {"A", "B"} and bool(job and job.get("offloadable"))
    return {"offloadable": eligible, "reason": "job elegível" if eligible else "processo stateful/interativo ou sem manifesto", "job_definition": job, "classification": classification["class"]}


@mcp.tool()
def capture_process_context(pid: int) -> Dict[str, Any]:
    """Captura cmdline, cwd, ambiente filtrado, FDs e usuário."""
    process = _get_process(pid); safe_keys = {"PATH", "HOME", "USER", "LANG", "VIRTUAL_ENV", "CONDA_PREFIX"}
    with process.oneshot():
        environment = {key: value for key, value in process.environ().items() if key in safe_keys}
        return {"pid": pid, "cmdline": process.cmdline(), "cwd": process.cwd(), "environment": environment, "file_descriptors": process.num_fds(), "username": process.username(), "open_files": [item.path for item in process.open_files()]}


@mcp.tool()
def check_host_capability(host_id: str = "", requires: Optional[List[str]] = None) -> Dict[str, Any]:
    """Verifica RAM, CPU, dependências, GPU e bateria local ou remota."""
    requires = requires or []
    if host_id:
        host = _find_host(host_id); result = _ssh(host, "python3 -c 'import psutil,json,shutil; print(json.dumps({\"memory_available\":psutil.virtual_memory().available,\"cpu_idle\":100-psutil.cpu_percent(interval=.2)}))'", 20)
        try: metrics = json.loads(result["stdout"])
        except json.JSONDecodeError: metrics = {}
        dependencies = {item: _ssh(host, f"command -v {shlex.quote(item)}", 5)["success"] for item in requires}
    else:
        metrics = {"memory_available": psutil.virtual_memory().available, "cpu_idle": 100 - psutil.cpu_percent(interval=0.2)}; dependencies = {item: shutil.which(item) is not None for item in requires}
    return {"host_id": host_id or "local", **metrics, "dependencies": dependencies, "gpu": bool(list(Path("/dev/dri").glob("card*"))), "battery": psutil.sensors_battery()._asdict() if psutil.sensors_battery() else None, "capable": bool(metrics) and all(dependencies.values())}


@mcp.tool()
def select_best_host(requires: Optional[List[str]] = None) -> Dict[str, Any]:
    """Ordena destinos por recursos, dependências e latência."""
    rows = []
    for host in _load_hosts():
        capability = check_host_capability(host["id"], requires); reachability = ping_host(host["id"]); score = (capability.get("cpu_idle", 0) + capability.get("memory_available", 0) / 1024 ** 3 * 5) if capability["capable"] and reachability["reachable"] else -1
        rows.append({"host": host, "capability": capability, "reachability": reachability, "score": round(score, 2)})
    rows.sort(key=lambda row: row["score"], reverse=True)
    return {"hosts": rows, "best": rows[0] if rows and rows[0]["score"] >= 0 else None}


@mcp.tool()
def estimate_offload_benefit(pid: int, host_id: str, transfer_bytes: int = 0, bandwidth_mbps: float = 100.0) -> Dict[str, Any]:
    """Compara custo de transferência com alívio local esperado."""
    process = _get_process(pid); cpu = process.cpu_percent(interval=0.5); memory = process.memory_info().rss; transfer_seconds = transfer_bytes * 8 / max(1, bandwidth_mbps * 1000000); benefit = cpu + memory / 1024 ** 3 * 10 - transfer_seconds
    return {"pid": pid, "host_id": host_id, "cpu_percent_relieved": cpu, "memory_bytes_relieved": memory, "transfer_seconds": round(transfer_seconds, 2), "benefit_score": round(benefit, 2), "recommended": benefit > 10}


@mcp.tool()
def relieve_pressure() -> Dict[str, Any]:
    """Propõe plano combinando realocação, limites e suspensões."""
    hogs = find_resource_hogs("cpu", 10, 0.5)["processes"]; plan = []
    for process in hogs:
        eligibility = check_offloadable(process["pid"])
        plan.append({"pid": process["pid"], "action": "offload_process" if eligibility["offloadable"] else "limit_process_resources", "parameters": {"cpu_percent": 50, "dry_run": True} if not eligibility["offloadable"] else {"dry_run": True}})
    return {"plan": plan, "diagnosis": diagnose_slowness()["dominant_bottleneck"]}


@mcp.tool()
def stage_workload(pid: int, host_id: str, dry_run: bool = True) -> Dict[str, Any]:
    """Sincroniza entradas declaradas no manifesto para o destino."""
    eligibility = check_offloadable(pid)
    if not eligibility["offloadable"]: raise ValueError(eligibility["reason"])
    host = _find_host(host_id); context = capture_process_context(pid); job = eligibility["job_definition"]; files = [str(Path(context["cwd"]) / item) for item in job.get("sync", [])]; destination = f"{host['user']}@{host['hostname']}:{context['cwd']}"
    return _system_action("stage_workload", {"pid": pid, "host_id": host_id, "files": files}, ["rsync", "-az", "--", *files, destination], dry_run, 1800)


@mcp.tool()
def track_job(job_id: str) -> Dict[str, Any]:
    """Retorna status, progresso e logs de um job."""
    jobs = _read_json(JOBS_FILE, {}); job = jobs.get(job_id)
    if job is None: raise ValueError("job não encontrado")
    if job.get("host_id") and job.get("remote_pid"):
        host = _find_host(job["host_id"]); status = _ssh(host, f"ps -p {int(job['remote_pid'])} -o stat=", 10); job["status"] = "running" if status["stdout"] else "completed"; jobs[job_id] = job; _write_json(JOBS_FILE, jobs)
    return job


@mcp.tool()
def retrieve_artifacts(job_id: str, destination: str = ".", dry_run: bool = True) -> Dict[str, Any]:
    """Traz artefatos do job remoto para o host local."""
    job = track_job(job_id); host = _find_host(job["host_id"]); artifacts = job.get("artifacts", []); source = f"{host['user']}@{host['hostname']}:{job['workdir']}/"
    include_arguments = [argument for pattern in artifacts for argument in ("--include", pattern)]
    return _system_action("retrieve_artifacts", {"job_id": job_id, "artifacts": artifacts}, ["rsync", "-az", *include_arguments, "--exclude", "*", source, str(Path(destination).expanduser())], dry_run, 1800)


@mcp.tool()
def start_remote_job(host_id: str, command: List[str], workdir: str, artifacts: Optional[List[str]] = None, dry_run: bool = True) -> Dict[str, Any]:
    """Inicia job remoto sob systemd scope e registra seu PID."""
    if not command: raise ValueError("command não pode ser vazio")
    host = _find_host(host_id); job_id = str(uuid.uuid4()); remote = f"cd {shlex.quote(workdir)} && nohup systemd-run --user --scope {' '.join(shlex.quote(part) for part in command)} >/tmp/{job_id}.log 2>&1 & echo $!"
    ssh_command = ["ssh", "-p", str(host.get("port", 22)), f"{host['user']}@{host['hostname']}", remote]
    result = _system_action("start_remote_job", {"host_id": host_id, "command": command, "workdir": workdir}, ssh_command, dry_run, 120)
    if not dry_run:
        remote_pid = int(result["result"]["stdout"].splitlines()[-1]); jobs = _read_json(JOBS_FILE, {}); jobs[job_id] = {"job_id": job_id, "host_id": host_id, "remote_pid": remote_pid, "command": command, "workdir": workdir, "artifacts": artifacts or [], "status": "running", "started_at": time.time()}; _write_json(JOBS_FILE, jobs)
    return {"job_id": job_id, **result}


@mcp.tool()
def offload_process(pid: int, host_id: str = "", dry_run: bool = True) -> Dict[str, Any]:
    """Orquestra staging, início remoto e encerramento local após confirmação."""
    eligibility = check_offloadable(pid)
    if not eligibility["offloadable"]: raise ValueError(eligibility["reason"])
    if not host_id:
        selected = select_best_host(eligibility["job_definition"].get("requires", []))["best"]
        if selected is None: raise ValueError("nenhum host compatível")
        host_id = selected["host"]["id"]
    context = capture_process_context(pid); job = eligibility["job_definition"]; staged = stage_workload(pid, host_id, dry_run); started = start_remote_job(host_id, shlex.split(job["restart_command"]), context["cwd"], job.get("artifacts", []), dry_run)
    terminated = None
    if not dry_run:
        status = track_job(started["job_id"])
        if status["status"] != "running": raise RuntimeError("job remoto não confirmou inicialização")
        terminated = kill_process(pid, dry_run=False)
    return {"host_id": host_id, "staged": staged, "started": started, "local_termination": terminated, "dry_run": dry_run}


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor MCP para monitoramento de processos Linux")
    parser.parse_args()
    mcp.run()


if __name__ == "__main__":
    main()