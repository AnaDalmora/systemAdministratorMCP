import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
from mcp.server.mcpserver import MCPServer


mcp = MCPServer("linux-process-monitor")

@mcp.prompt()
def analisar_saude_linux(foco: str = "cpu") -> str:
    """Prompt estruturado para análise de sistema."""
    return f"Você é um engenheiro de confiabilidade (SRE) Sênior em Linux. Use suas ferramentas para investigar o consumo de {foco} no servidor atual e escreva um relatório apontando gargalos e sugerindo otimizações."

ACTION_ALLOWLIST_ENV = "PROCESS_MONITOR_ACTION_ALLOWLIST"
AUDIT_LOG_ENV = "PROCESS_MONITOR_AUDIT_LOG"
DEFAULT_AUDIT_LOG = Path.home() / ".local" / "state" / "process-monitor-mcp" / "actions.jsonl"
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor MCP para monitoramento de processos Linux")
    parser.parse_args()
    mcp.run()


if __name__ == "__main__":
    main()