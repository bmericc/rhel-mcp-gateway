"""RHEL yönetimi için amaca özel MCP araçları.

Her araç, sunucuda çalıştırılacak sabit komutları (argv listesi) kendisi kurar;
kullanıcıdan gelen değerler doğrulanır ve shell'e her zaman quote edilerek verilir.
Komutların nasıl çalıştırılacağı (Cockpit veya SSH) `Runner` ile soyutlanmıştır.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, NamedTuple

import mcp.types as types

from i18n import N, t


class CommandResult(NamedTuple):
    user: str
    exit_status: int | None
    stdout: str
    stderr: str
    via: str = "ssh"


# runner(argv, privileged=False, timeout=60) -> CommandResult
# privileged=True: SSH'ta root olmayan kullanıcıda `sudo -n`, Cockpit'te superuser ile çalıştırılır
Runner = Callable[..., Awaitable[CommandResult]]


class ToolInputError(ValueError):
    """Geçersiz araç parametresi (komut çalıştırılmadan reddedilir)."""


MAX_OUTPUT_CHARS = 20000
DEFAULT_TIMEOUT = 60
LONG_TIMEOUT = 900

# --- Doğrulama ---

_SERVICE_RE = re.compile(r"^[A-Za-z0-9@_:.\-]{1,128}$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+:\-]{0,127}$")
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?/(tcp|udp)$")
_FW_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,63}$")
_SINCE_RE = re.compile(r"^[A-Za-z0-9 :+\-]{1,40}$")
LOG_PRIORITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
SERVICE_ACTIONS = ["start", "stop", "restart", "reload", "enable", "disable"]


def _check(pattern: re.Pattern, value: Any, label: str) -> str:
    if not isinstance(value, str) or not pattern.match(value) or value.startswith("-"):
        raise ToolInputError(t("Invalid {label}: {value}", label=t(label), value=repr(value)))
    return value


def validate_service(value: Any) -> str:
    return _check(_SERVICE_RE, value, N("service name"))


def validate_package(value: Any) -> str:
    return _check(_PACKAGE_RE, value, N("package name"))


def validate_packages(values: Any) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ToolInputError(t("At least one package name is required."))
    return [validate_package(v) for v in values]


def validate_port(value: Any) -> str:
    _check(_PORT_RE, value, N("port (e.g. 8080/tcp)"))
    for part in value.split("/")[0].split("-"):
        if not 1 <= int(part) <= 65535:
            raise ToolInputError(t("Invalid port: {value}", value=repr(value)))
    return value


def validate_since(value: Any) -> str:
    return _check(_SINCE_RE, value, N("time expression"))


def clamp_int(value: Any, default: int, low: int, high: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolInputError(t("Expected a number: {value}", value=repr(value)))
    return max(low, min(high, value))


# --- Çıktı yardımcıları ---

def truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n" + t("... [output truncated, {total} characters total]", total=len(text))


def result_dict(r: CommandResult) -> dict:
    return {
        "user": r.user,
        "via": r.via,
        "exit_status": r.exit_status,
        "stdout": truncate(r.stdout),
        "stderr": truncate(r.stderr),
    }


def parse_os_release(text: str) -> dict:
    data = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            data[key.strip()] = value.strip().strip('"')
    return data


def parse_free_bytes(text: str) -> dict:
    """`free -b` çıktısından bellek ve swap kullanımı."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].rstrip(":").lower()
        if name in ("mem", "swap") and len(parts) >= 3:
            total, used = int(parts[1]), int(parts[2])
            entry = {"total_bytes": total, "used_bytes": used}
            if name == "mem" and len(parts) >= 7:
                entry["available_bytes"] = int(parts[6])
            entry["used_percent"] = round(used * 100 / total, 1) if total else 0.0
            out["memory" if name == "mem" else "swap"] = entry
    return out


def parse_df(text: str) -> list[dict]:
    """`df -PT -B1` çıktısı: Filesystem Type Size Used Avail Use% Mount."""
    disks = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        disks.append({
            "filesystem": parts[0],
            "type": parts[1],
            "size_bytes": int(parts[2]),
            "used_bytes": int(parts[3]),
            "available_bytes": int(parts[4]),
            "used_percent": int(parts[5].rstrip("%") or 0),
            "mount": parts[6],
        })
    return disks


def parse_loadavg(text: str) -> dict:
    parts = text.split()
    if len(parts) < 3:
        return {}
    return {"load_1m": float(parts[0]), "load_5m": float(parts[1]), "load_15m": float(parts[2])}


def parse_failed_units(text: str) -> list[dict]:
    """`systemctl --failed --plain --no-legend` çıktısı: UNIT LOAD ACTIVE SUB DESCRIPTION."""
    units = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            units.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })
    return units


def parse_ps(text: str, limit: int) -> list[dict]:
    """`ps -eo pid,user,pcpu,pmem,rss,args --no-headers` çıktısı."""
    procs = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        procs.append({
            "pid": int(parts[0]),
            "user": parts[1],
            "cpu_percent": float(parts[2]),
            "mem_percent": float(parts[3]),
            "rss_kb": int(parts[4]),
            "command": parts[5],
        })
        if len(procs) >= limit:
            break
    return procs


def parse_dnf_list(text: str) -> list[dict]:
    """`dnf check-update` / `dnf updateinfo list` satırlarını ayrıştırır."""
    # check-update:        "openssl.x86_64  1:3.0.7-27.el9  rhel-9-baseos"
    # updateinfo --security: "RHSA-2024:1234  Important/Sec.  openssl-1:3.0.7-27.el9.x86_64"
    items = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or line.startswith(("Last metadata", "Obsoleting")):
            continue
        if "/" in parts[1] or parts[1].lower() in ("bugfix", "enhancement", "security", "newpackage"):
            items.append({"advisory": parts[0], "type": parts[1], "package": parts[2]})
        else:
            items.append({"package": parts[0], "version": parts[1], "repo": parts[2]})
    return items


# --- Araç tanımları ---

Handler = Callable[[Runner, dict], Awaitable[Any]]


@dataclass
class ToolSpec:
    name: str
    description: str
    properties: dict
    handler: Handler
    required: list[str] = field(default_factory=list)
    read_only: bool = True
    # Değiştiren araçlar `confirm: true` olmadan çalışmaz; sadece ne yapılacağını söyler
    preview: Callable[[dict], str] | None = None

    def to_tool(self) -> types.Tool:
        # Descriptions are translated per request (see i18n), not at import time
        properties = {"server_name": {"type": "string", "description": t("Registered server name")}}
        properties.update({
            name: {**prop, "description": t(prop["description"])} if "description" in prop else prop
            for name, prop in self.properties.items()
        })
        required = ["server_name", *self.required]
        if not self.read_only:
            properties["confirm"] = {
                "type": "boolean",
                "description": t("Set to true to actually apply the change. Otherwise only what would be done is shown."),
            }
        return types.Tool(
            name=self.name,
            description=t(self.description),
            inputSchema={"type": "object", "properties": properties, "required": required},
            annotations=types.ToolAnnotations(
                readOnlyHint=self.read_only,
                destructiveHint=not self.read_only,
                openWorldHint=False,
            ),
        )


async def server_info(run: Runner, args: dict) -> dict:
    os_release = await run(["cat", "/etc/os-release"])
    kernel = await run(["uname", "-r"])
    host = await run(["hostname", "-f"])
    uptime = await run(["uptime", "-p"])
    since = await run(["uptime", "-s"])
    return {
        "user": os_release.user,
        "hostname": host.stdout.strip(),
        "os": parse_os_release(os_release.stdout).get("PRETTY_NAME", ""),
        "os_release": parse_os_release(os_release.stdout),
        "kernel": kernel.stdout.strip(),
        "uptime": uptime.stdout.strip(),
        "up_since": since.stdout.strip(),
    }


async def resource_usage(run: Runner, args: dict) -> dict:
    mem = await run(["free", "-b"])
    disks = await run(["df", "-PT", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"])
    load = await run(["cat", "/proc/loadavg"])
    cpus = await run(["nproc"])
    out = parse_free_bytes(mem.stdout)
    out["load"] = parse_loadavg(load.stdout)
    out["cpu_count"] = int(cpus.stdout.strip() or 0)
    out["disks"] = parse_df(disks.stdout)
    return out


async def service_status(run: Runner, args: dict) -> dict:
    service = validate_service(args.get("service"))
    active = await run(["systemctl", "is-active", service])
    enabled = await run(["systemctl", "is-enabled", service])
    status = await run(["systemctl", "status", service, "--no-pager", "-l", "-n", "20"], privileged=True)
    return {
        "service": service,
        "active": active.stdout.strip(),
        "enabled": enabled.stdout.strip(),
        "status": truncate(status.stdout or status.stderr),
    }


async def failed_services(run: Runner, args: dict) -> dict:
    r = await run(["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"])
    units = parse_failed_units(r.stdout)
    return {"count": len(units), "units": units}


async def read_logs(run: Runner, args: dict) -> dict:
    lines = clamp_int(args.get("lines"), 100, 1, 1000)
    argv = ["journalctl", "--no-pager", "-o", "short-iso", "-n", str(lines)]
    if args.get("unit"):
        argv += ["-u", validate_service(args["unit"])]
    if args.get("since"):
        argv += ["--since", validate_since(args["since"])]
    if args.get("priority"):
        if args["priority"] not in LOG_PRIORITIES:
            raise ToolInputError(t("Invalid priority: {value}", value=repr(args["priority"])))
        argv += ["-p", args["priority"]]
    if args.get("grep"):
        if not isinstance(args["grep"], str) or len(args["grep"]) > 200:
            raise ToolInputError(t("The grep expression may be at most 200 characters."))
        argv += ["-g", args["grep"]]
    return result_dict(await run(argv, privileged=True))


async def top_processes(run: Runner, args: dict) -> dict:
    sort_by = args.get("sort_by", "cpu")
    if sort_by not in ("cpu", "mem"):
        raise ToolInputError(t("Invalid sort order: {value}", value=repr(sort_by)))
    limit = clamp_int(args.get("limit"), 10, 1, 50)
    key = "-pcpu" if sort_by == "cpu" else "-pmem"
    r = await run(["ps", "-eo", "pid,user,pcpu,pmem,rss,args", f"--sort={key}", "--no-headers"])
    return {"sort_by": sort_by, "processes": parse_ps(r.stdout, limit)}


async def network_info(run: Runner, args: dict) -> dict:
    addrs = await run(["ip", "-br", "addr"])
    routes = await run(["ip", "route"])
    listening = await run(["ss", "-tulpnH"], privileged=True)
    return {
        "addresses": addrs.stdout.strip().splitlines(),
        "routes": routes.stdout.strip().splitlines(),
        "listening": truncate(listening.stdout),
    }


async def firewall_status(run: Runner, args: dict) -> dict:
    state = await run(["firewall-cmd", "--state"], privileged=True)
    rules = await run(["firewall-cmd", "--list-all"], privileged=True)
    return {
        "state": (state.stdout or state.stderr).strip(),
        "rules": truncate(rules.stdout or rules.stderr),
    }


async def selinux_status(run: Runner, args: dict) -> dict:
    mode = await run(["getenforce"])
    denials = await run(["ausearch", "-m", "AVC,USER_AVC", "-ts", "recent", "-i"], privileged=True)
    text = denials.stdout if denials.exit_status == 0 else ""
    return {
        "mode": mode.stdout.strip(),
        "recent_denials": truncate(text) or t("No SELinux denials in the last 10 minutes."),
    }


async def available_updates(run: Runner, args: dict) -> dict:
    security_only = bool(args.get("security_only"))
    if security_only:
        r = await run(["dnf", "-q", "updateinfo", "list", "--security"], privileged=True, timeout=LONG_TIMEOUT)
    else:
        r = await run(["dnf", "-q", "check-update"], privileged=True, timeout=LONG_TIMEOUT)
    # check-update: 0 = güncelleme yok, 100 = güncelleme var, diğerleri hata
    if r.exit_status not in (0, 100):
        return {"error": truncate(r.stderr or r.stdout), "exit_status": r.exit_status}
    updates = parse_dnf_list(r.stdout)
    return {"security_only": security_only, "count": len(updates), "updates": updates}


async def package_info(run: Runner, args: dict) -> dict:
    name = validate_package(args.get("name"))
    installed = await run(["rpm", "-q", name])
    info = await run(["dnf", "-q", "info", name], timeout=LONG_TIMEOUT)
    return {
        "name": name,
        "installed": installed.exit_status == 0,
        "installed_version": installed.stdout.strip() if installed.exit_status == 0 else None,
        "info": truncate(info.stdout or info.stderr),
    }


# --- Değiştiren araçlar ---

async def service_action(run: Runner, args: dict) -> dict:
    service = validate_service(args.get("service"))
    action = args.get("action")
    if action not in SERVICE_ACTIONS:
        raise ToolInputError(t("Invalid action: {value}", value=repr(action)))
    r = await run(["systemctl", action, service], privileged=True)
    active = await run(["systemctl", "is-active", service])
    out = result_dict(r)
    out["active_after"] = active.stdout.strip()
    return out


async def install_updates(run: Runner, args: dict) -> dict:
    argv = ["dnf", "-y", "upgrade"]
    if args.get("security_only"):
        argv.append("--security")
    return result_dict(await run(argv, privileged=True, timeout=LONG_TIMEOUT))


async def package_install(run: Runner, args: dict) -> dict:
    names = validate_packages(args.get("names"))
    return result_dict(await run(["dnf", "-y", "install", *names], privileged=True, timeout=LONG_TIMEOUT))


async def package_remove(run: Runner, args: dict) -> dict:
    names = validate_packages(args.get("names"))
    return result_dict(await run(["dnf", "-y", "remove", *names], privileged=True, timeout=LONG_TIMEOUT))


def _firewall_target(args: dict) -> str:
    port, service = args.get("port"), args.get("service")
    if bool(port) == bool(service):
        raise ToolInputError(t("Exactly one of the port or service parameters must be given."))
    if args.get("action") not in ("add", "remove"):
        raise ToolInputError(t("Invalid action: {value}", value=repr(args.get("action"))))
    if port:
        return f"--{args['action']}-port={validate_port(port)}"
    return f"--{args['action']}-service={_check(_FW_SERVICE_RE, service, N('firewalld service name'))}"


async def firewall_rule(run: Runner, args: dict) -> dict:
    target = _firewall_target(args)
    change = await run(["firewall-cmd", "--permanent", target], privileged=True)
    if change.exit_status != 0:
        return result_dict(change)
    reload = await run(["firewall-cmd", "--reload"], privileged=True)
    out = result_dict(change)
    out["reload"] = result_dict(reload)
    return out


async def reboot_server(run: Runner, args: dict) -> dict:
    r = await run(["systemctl", "reboot"], privileged=True)
    out = result_dict(r)
    out["note"] = t("Reboot command sent; the connection is expected to drop.")
    return out


def _names(args: dict) -> str:
    names = args.get("names")
    return ", ".join(names) if isinstance(names, list) else str(names)


TOOLS: list[ToolSpec] = [
    ToolSpec(
        "server_info",
        "Returns the server's hostname, operating system version, kernel and uptime.",
        {}, server_info,
    ),
    ToolSpec(
        "resource_usage",
        "Returns memory, swap, system load, CPU count and disk usage.",
        {}, resource_usage,
    ),
    ToolSpec(
        "service_status",
        "Returns the active/enabled state of a systemd service and its latest log lines.",
        {"service": {"type": "string", "description": "Service name (e.g. nginx, httpd.service)"}},
        service_status, required=["service"],
    ),
    ToolSpec(
        "failed_services",
        "Lists failed systemd units.",
        {}, failed_services,
    ),
    ToolSpec(
        "read_logs",
        "Reads filtered logs with journalctl.",
        {
            "unit": {"type": "string", "description": "Only logs of this service"},
            "since": {"type": "string", "description": "Start time (e.g. '1 hour ago', 'today', '2026-10-06 10:00')"},
            "priority": {"type": "string", "enum": LOG_PRIORITIES, "description": "This priority and more severe ones"},
            "grep": {"type": "string", "description": "Expression to search for in the message (regex)"},
            "lines": {"type": "integer", "description": "Maximum number of lines (default 100, max 1000)"},
        },
        read_logs,
    ),
    ToolSpec(
        "top_processes",
        "Lists the processes using the most CPU or memory.",
        {
            "sort_by": {"type": "string", "enum": ["cpu", "mem"], "description": "Sort criterion (default cpu)"},
            "limit": {"type": "integer", "description": "Number of processes (default 10, max 50)"},
        },
        top_processes,
    ),
    ToolSpec(
        "network_info",
        "Returns IP addresses, the routing table and listening ports.",
        {}, network_info,
    ),
    ToolSpec(
        "firewall_status",
        "Returns the firewalld state and active rules.",
        {}, firewall_status,
    ),
    ToolSpec(
        "selinux_status",
        "Returns the SELinux mode and recent SELinux (AVC) denials.",
        {}, selinux_status,
    ),
    ToolSpec(
        "available_updates",
        "Lists pending package updates.",
        {"security_only": {"type": "boolean", "description": "Security updates only"}},
        available_updates,
    ),
    ToolSpec(
        "package_info",
        "Returns whether a package is installed, its version and its dnf info.",
        {"name": {"type": "string", "description": "Package name"}},
        package_info, required=["name"],
    ),
    ToolSpec(
        "service_action",
        "Starts, stops, restarts, reloads, enables or disables a systemd service.",
        {
            "service": {"type": "string", "description": "Service name"},
            "action": {"type": "string", "enum": SERVICE_ACTIONS},
        },
        service_action, required=["service", "action"], read_only=False,
        preview=lambda a: f"systemctl {a.get('action')} {a.get('service')}",
    ),
    ToolSpec(
        "install_updates",
        "Installs package updates with dnf.",
        {"security_only": {"type": "boolean", "description": "Security updates only"}},
        install_updates, read_only=False,
        preview=lambda a: "dnf -y upgrade" + (" --security" if a.get("security_only") else ""),
    ),
    ToolSpec(
        "package_install",
        "Installs packages with dnf.",
        {"names": {"type": "array", "items": {"type": "string"}, "description": "Package names"}},
        package_install, required=["names"], read_only=False,
        preview=lambda a: f"dnf -y install {_names(a)}",
    ),
    ToolSpec(
        "package_remove",
        "Removes packages with dnf.",
        {"names": {"type": "array", "items": {"type": "string"}, "description": "Package names"}},
        package_remove, required=["names"], read_only=False,
        preview=lambda a: f"dnf -y remove {_names(a)}",
    ),
    ToolSpec(
        "firewall_rule",
        "Adds/removes a permanent firewalld port or service rule and reloads.",
        {
            "action": {"type": "string", "enum": ["add", "remove"]},
            "port": {"type": "string", "description": "Port/protocol (e.g. 8080/tcp, 3000-3010/udp)"},
            "service": {"type": "string", "description": "firewalld service name (e.g. http, https)"},
        },
        firewall_rule, required=["action"], read_only=False,
        preview=lambda a: f"firewall-cmd --permanent {_firewall_target(a)} && firewall-cmd --reload",
    ),
    ToolSpec(
        "reboot_server",
        "Reboots the server.",
        {}, reboot_server, read_only=False,
        preview=lambda a: "systemctl reboot",
    ),
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}


async def fleet_health_for(run: Runner) -> dict:
    """fleet_health için tek sunucunun özeti."""
    load = await run(["cat", "/proc/loadavg"])
    failed = await run(["systemctl", "--failed", "--plain", "--no-legend", "--no-pager"])
    root_disk = await run(["df", "-PT", "-B1", "/"])
    disks = parse_df(root_disk.stdout)
    failed_units = [u["unit"] for u in parse_failed_units(failed.stdout)]
    return {
        "user": load.user,
        "load": parse_loadavg(load.stdout),
        "failed_services": failed_units,
        "root_disk_used_percent": disks[0]["used_percent"] if disks else None,
    }


def to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False)
