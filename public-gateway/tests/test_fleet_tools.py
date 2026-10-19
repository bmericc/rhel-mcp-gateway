"""Amaca özel MCP araçları: ayrıştırıcılar, doğrulama, komut kurulumu ve onay akışı."""
import asyncio
import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import fleet_tools
import main

# --- Ayrıştırıcılar ---

FREE_B = """\
               total        used        free      shared  buff/cache   available
Mem:      8000000000  2000000000  1000000000    10000000  5000000000  6000000000
Swap:     2000000000           0  2000000000
"""

DF = """\
Filesystem            Type 1-blocks       Used  Available Capacity Mounted on
/dev/mapper/rhel-root xfs  1000000000 820000000 180000000      82% /
/dev/sda1             xfs  1000000000 300000000 700000000      30% /boot
"""

FAILED = """\
nginx.service      loaded failed failed The nginx HTTP and reverse proxy server
kdump.service      loaded failed failed Crash recovery kernel arming
"""

PS = """\
 1234 nginx     45.5  2.1  20480 nginx: worker process
    1 root       0.1  0.2   9000 /usr/lib/systemd/systemd --switched-root
"""

CHECK_UPDATE = """\
Last metadata expiration check: 0:10:00 ago on Tue 06 Oct 2026.

openssl.x86_64                1:3.0.7-27.el9          rhel-9-baseos-rpms
kernel.x86_64                 5.14.0-427.el9          rhel-9-baseos-rpms
"""

UPDATEINFO = """\
RHSA-2026:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64
RHSA-2026:1300 Moderate/Sec.  curl-7.76.1-29.el9.x86_64
"""

UBUNTU_OS_RELEASE = """\
NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
"""

APT_UPGRADABLE = """\
Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
curl/noble-updates 8.5.0-2ubuntu10.5 amd64 [upgradable from: 8.5.0-2ubuntu10.4]
"""


def test_parse_free_bytes():
    out = fleet_tools.parse_free_bytes(FREE_B)
    assert out["memory"] == {
        "total_bytes": 8000000000,
        "used_bytes": 2000000000,
        "available_bytes": 6000000000,
        "used_percent": 25.0,
    }
    assert out["swap"]["used_percent"] == 0.0


def test_parse_df():
    disks = fleet_tools.parse_df(DF)
    assert [d["mount"] for d in disks] == ["/", "/boot"]
    assert disks[0]["used_percent"] == 82
    assert disks[0]["filesystem"] == "/dev/mapper/rhel-root"


def test_parse_failed_units():
    units = fleet_tools.parse_failed_units(FAILED)
    assert [u["unit"] for u in units] == ["nginx.service", "kdump.service"]
    assert units[0]["description"] == "The nginx HTTP and reverse proxy server"


def test_parse_ps_respects_limit():
    procs = fleet_tools.parse_ps(PS, limit=1)
    assert procs == [{
        "pid": 1234, "user": "nginx", "cpu_percent": 45.5, "mem_percent": 2.1,
        "rss_kb": 20480, "command": "nginx: worker process",
    }]


def test_parse_dnf_check_update():
    items = fleet_tools.parse_dnf_list(CHECK_UPDATE)
    assert items == [
        {"package": "openssl.x86_64", "version": "1:3.0.7-27.el9", "repo": "rhel-9-baseos-rpms"},
        {"package": "kernel.x86_64", "version": "5.14.0-427.el9", "repo": "rhel-9-baseos-rpms"},
    ]


def test_parse_apt_upgradable():
    items = fleet_tools.parse_apt_upgradable(APT_UPGRADABLE)
    assert [i["package"] for i in items] == ["openssl", "curl"]
    assert items[0]["version"] == "3.0.13-0ubuntu3.4"
    assert items[0]["current_version"] == "3.0.13-0ubuntu3.1"
    assert items[0]["security"] is True
    assert items[1]["security"] is False


def test_parse_dnf_updateinfo():
    items = fleet_tools.parse_dnf_list(UPDATEINFO)
    assert items[0] == {"advisory": "RHSA-2026:1234", "type": "Important/Sec.", "package": "openssl-1:3.0.7-27.el9.x86_64"}
    assert len(items) == 2


def test_parse_os_release_and_loadavg():
    assert fleet_tools.parse_os_release('NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.4"\n') == {
        "NAME": "Red Hat Enterprise Linux", "VERSION_ID": "9.4",
    }
    assert fleet_tools.parse_loadavg("0.50 0.40 0.30 1/200 999") == {"load_1m": 0.5, "load_5m": 0.4, "load_15m": 0.3}


def test_truncate():
    assert fleet_tools.truncate("abc", 5) == "abc"
    assert fleet_tools.truncate("a" * 10, 5).startswith("aaaaa\n... [output truncated")


# --- Doğrulama ---

@pytest.mark.parametrize("value", ["nginx; rm -rf /", "-x", "a b", "$(reboot)", "", None, "x" * 200])
def test_validate_service_rejects(value):
    with pytest.raises(fleet_tools.ToolInputError):
        fleet_tools.validate_service(value)


@pytest.mark.parametrize("value", ["nginx", "httpd.service", "getty@tty1.service", "systemd-journald"])
def test_validate_service_accepts(value):
    assert fleet_tools.validate_service(value) == value


@pytest.mark.parametrize("value", ["70000/tcp", "80", "80/icmp", "0/tcp", "1-99999/udp"])
def test_validate_port_rejects(value):
    with pytest.raises(fleet_tools.ToolInputError):
        fleet_tools.validate_port(value)


@pytest.mark.parametrize("value", [[], "nginx", ["ok", "bad name"], ["../etc"]])
def test_validate_packages_rejects(value):
    with pytest.raises(fleet_tools.ToolInputError):
        fleet_tools.validate_packages(value)


def test_clamp_int():
    assert fleet_tools.clamp_int(None, 10, 1, 50) == 10
    assert fleet_tools.clamp_int(500, 10, 1, 50) == 50
    with pytest.raises(fleet_tools.ToolInputError):
        fleet_tools.clamp_int("5", 10, 1, 50)


# --- MCP üzerinden uçtan uca (sahte SSH) ---

pytestmark_anyio = pytest.mark.anyio


class Result:
    def __init__(self, exit_status=0, stdout="", stderr=""):
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr


class ScriptedConn:
    """Komut metnine göre yanıt veren sahte SSH bağlantısı."""

    def __init__(self, script, commands, delay=0):
        self.script = script
        self.commands = commands
        self.delay = delay

    async def run(self, command, check=False):
        self.commands.append(command)
        if self.delay:
            await asyncio.sleep(self.delay)
        for needle, result in self.script:
            if needle in command:
                return result
        return Result(0, "", "")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def ssh(monkeypatch, servers_file):
    state = {"script": [], "commands": [], "connects": [], "delay": 0, "unreachable": set()}

    def connect(host, **kwargs):
        state["connects"].append((host, kwargs["username"]))
        if host in state["unreachable"]:
            raise OSError("No route to host")
        return ScriptedConn(state["script"], state["commands"], state["delay"])

    monkeypatch.setattr(main.asyncssh, "connect", connect)
    servers_file({
        "root-box": {"name": "root-box", "host": "10.0.0.1", "user": "root", "ssh_key_path": "/k"},
        "user-box": {"name": "user-box", "host": "10.0.0.2", "user": "bmericc", "ssh_key_path": "/k"},
    })
    return state


async def call(name, arguments):
    async with create_connected_server_and_client_session(main.mcp_server) as client:
        return await client.call_tool(name, arguments)


def payload(result):
    return json.loads(result.content[0].text)


@pytestmark_anyio
async def test_service_status_command_and_sudo(ssh):
    ssh["script"] = [("is-active", Result(0, "active\n")), ("is-enabled", Result(0, "enabled\n"))]
    result = await call("service_status", {"server_name": "user-box", "service": "nginx"})
    data = payload(result)
    assert data["active"] == "active"
    assert data["enabled"] == "enabled"
    # bmericc için yetki gerektiren komut sudo -n ile, gerektirmeyen sudo'suz çalışır
    assert "env LC_ALL=C systemctl is-active nginx" in ssh["commands"]
    assert "sudo -n env LC_ALL=C systemctl status nginx --no-pager -l -n 20" in ssh["commands"]


@pytestmark_anyio
async def test_root_never_uses_sudo(ssh):
    await call("service_status", {"server_name": "root-box", "service": "nginx"})
    assert not any(c.startswith("sudo") for c in ssh["commands"])


@pytestmark_anyio
async def test_resource_usage(ssh):
    ssh["script"] = [
        ("free -b", Result(0, FREE_B)),
        ("df -PT", Result(0, DF)),
        ("/proc/loadavg", Result(0, "1.00 0.50 0.25 1/100 42\n")),
        ("nproc", Result(0, "4\n")),
    ]
    data = payload(await call("resource_usage", {"server_name": "root-box"}))
    assert data["memory"]["used_percent"] == 25.0
    assert data["cpu_count"] == 4
    assert data["load"]["load_1m"] == 1.0
    assert data["disks"][0]["used_percent"] == 82


@pytestmark_anyio
async def test_read_logs_builds_quoted_command(ssh):
    await call("read_logs", {
        "server_name": "root-box", "unit": "nginx", "since": "1 hour ago",
        "priority": "err", "grep": "it's broken", "lines": 5000,
    })
    assert ssh["commands"] == [
        "env LC_ALL=C journalctl --no-pager -o short-iso -n 1000 -u nginx "
        "--since '1 hour ago' -p err -g 'it'\"'\"'s broken'"
    ]


@pytestmark_anyio
async def test_invalid_input_is_error_and_runs_nothing(ssh):
    result = await call("service_status", {"server_name": "root-box", "service": "nginx; reboot"})
    assert result.isError
    assert "Invalid service name" in result.content[0].text
    assert ssh["commands"] == []


@pytestmark_anyio
async def test_schema_enum_is_enforced(ssh):
    result = await call("top_processes", {"server_name": "root-box", "sort_by": "disk"})
    assert result.isError
    assert ssh["commands"] == []


@pytestmark_anyio
async def test_failed_services(ssh):
    ssh["script"] = [("--failed", Result(0, FAILED))]
    data = payload(await call("failed_services", {"server_name": "root-box"}))
    assert data["count"] == 2


@pytestmark_anyio
async def test_available_updates_exit_100_means_updates(ssh):
    ssh["script"] = [("check-update", Result(100, CHECK_UPDATE))]
    data = payload(await call("available_updates", {"server_name": "root-box"}))
    assert data["count"] == 2


@pytestmark_anyio
async def test_available_updates_error(ssh):
    ssh["script"] = [("check-update", Result(1, "", "Error: Failed to download metadata"))]
    data = payload(await call("available_updates", {"server_name": "root-box"}))
    assert "Failed to download metadata" in data["error"]


@pytestmark_anyio
async def test_available_updates_apt(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE)), ("--upgradable", Result(0, APT_UPGRADABLE))]
    data = payload(await call("available_updates", {"server_name": "user-box"}))
    assert data["package_manager"] == "apt"
    assert data["count"] == 2
    assert "sudo -n env LC_ALL=C apt-get update -q" in ssh["commands"]
    assert not any("dnf" in c for c in ssh["commands"])


@pytestmark_anyio
async def test_available_updates_apt_security_only(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE)), ("--upgradable", Result(0, APT_UPGRADABLE))]
    data = payload(await call("available_updates", {"server_name": "root-box", "security_only": True}))
    assert [u["package"] for u in data["updates"]] == ["openssl"]


@pytestmark_anyio
async def test_available_updates_apt_update_error(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE)), ("apt-get update", Result(100, "", "E: Could not get lock"))]
    data = payload(await call("available_updates", {"server_name": "root-box"}))
    assert "Could not get lock" in data["error"]


@pytestmark_anyio
async def test_install_updates_apt(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE)), ("--upgradable", Result(0, APT_UPGRADABLE))]
    data = payload(await call("install_updates", {"server_name": "root-box", "confirm": True}))
    assert data["package_manager"] == "apt"
    assert ssh["commands"][-1] == (
        "env LC_ALL=C env DEBIAN_FRONTEND=noninteractive apt-get -y "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade --with-new-pkgs"
    )


@pytestmark_anyio
async def test_install_updates_apt_security_only(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE)), ("--upgradable", Result(0, APT_UPGRADABLE))]
    await call("install_updates", {"server_name": "root-box", "security_only": True, "confirm": True})
    assert ssh["commands"][-1].endswith("install --only-upgrade openssl")


@pytestmark_anyio
async def test_install_updates_dnf(ssh):
    await call("install_updates", {"server_name": "root-box", "security_only": True, "confirm": True})
    assert ssh["commands"][-1] == "env LC_ALL=C dnf -y upgrade --security"


@pytestmark_anyio
async def test_destructive_tool_without_confirm_only_previews(ssh):
    result = await call("service_action", {"server_name": "root-box", "service": "nginx", "action": "restart"})
    text = result.content[0].text
    assert "Confirmation required" in text
    assert "systemctl restart nginx" in text
    assert ssh["connects"] == []


@pytestmark_anyio
async def test_destructive_preview_validates_input(ssh):
    result = await call("firewall_rule", {"server_name": "root-box", "action": "add", "port": "99999/tcp"})
    assert result.isError
    assert ssh["connects"] == []


@pytestmark_anyio
async def test_service_action_with_confirm(ssh):
    ssh["script"] = [("is-active", Result(0, "active\n"))]
    data = payload(await call("service_action", {
        "server_name": "user-box", "service": "nginx", "action": "restart", "confirm": True,
    }))
    assert "sudo -n env LC_ALL=C systemctl restart nginx" in ssh["commands"]
    assert data["active_after"] == "active"
    assert data["user"] == "bmericc"


@pytestmark_anyio
async def test_package_install_with_confirm(ssh):
    data = payload(await call("package_install", {"server_name": "root-box", "names": ["htop", "tmux"], "confirm": True}))
    assert ssh["commands"][-1] == "env LC_ALL=C dnf -y install htop tmux"
    assert data["package_manager"] == "dnf"


@pytestmark_anyio
async def test_package_install_apt(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE))]
    data = payload(await call("package_install", {"server_name": "user-box", "names": ["htop"], "confirm": True}))
    assert data["package_manager"] == "apt"
    assert ssh["commands"][-1] == (
        "sudo -n env LC_ALL=C env DEBIAN_FRONTEND=noninteractive apt-get -y "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install htop"
    )


@pytestmark_anyio
async def test_package_remove_apt(ssh):
    ssh["script"] = [("os-release", Result(0, UBUNTU_OS_RELEASE))]
    data = payload(await call("package_remove", {"server_name": "root-box", "names": ["htop", "tmux"], "confirm": True}))
    assert data["package_manager"] == "apt"
    assert ssh["commands"][-1].endswith("apt-get -y -o Dpkg::Options::=--force-confdef "
                                        "-o Dpkg::Options::=--force-confold remove htop tmux")
    assert not any("dnf" in c for c in ssh["commands"])


@pytestmark_anyio
async def test_package_remove_dnf(ssh):
    await call("package_remove", {"server_name": "root-box", "names": ["htop"], "confirm": True})
    assert ssh["commands"][-1] == "env LC_ALL=C dnf -y remove htop"


@pytestmark_anyio
async def test_package_info_dnf(ssh):
    ssh["script"] = [("rpm -q", Result(0, "openssl-3.0.7-27.el9.x86_64\n")), ("dnf -q info", Result(0, "Name : openssl\n"))]
    data = payload(await call("package_info", {"server_name": "root-box", "name": "openssl"}))
    assert data["package_manager"] == "dnf"
    assert data["installed"] is True
    assert data["installed_version"] == "openssl-3.0.7-27.el9.x86_64"


@pytestmark_anyio
async def test_package_info_apt(ssh):
    ssh["script"] = [
        ("os-release", Result(0, UBUNTU_OS_RELEASE)),
        ("dpkg-query", Result(0, "install ok installed 3.0.13-0ubuntu3.4")),
        ("apt-cache show", Result(0, "Package: openssl\nVersion: 3.0.13-0ubuntu3.4\n")),
    ]
    data = payload(await call("package_info", {"server_name": "root-box", "name": "openssl"}))
    assert data["package_manager"] == "apt"
    assert data["installed"] is True
    assert data["installed_version"] == "3.0.13-0ubuntu3.4"
    assert "Package: openssl" in data["info"]
    assert "env LC_ALL=C dpkg-query -W '--showformat=${Status} ${Version}' openssl" in ssh["commands"]
    assert not any("rpm" in c or "dnf" in c for c in ssh["commands"])


@pytestmark_anyio
async def test_package_info_apt_config_files_only(ssh):
    ssh["script"] = [
        ("os-release", Result(0, UBUNTU_OS_RELEASE)),
        ("dpkg-query", Result(0, "deinstall ok config-files 3.0.13-0ubuntu3.4")),
    ]
    data = payload(await call("package_info", {"server_name": "root-box", "name": "openssl"}))
    assert data["installed"] is False
    assert data["installed_version"] is None


@pytestmark_anyio
async def test_package_info_apt_unknown_package(ssh):
    ssh["script"] = [
        ("os-release", Result(0, UBUNTU_OS_RELEASE)),
        ("dpkg-query", Result(1, "", "dpkg-query: no packages found matching nosuch")),
        ("apt-cache show", Result(100, "", "E: No packages found")),
    ]
    data = payload(await call("package_info", {"server_name": "root-box", "name": "nosuch"}))
    assert data["installed"] is False
    assert "No packages found" in data["info"]


@pytestmark_anyio
async def test_firewall_rule_reloads_after_change(ssh):
    await call("firewall_rule", {"server_name": "root-box", "action": "add", "port": "8080/tcp", "confirm": True})
    assert ssh["commands"] == [
        "env LC_ALL=C firewall-cmd --permanent --add-port=8080/tcp",
        "env LC_ALL=C firewall-cmd --reload",
    ]


@pytestmark_anyio
async def test_firewall_rule_skips_reload_on_failure(ssh):
    ssh["script"] = [("--permanent", Result(1, "", "Error: INVALID_PORT"))]
    await call("firewall_rule", {"server_name": "root-box", "action": "add", "service": "http", "confirm": True})
    assert len(ssh["commands"]) == 1


@pytestmark_anyio
async def test_unknown_server(ssh):
    result = await call("server_info", {"server_name": "yok"})
    assert "server 'yok' not found" in result.content[0].text


@pytestmark_anyio
async def test_command_timeout(ssh, monkeypatch):
    monkeypatch.setattr(fleet_tools, "DEFAULT_TIMEOUT", 0.05)
    ssh["delay"] = 1
    result = await call("run_remote_command", {"server_name": "root-box", "command": "sleep 100", "confirm": True})
    text = result.content[0].text
    assert "Exit Status: None" in text
    assert "timed out" in text


@pytestmark_anyio
async def test_fleet_health(ssh):
    ssh["unreachable"] = {"10.0.0.2"}
    ssh["script"] = [
        ("/proc/loadavg", Result(0, "0.10 0.20 0.30 1/100 42\n")),
        ("--failed", Result(0, FAILED)),
        ("df -PT", Result(0, DF)),
    ]
    data = payload(await call("fleet_health", {}))
    assert data["root-box"]["failed_services"] == ["nginx.service", "kdump.service"]
    assert data["root-box"]["root_disk_used_percent"] == 82
    assert "No route to host" in data["user-box"]["error"]
