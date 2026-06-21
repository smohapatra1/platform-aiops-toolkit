"""
Runs a playbook on a host and returns structured output ready for analysis and runbook generation.
"""

import os
import shutil
import subprocess
import time

from config import SSH_OPTS

def _ssh_run(host, username, password, cmd, port=22, timeout=30):
    if not shutil.which("sshpass"):
        raise RuntimeError("sshpass is not installed -- run: sudo apt install sshpass")
    env = {**os.environ, "SSHPASS": password}
    try:
        proc = subprocess.run(
            ["sshpass", "-e", "ssh", "-p", str(port)] + SSH_OPTS + [
                "{u}@{h}".format(u=username, h=host), cmd,
            ],
            input=password + "\n",
            capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("SSH timed out after {t}s connecting to {h}".format(t=timeout, h=host))
    return proc.stdout, proc.stderr, proc.returncode


def run_playbook(host, playbook, username, password, port=22, timeout=30):
    """
    Runs all commands in a playbook on the given host.

    Returns:
        {
            "host": str,
            "playbook": str,
            "description": str,
            "results": [
                {"label": str, "cmd": str, "stdout": str, "stderr": str, "rc": int}
            ]
        }
    """
    results = []
    for step in playbook.get("commands", []):
        label = step["label"]
        cmd = step["cmd"]

        if cmd.strip().startswith("sudo"):
            rest = cmd[cmd.index("sudo") + 4:].strip()
            cmd = "sudo -S -p '' {rest}".format(rest=rest)

        t0 = time.time()
        out, err, rc = _ssh_run(host, username, password, cmd, port=port, timeout=timeout)
        duration = round(time.time() - t0, 1)
        err = "\n".join(l for l in err.splitlines() if "[sudo]" not in l and "password for" not in l.lower())
        results.append({"label": label, "cmd": step["cmd"], "stdout": out, "stderr": err.strip(), "rc": rc, "duration": duration})

    return results


def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def output_as_dict(host, playbook_name, playbook_def, results):
    """Return a flat label->stdout dict for pattern matching."""
    return {r["label"]: r["stdout"] for r in results}


def collect_logs(host, username, password, findings, since="2 hours ago", port=22, timeout=60):
    """
    Smart log collector — only pulls logs relevant to detected findings.
    Always collects: system-wide errors, kernel errors, failed units.
    Conditionally collects: per-service journals based on findings patterns.

    Customize PATTERN_TO_SERVICE and SERVICE_CMDS for your environment's service names.

    Returns list of {label, cmd, stdout, stderr, rc} same format as run_playbook.
    """
    # Map finding pattern names → service journals to pull.
    # Customize service names for your environment.
    PATTERN_TO_SERVICE = {
        "service_inactive":     ["app-controller", "forwarding-agent", "network-agent", "ovs"],
        "service_failed":       ["app-controller", "forwarding-agent", "network-agent", "ovs"],
        "service_activating":   ["app-controller", "forwarding-agent", "network-agent", "ovs"],
        "ovs_not_connected":    ["ovs"],
        "ovs_no_bridges":       ["ovs"],
        "ovs_port_down":        ["ovs"],
        "gre_remote_unreachable": ["ovs", "app-controller"],
        "fastpath_inactive":    ["fastpath"],
        "fpcli_unavailable":    ["fastpath"],
        "no_qemu_vms":          [],
        "kernel_errors":        [],
        "oom_killer":           [],
        "disk_critical":        [],
        "disk_warn":            [],
        "inode_critical":       [],
        "inode_warn":           [],
        "fd_critical":          [],
        "fd_warn":              [],
        "softnet_drops":        [],
        "mem_pressure_high":    [],
        "io_pressure_high":     [],
    }

    OVS_SVC = (
        "$(systemctl list-unit-files ovs-vswitchd.service openvswitch-switch.service --no-legend 2>/dev/null"
        " | awk '$2!=\"not-found\" {print $1}' | head -1)"
    )

    # Customize service names here to match your environment's systemd unit names
    SERVICE_CMDS = {
        "app-controller":    "sudo journalctl -u app-controller.service --since '{s}' --no-pager | tail -80".format(s=since),
        "forwarding-agent":  "sudo journalctl -u forwarding-agent.service --since '{s}' --no-pager | tail -80".format(s=since),
        "network-agent":     "sudo journalctl -u network-agent.service --since '{s}' --no-pager | tail -80".format(s=since),
        "ovs":               "sudo journalctl -u {ovs} --since '{s}' --no-pager | tail -80; sudo tail -50 /var/log/openvswitch/ovs-vswitchd.log 2>/dev/null".format(ovs=OVS_SVC, s=since),
        "fastpath":          "sudo journalctl -u fast-path.service --since '{s}' --no-pager | tail -80".format(s=since),
    }

    # Always collect these
    always = [
        {"label": "log_failed_units",   "cmd": "systemctl list-units --state=failed --no-legend 2>/dev/null"},
        {"label": "log_journal_errors", "cmd": "sudo journalctl -p err..crit --since '{s}' --no-pager -o short-iso | tail -100".format(s=since)},
        {"label": "log_dmesg_errors",   "cmd": "sudo dmesg -T --level=err,crit,warn | tail -50"},
        {"label": "log_dmesg_oom",      "cmd": "sudo dmesg -T | grep -i 'oom\\|killed process\\|out of memory' | tail -20"},
        {"label": "log_dmesg_net",      "cmd": "sudo dmesg -T | grep -iE 'gre|vxlan|openvswitch|ovs' | tail -20"},
    ]

    # Decide which service journals to fetch based on findings
    services_needed = set()
    for f in findings:
        if f["severity"] in ("ERROR", "WARNING"):
            for svc in PATTERN_TO_SERVICE.get(f["pattern"], []):
                services_needed.add(svc)

    # If no specific findings, pull all service journals
    if not services_needed and findings:
        services_needed = set(SERVICE_CMDS.keys())

    service_steps = [
        {"label": "log_{s}".format(s=svc.replace("-", "_")), "cmd": SERVICE_CMDS[svc]}
        for svc in sorted(services_needed)
    ]

    all_steps = always + service_steps

    results = []
    for step in all_steps:
        cmd = step["cmd"]
        if cmd.strip().startswith("sudo"):
            rest = cmd[cmd.index("sudo") + 4:].strip()
            cmd = "sudo -S -p '' {rest}".format(rest=rest)
        t0 = time.time()
        out, err, rc = _ssh_run(host, username, password, cmd, port=port, timeout=timeout)
        duration = round(time.time() - t0, 1)
        err = "\n".join(l for l in err.splitlines() if "[sudo]" not in l and "password for" not in l.lower())
        results.append({"label": step["label"], "cmd": step["cmd"], "stdout": out, "stderr": err.strip(), "rc": rc, "duration": duration})

    return results


def collect_iface_debug(host, username, password, dropping_ifaces, port=22, timeout=45):
    """
    Collect per-interface diagnostics for interfaces with detected drops.
    dropping_ifaces: list of interface names that have drops.
    """
    ifaces = " ".join(dropping_ifaces[:6])
    cmds = [
        {
            "label": "ethtool_stats",
            "cmd": (
                "for iface in {ifaces}; do"
                " echo \"=== $iface ===\";"
                " ethtool -S \"$iface\" 2>/dev/null | grep -vE '^\\s*\\w+: 0$' | grep -v '^$'"
                " || echo '  ethtool unavailable';"
                " done"
            ).format(ifaces=ifaces),
        },
        {
            "label": "ethtool_driver",
            "cmd": (
                "for iface in {ifaces}; do"
                " echo \"=== $iface ===\";"
                " ethtool -i \"$iface\" 2>/dev/null | grep -E 'driver|bus-info|firmware'"
                " || echo '  unavailable';"
                " done"
            ).format(ifaces=ifaces),
        },
        {
            "label": "ethtool_ringbuf",
            "cmd": (
                "for iface in {ifaces}; do"
                " echo \"=== $iface ===\";"
                " ethtool -g \"$iface\" 2>/dev/null | grep -E 'Pre-set|Current|RX:|TX:'"
                " || echo '  unavailable';"
                " done"
            ).format(ifaces=ifaces),
        },
        {
            "label": "dpdk_binding",
            "cmd": (
                "echo '--- vfio-pci ---';"
                " ls /sys/bus/pci/drivers/vfio-pci/ 2>/dev/null | grep -v module || echo 'none';"
                " echo '--- igb_uio ---';"
                " ls /sys/bus/pci/drivers/igb_uio/ 2>/dev/null | grep -v module || echo 'none'"
            ),
        },
        {
            "label": "fp_ports",
            "cmd": "sudo fp-cli port show 2>/dev/null || echo 'fp-cli unavailable'",
        },
        {
            "label": "iface_txqlen",
            "cmd": "ip link show | awk '/^[0-9]+:/{iface=$2} /qlen/{match($0,/qlen ([0-9]+)/,a); printf \"%s txqueuelen=%s\\n\",iface,a[1]}' 2>/dev/null",
        },
        {
            "label": "rss_config",
            "cmd": (
                "for iface in {ifaces}; do"
                " echo \"=== $iface ===\";"
                " ethtool -x \"$iface\" 2>/dev/null | head -20 || echo '  rss indirection: unavailable';"
                " ethtool -n \"$iface\" 2>/dev/null | grep -E 'RSS|hash|flow' || echo '  rss hash fields: unavailable';"
                " businfo=$(ethtool -i \"$iface\" 2>/dev/null | awk '/bus-info/{{print $2}}');"
                " physfn=$(ls /sys/bus/pci/devices/${{businfo}}/physfn/net/ 2>/dev/null | head -1);"
                " [ -n \"$physfn\" ] && echo \"  PF interface: $physfn\" || echo '  PF: not found';"
                " done"
            ).format(ifaces=ifaces),
        },
    ]
    results = []
    for step in cmds:
        cmd = step["cmd"]
        if cmd.strip().startswith("sudo"):
            rest = cmd[cmd.index("sudo") + 4:].strip()
            cmd = "sudo -S -p '' {rest}".format(rest=rest)
        t0 = time.time()
        out, err, rc = _ssh_run(host, username, password, cmd, port=port, timeout=timeout)
        duration = round(time.time() - t0, 1)
        err = "\n".join(l for l in err.splitlines() if "[sudo]" not in l and "password for" not in l.lower())
        results.append({"label": step["label"], "cmd": step["cmd"], "stdout": out, "stderr": err.strip(), "rc": rc, "duration": duration})
    return results


def collect_softnet_debug(host, username, password, port=22, timeout=30):
    """
    Collect detailed softnet / NIC diagnostics when drops are detected.
    Returns list of {label, cmd, stdout, stderr, rc}.
    """
    cmds = [
        {
            "label": "softnet_per_cpu",
            "cmd": (
                "awk 'BEGIN{c=0}{"
                "printf \"cpu%d dropped=%d throttled=%d\\n\","
                "c++,strtonum(\"0x\"$2),strtonum(\"0x\"$3)"
                "}' /proc/net/softnet_stat"
            ),
        },
        {
            "label": "netdev_sysctls",
            "cmd": (
                "sysctl"
                " net.core.netdev_max_backlog"
                " net.core.netdev_budget"
                " net.core.netdev_budget_usecs"
                " net.core.dev_weight"
                " net.core.rmem_max net.core.wmem_max"
                " net.core.rmem_default net.core.wmem_default"
                " net.netfilter.nf_conntrack_max"
                " net.ipv4.neigh.default.gc_thresh2"
                " net.ipv4.neigh.default.gc_thresh3"
                " net.ipv6.neigh.default.gc_thresh2"
                " net.ipv6.neigh.default.gc_thresh3"
                " net.ipv4.conf.all.rp_filter"
                " net.ipv4.conf.default.rp_filter"
                " 2>/dev/null;"
                " echo \"kernel=$(uname -r)\";"
                " awk -F'=' '/^(NAME|VERSION_ID)=/{gsub(/\"/,\"\");printf \"%s \",$2}"
                " END{print \"\"}' /etc/os-release 2>/dev/null"
            ),
        },
        {
            "label": "irq_affinity",
            "cmd": "cat /proc/interrupts | grep -E 'eth|ens|eno|gre|veth|data|iavf|mlx|ixgbe|i40e|ice|virtio' | head -30 || echo 'no matching IRQs'",
        },
        {
            "label": "rps_config",
            "cmd": "for f in /sys/class/net/*/queues/rx-*/rps_cpus; do echo \"$f: $(cat $f 2>/dev/null)\"; done 2>/dev/null | head -20",
        },
        {
            "label": "nic_drops",
            "cmd": (
                "for iface in $(ip -o link show | awk -F': ' '$2!~/lo|gre0|gretap|erspan|ovs-system|^mgmt/{print $2}' | head -10); do"
                " out=$(ethtool -S \"$iface\" 2>/dev/null | grep -iE 'drop|miss|rx_no_buffer' | grep -v ' 0$');"
                " [ -n \"$out\" ] && printf '=== %s ===\\n%s\\n' \"$iface\" \"$out\";"
                " done || true"
            ),
        },
        {
            "label": "hugepages",
            "cmd": (
                "grep -iE '^(HugePages_Total|HugePages_Free|HugePages_Rsvd|Hugepagesize)' /proc/meminfo 2>/dev/null;"
                " echo '---';"
                " for d in /sys/kernel/mm/hugepages/hugepages-*/; do"
                "  size=$(basename \"$d\");"
                "  total=$(cat \"$d/nr_hugepages\" 2>/dev/null || echo 0);"
                "  free=$(cat \"$d/free_hugepages\" 2>/dev/null || echo 0);"
                "  echo \"$size nr_hugepages=$total free_hugepages=$free\";"
                " done"
            ),
        },
        {
            "label": "nstat_drops",
            "cmd": (
                "nstat -az 2>/dev/null"
                " | awk 'NR>1 && $2+0>0 && ($1~/[Dd]rop|[Dd]iscard|[Oo]verflow|ListenOver|BacklogDrop|RcvbufError|InDiscard|ListenDrop/)'"
                " | sort -k2 -rn | head -20"
                " || echo 'nstat unavailable'"
            ),
        },
        {
            "label": "cpu_softirq",
            "cmd": (
                "mpstat -P ALL 1 1 2>/dev/null"
                " | awk 'NR>3 && $2~/^[0-9]/{printf \"cpu%s usr=%.1f sys=%.1f sirq=%.1f\\n\",$2,$3,$5,$8}'"
                " | head -64"
                " || echo 'mpstat unavailable'"
            ),
        },
        {
            "label": "cpu_governor",
            "cmd": (
                "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u"
                " || echo 'unavailable'"
            ),
        },
        {
            "label": "numa_info",
            "cmd": "numactl --hardware 2>/dev/null || echo 'numactl unavailable'",
        },
        {
            "label": "cpu_steal",
            "cmd": "top -bn2 -d1 | grep '%Cpu' | tail -1",
        },
        {
            "label": "process_affinity",
            "cmd": (
                "echo \"host_cores=$(nproc --all 2>/dev/null)\";"
                " for svc in app-controller forwarding-agent network-agent fast-path ovs-vswitchd openvswitch-switch ovsdb-server; do"
                "  pid=$(systemctl show -p MainPID ${svc}.service 2>/dev/null | cut -d= -f2);"
                "  [ -n \"$pid\" ] && [ \"$pid\" != '0' ] &&"
                "  cpus=$(taskset -cp $pid 2>/dev/null | grep -oP 'list: \\K.*' || echo 'N/A');"
                "  printf 'svc=%s pid=%s cpus=[%s]\\n' \"$svc\" \"$pid\" \"$cpus\";"
                " done;"
                " ps -eo pid,cmd 2>/dev/null | awk '$2~/^(kvm|qemu-system|qemu-kvm)$/' |"
                " while read pid cmd; do"
                "  name=$(echo \"$cmd\" | grep -oP \"(?<=-name ')[^']+|(?<=-name )[^', ]+\" || echo vm);"
                "  cpus=$(taskset -cp $pid 2>/dev/null | grep -oP 'list: \\K.*' || echo 'N/A');"
                "  printf 'svc=vm:%s pid=%s cpus=[%s]\\n' \"$name\" \"$pid\" \"$cpus\";"
                " done || true"
            ),
        },
        {
            "label": "vm_cpu_alloc",
            "cmd": (
                "ps -eo pid,cmd 2>/dev/null | awk '$2~/^(kvm|qemu-system|qemu-kvm)$/' |"
                " while read pid cmd; do"
                "  name=$(echo \"$cmd\" | grep -oP \"(?<=-name ')[^']+|(?<=-name )[^', ]+\" || echo unknown);"
                "  smp=$(echo \"$cmd\" | grep -oP '(?<=-smp )[^ ,]+' || echo '?');"
                "  mem=$(echo \"$cmd\" | grep -oP '(?<=-m )[^ ,]+' || echo '?');"
                "  cpuset=$(taskset -cp $pid 2>/dev/null | grep -oP 'list: \\K.*' || echo 'N/A');"
                "  printf 'vm=%-40s smp=%-10s mem=%-8s cpuset=[%s]\\n' \"$name\" \"$smp\" \"$mem\" \"$cpuset\";"
                " done || echo 'no VMs running'"
            ),
        },
    ]
    results = []
    for step in cmds:
        cmd = step["cmd"]
        if cmd.strip().startswith("sudo"):
            rest = cmd[cmd.index("sudo") + 4:].strip()
            cmd = "sudo -S -p '' {rest}".format(rest=rest)
        t0 = time.time()
        out, err, rc = _ssh_run(host, username, password, cmd, port=port, timeout=timeout)
        duration = round(time.time() - t0, 1)
        err = "\n".join(l for l in err.splitlines() if "[sudo]" not in l and "password for" not in l.lower())
        results.append({"label": step["label"], "cmd": step["cmd"], "stdout": out, "stderr": err.strip(), "rc": rc, "duration": duration})
    return results


def print_results(results):
    for r in results:
        print("\n{'='*60}")
        print("[{label}] $ {cmd}".format(**r))
        print("=" * 60)
        if r["stdout"]:
            print(r["stdout"], end="")
        if r["stderr"]:
            print("STDERR: " + r["stderr"])
        if r["rc"] != 0:
            print("(exit code: {rc})".format(**r))
