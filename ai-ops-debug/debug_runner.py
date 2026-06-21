#!/usr/bin/env python3
"""
Compute node debug runner — runs a diagnostic playbook over SSH, detects issues
via pattern matching, and generates an AI runbook using Claude API.

Usage:
    python3 debug_runner.py <host> [options]
    python3 debug_runner.py <host> --playbook primary_health --output confluence
    python3 debug_runner.py <host> --playbook tunnel_debug --output json
    python3 debug_runner.py --list-playbooks
    python3 debug_runner.py --show-settings
    python3 debug_runner.py --search-logs <query> [--freshness 1h]

Environment variables (or .env file):
    SSH_USERNAME          Default SSH username (can override with --user)
    SSH_PASSWORD          Default SSH password (can override with --password)
    CONFLUENCE_TOKEN      Token for posting runbooks to Confluence
    CONFLUENCE_PARENT_PAGE_ID  Parent page ID for Confluence runbook pages
    CONFLUENCE_BASE_URL   Confluence base URL
    CONFLUENCE_SPACE_KEY  Confluence space key
    GCP_LOG_PROJECTS      Comma-separated GCP project IDs for --search-logs
    ANTHROPIC_API_KEY     For AI runbook generation via Claude API
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from collect import _ssh_run                              # noqa: E402
from playbooks import PLAYBOOKS                           # noqa: E402
from patterns import match_patterns, _check_gre_reachability  # noqa: E402
import collect                                            # noqa: E402


COMPUTE_TYPE_PLAYBOOK = {
    "primary": "primary_health",
    "secondary": "secondary_health",
    "generic":  "generic_health",
}

# Interfaces excluded from drop/NIC findings — management plane, not data-plane
_MGMT_IFACE_RE = re.compile(r'^mgmt\d*$', re.IGNORECASE)


def _safe_err(exc):
    """Return a sanitized error string — never exposes command args or passwords."""
    msg = str(exc)
    if "timed out" in msg.lower() or exc.__class__.__name__ == "TimeoutExpired":
        return "timed out"
    if msg.startswith("["):
        return exc.__class__.__name__
    return msg


def detect_compute_type(host, username, password):
    """
    Probe the host to determine compute type.

    Primary: parse QEMU/KVM process args for VM names containing 'primary' or 'secondary'.
    Fallback: check fast-path.service (primary) and VXLAN ports in OVS (secondary).
    Returns: 'primary', 'secondary', or 'generic'

    Customize the probe strings below to match your environment's naming conventions.
    """
    probe_vms = "ps -eo pid,cmd 2>/dev/null | awk '$2~/^(kvm|qemu-system|qemu-kvm)$/'"
    try:
        out, _, _ = _ssh_run(host, username, password, probe_vms, timeout=10)
        lower = out.lower()
        # Customize: replace 'primary'/'secondary' with VM name patterns in your environment
        if "primary" in lower:
            return "primary"
        if "secondary" in lower:
            return "secondary"
    except Exception as e:
        print("  [detect] qemu probe failed: {m}".format(m=_safe_err(e)))
        sys.stdout.flush()

    # Fallback — service / OVS signals
    probe_svc = (
        "fp=$(systemctl is-active fast-path.service 2>/dev/null || echo inactive); "
        "vxlan=$(sudo -S -p '' bash -c 'ovs-vsctl list-br 2>/dev/null | while read br; do ovs-vsctl list-ports $br 2>/dev/null; done' 2>/dev/null | grep -c vxlan || echo 0); "
        "echo fp=$fp vxlan=$vxlan"
    )
    try:
        out, _, _ = _ssh_run(host, username, password, probe_svc, timeout=10)
        if "fp=active" in out:
            return "primary"
        m = re.search(r"vxlan=(\d+)", out)
        if m and int(m.group(1)) > 0:
            return "secondary"
    except Exception as e:
        print("  [detect] service probe failed: {m}".format(m=_safe_err(e)))
        sys.stdout.flush()

    return "generic"


def resolve_creds(user_override=None, pass_override=None):
    """Resolve SSH credentials from args → environment variables."""
    username = user_override or os.environ.get("SSH_USERNAME", "")
    password = pass_override or os.environ.get("SSH_PASSWORD", "")
    if not username or not password:
        print("ERROR: SSH credentials required. Set SSH_USERNAME/SSH_PASSWORD env vars "
              "or pass --user/--password.")
        sys.exit(1)
    return username, password


def make_ssh_runner(host, username, password, port=22, timeout=30):
    """Returns a callable(cmd) -> (stdout, stderr, rc)."""
    def runner(cmd):
        return _ssh_run(host, username, password, cmd, port=port, timeout=timeout)
    return None, runner


def _brief_detail(label, text):
    """Return a short inline summary of collected output for progress display."""
    t = text.strip()
    if not t:
        return ""

    if label == "hostname":
        return t.splitlines()[0].strip()

    if label == "uptime":
        m = re.search(r"up\s+(.+?),\s+\d+\s+user", t)
        return "up " + m.group(1).strip() if m else t.splitlines()[0][:60]

    if label == "cpu_mem":
        cpu_m = re.search(r"(\d+\.\d+)\s+id", t)
        mem_m = re.search(r"MiB Mem\s*:.*?,\s*(\d+\.\d+)\s+free", t)
        parts = []
        if cpu_m:
            parts.append("CPU {:.1f}% used".format(100 - float(cpu_m.group(1))))
        if mem_m:
            parts.append("{} MiB free".format(mem_m.group(1)))
        return ", ".join(parts)

    if label == "disk":
        lines = [l for l in t.splitlines() if re.search(r'\d+%', l) and not l.startswith("Filesystem")]
        summaries = []
        for l in lines[:5]:
            parts = l.split()
            if len(parts) >= 6:
                summaries.append("{} {}".format(parts[5], parts[4]))
        return "  ".join(summaries)

    if label == "inode_check":
        lines = [l for l in t.splitlines() if re.search(r'\d+%', l) and not l.startswith("Filesystem")]
        maxpct, maxmount = 0, ""
        for l in lines:
            m = re.search(r'(\d+)%', l)
            if m and int(m.group(1)) > maxpct:
                maxpct = int(m.group(1))
                parts = l.split()
                maxmount = parts[5] if len(parts) >= 6 else ""
        return "{} {}% inodes".format(maxmount, maxpct) if maxpct else ""

    if label == "fd_usage":
        m = re.search(r'(\d+)\s+(\d+)\s+(\d+)', t)
        if m:
            alloc, maxfd = int(m.group(1)), int(m.group(3))
            pct = int(alloc / maxfd * 100) if maxfd > 0 and maxfd < 10 ** 15 else 0
            return "{}/{} ({}%)".format(alloc, maxfd, pct)
        return ""

    if label in ("mem_pressure", "io_pressure"):
        m = re.search(r"some avg10=(\S+).*?full avg10=(\S+)", t)
        return "some={} full={}".format(m.group(1), m.group(2)) if m else ""

    if label == "softnet_stat":
        total_m = re.search(r"softnet_dropped=(\d+)", t)
        delta_m = re.search(r"softnet_recent_delta=(\d+)", t)
        if not total_m:
            return ""
        total = int(total_m.group(1))
        if delta_m:
            delta = int(delta_m.group(1))
            recent = " (+{:,} in last 5s)".format(delta) if delta > 0 else " (none recent)"
        else:
            recent = ""
        return "{:,} total{}".format(total, recent)

    if label == "conntrack_usage":
        m = re.search(r"nf_conntrack_count=(\d+) nf_conntrack_max=(\d+)", t)
        if not m:
            return ""
        count, maxv = int(m.group(1)), int(m.group(2))
        pct = count / maxv * 100 if maxv else 0
        if pct >= 85:
            status = "CRITICAL"
        elif pct >= 70:
            status = "WARN"
        else:
            status = "OK"
        return "{:,}/{:,}  ({:.0f}%)  {}".format(count, maxv, pct, status)

    if label == "tc_qdisc_drops":
        ifaces = re.findall(r'=== (\S+) ===', t)
        if not ifaces:
            return "no data"
        bad = []
        for name in ifaces:
            block_start = t.find("=== {} ===".format(name))
            next_block = t.find("=== ", block_start + 4)
            block = t[block_start:next_block] if next_block != -1 else t[block_start:]
            drops = sum(int(d) for d in re.findall(r'dropped (\d+)', block))
            if drops:
                bad.append("{} ({:,})".format(name, drops))
        if bad:
            return "DROPS on: {}".format(", ".join(bad))
        return "{} interface(s): 0 qdisc drops".format(len(ifaces))

    if label == "services":
        if "Active:" in t:
            lines = t.splitlines()
            not_running = []
            running = 0
            last_svc = None
            SKIP_PREFIXES = ("Loaded:", "Active:", "Drop", "Process", "Main", "CGroup", "Tasks",
                             "Memory", "CPU:", "Docs:", "Since", "Trigger", "Listen", "#")
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if not any(stripped.startswith(p) for p in SKIP_PREFIXES) and not stripped.startswith("└") and not stripped.startswith("├"):
                    m = re.search(r'\b([\w][\w._-]+\.service)\b', stripped)
                    if m:
                        last_svc = m.group(1)
                act_m = re.match(r'Active:\s+(\S+)', stripped)
                if act_m and last_svc:
                    state = act_m.group(1)
                    if state == "active":
                        running += 1
                    else:
                        not_running.append("{} [{}]".format(last_svc.replace(".service", ""), state))
                    last_svc = None
            if not_running:
                return "{} active | NOT running: {}".format(running, ", ".join(not_running))
            return "all {} active".format(running)
        else:
            lines = [l.strip() for l in t.splitlines() if l.strip()]
            not_active = [s for s in lines if s != "active"]
            if not_active:
                return "{}/{} active, {} not running".format(
                    lines.count("active"), len(lines), len(not_active))
            return "all {} active".format(len(lines))

    if label == "fp_service":
        state_m = re.search(r'Active:\s+(\S+)', t)
        if state_m:
            state = state_m.group(1)
            return "fast-path: {}".format(state) if state == "active" else "fast-path NOT running [{}]".format(state)
        return ""

    if label == "tunnel_show":
        active = len(re.findall(r"^gre\d+: gre/ip remote \d", t, re.MULTILINE))
        return "{} active GRE tunnel(s)".format(active) if active else "no active GRE tunnels"

    if label == "ovs_show":
        bridges = len(re.findall(r'^\s+Bridge\b', t, re.MULTILINE))
        connected = "controller disconnected" if "is_connected: false" in t else "controller OK"
        return "{} bridge(s), {}".format(bridges, connected)

    if label == "ovs_dpif":
        hit_m  = re.search(r'hit:(\d+)', t)
        miss_m = re.search(r'missed:(\d+)', t)
        lost_m = re.search(r'lost:(\d+)', t)
        flow_m = re.search(r'flows:\s*(\d+)', t)
        if not hit_m:
            return ""
        hit    = int(hit_m.group(1))
        missed = int(miss_m.group(1)) if miss_m else 0
        lost   = int(lost_m.group(1)) if lost_m else 0
        flows  = int(flow_m.group(1)) if flow_m else 0
        total  = hit + missed
        miss_pct = missed / total * 100 if total else 0
        parts = ["flows={:,}".format(flows), "miss={:.1f}%".format(miss_pct)]
        if lost:
            parts.append("[LOST {:,}]".format(lost))
        if miss_pct > 15:
            parts.append("slow-path HIGH")
        return "  ".join(parts)

    if label == "ovs_bridges":
        bridges = [l.strip() for l in t.splitlines() if l.strip()]
        return ", ".join(bridges[:4]) + ("..." if len(bridges) > 4 else "")

    if label == "ovs_port_states":
        down  = len(re.findall(r",down", t))
        total = len([l for l in t.splitlines() if l.strip()])
        return "{} port(s) down / {} total".format(down, total)

    if label == "qemu_count":
        names = [l.strip() for l in t.splitlines() if l.strip()]
        return "{} VM(s): {}".format(len(names), ", ".join(names)) if names else "no VMs running"

    if label == "interfaces":
        up = len(re.findall(r'\bstate UP\b', t))
        down_ifaces = re.findall(r'^\d+:\s+(\S+?):\s+<[^>]*>.*state DOWN', t, re.MULTILINE)
        parts = ["{} UP".format(up)]
        if down_ifaces:
            parts.append("{} DOWN ({})".format(len(down_ifaces), ", ".join(down_ifaces)))
        elif up:
            parts.append("0 DOWN")
        return ", ".join(parts) if (up or down_ifaces) else ""

    if label == "ip_route":
        return "{} routes".format(len([l for l in t.splitlines() if l.strip()]))

    if label == "ip_rule":
        lines  = [l.strip() for l in t.splitlines() if l.strip()]
        custom = [l for l in lines if not re.match(r'^(0|32766|32767):\s+from all lookup (local|main|default)', l)]
        if not custom:
            return "{} rules (default only)".format(len(lines))
        return "{} rules  ({} custom): {}".format(len(lines), len(custom), "; ".join(custom[:3]))

    if label == "iface_drops":
        rx = {}
        for iface, count in re.findall(r'(\S+)\s+rx_dropped=(\d+)', t):
            rx[iface] = rx.get(iface, 0) + int(count)
        tx = {}
        for iface, count in re.findall(r'(\S+)\s+tx_dropped=(\d+)', t):
            tx[iface] = tx.get(iface, 0) + int(count)
        if not rx and not tx:
            return "no drops"
        n = len(set(list(rx.keys()) + list(tx.keys())))
        top = max(rx, key=rx.get) if rx else max(tx, key=tx.get)
        top_cnt = rx.get(top, tx.get(top, 0))
        return "{} interface(s) with drops  (top: {} {:,})".format(n, top, top_cnt)

    if label == "ethtool_stats":
        ifaces = re.findall(r'^=== (\S+) ===', t, re.MULTILINE)
        parts = []
        for iface in ifaces:
            block_m  = re.search(r'=== {i} ===\n(.*?)(?===|\Z)'.format(i=re.escape(iface)), t, re.DOTALL)
            block    = block_m.group(1) if block_m else ""
            disc_m   = re.search(r'rx_discards:\s+(\d+)', block)
            q_counts = [int(x) for x in re.findall(r'rx-\d+\.packets:\s+(\d+)', block)]
            disc_str = " discards={:,}".format(int(disc_m.group(1))) if disc_m and int(disc_m.group(1)) > 0 else ""
            if q_counts and max(q_counts) > 0:
                pct   = int(max(q_counts) / sum(q_counts) * 100)
                q_str = " q0={:.0f}%".format(pct) if pct > 80 else ""
            else:
                q_str = ""
            if disc_str or q_str:
                parts.append("{}:{}{}".format(iface, disc_str, q_str))
        return "  ".join(parts) if parts else "{} interface(s) checked".format(len(ifaces))

    if label == "hugepages":
        _PLATFORM_BY_SIZE = {"hugepages-2048kB": 4096}
        sysfs = re.findall(r'(hugepages-\S+)\s+nr_hugepages=(\d+)\s+free_hugepages=(\d+)', t)
        if sysfs:
            rows = ["  {:<18} {:>8} {:>8} {:>8}  status".format("size", "total", "free", "used")]
            rows.append("  " + "-" * 60)
            for size_name, total_s, free_s in sysfs:
                total, free = int(total_s), int(free_s)
                used = total - free
                kb_m = re.search(r'(\d+)kB', size_name)
                kb = int(kb_m.group(1)) if kb_m else 0
                if kb >= 1024 * 1024:
                    size_label = "{} GB".format(kb // (1024 * 1024))
                elif kb >= 1024:
                    size_label = "{} MB".format(kb // 1024)
                else:
                    size_label = "{} kB".format(kb)
                total_gb = round(total * kb / 1024 / 1024, 1)
                expected = _PLATFORM_BY_SIZE.get(size_name)
                if total == 0:
                    status = "not configured"
                elif free == total:
                    if expected and total < expected:
                        status = "below platform standard ({} expected)  none in use".format(expected)
                    else:
                        status = "OK  ({:.0f} GB reserved, none in use yet)".format(total_gb)
                elif free == 0:
                    status = "EXHAUSTED"
                elif free <= 64:
                    status = "LOW  ({} free)".format(free)
                elif expected and total < expected:
                    status = "below platform standard ({} expected)".format(expected)
                else:
                    status = "OK  ({:.0f} GB reserved)".format(total_gb)
                rows.append("  {:<18} {:>8,} {:>8,} {:>8,}  {}".format(
                    size_label, total, free, used, status))
            return "\n" + "\n".join(rows)

        total_m = re.search(r'HugePages_Total:\s+(\d+)', t)
        free_m  = re.search(r'HugePages_Free:\s+(\d+)', t)
        size_m  = re.search(r'Hugepagesize:\s+(\d+)\s*kB', t)
        if total_m and free_m:
            total, free = int(total_m.group(1)), int(free_m.group(1))
            size_kb = int(size_m.group(1)) if size_m else 2048
            size_str = "{} MB".format(size_kb // 1024) if size_kb >= 1024 else "{} kB".format(size_kb)
            total_gb = round(total * size_kb / 1024 / 1024, 1)
            flag = ("EXHAUSTED" if free == 0 and total > 0
                    else "LOW" if free <= 64 and total > 0
                    else "below platform standard (4096 expected)" if total < 4096
                    else "OK  ({:.0f} GB)".format(total_gb))
            return "{}/{} used  ({} × {} = {:.0f} GB)  {}".format(
                total - free, total, total, size_str, total_gb, flag)
        return "not configured  (platform standard: 4096 × 2 MB)" if re.search(r'HugePages_Total:\s+0', t) else ""

    if label == "cpu_governor":
        governors = sorted(set(l.strip() for l in t.splitlines() if l.strip() and l.strip() != "unavailable"))
        return ", ".join(governors) if governors else "unavailable"

    if label == "numa_info":
        nodes_m = re.search(r'available:\s+(\d+) nodes?', t)
        if nodes_m:
            mem_m = re.findall(r'node \d+ size:\s+(\d+) MB', t)
            mem_str = " ({} MB each)".format(mem_m[0]) if mem_m and len(set(mem_m)) == 1 else ""
            return "{} NUMA node(s){}".format(nodes_m.group(1), mem_str)
        return "unavailable"

    if label == "cpu_steal":
        m = re.search(r'(\d+\.\d+)\s*st', t)
        if m:
            steal = float(m.group(1))
            flag = " -- HIGH" if steal >= 5.0 else (" -- elevated" if steal >= 1.0 else "")
            return "{:.1f}% steal{}".format(steal, flag)
        return ""

    if label == "nic_drops":
        nonzero = len(re.findall(r'(drop|miss|rx_no_buffer)\s*:\s*[1-9]', t, re.IGNORECASE))
        return "{} non-zero drop counter(s)".format(nonzero) if nonzero else "no NIC drops"

    if label == "nstat_drops":
        if "unavailable" in t:
            return "nstat unavailable"
        lines = [l.strip() for l in t.splitlines() if l.strip() and not l.startswith('#')]
        if not lines:
            return "no drop counters > 0"
        entries = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    entries.append((parts[0], int(parts[1])))
                except ValueError:
                    pass
        entries.sort(key=lambda x: -x[1])
        return "  ".join("{}: {:,}".format(k, v) for k, v in entries[:5])

    if label == "cpu_softirq":
        if "unavailable" in t:
            return "mpstat unavailable"
        entries = re.findall(r'cpu(\d+) usr=(\S+) sys=(\S+) sirq=(\S+)', t)
        if not entries:
            return ""
        high = [(c, float(s)) for c, _, _, s in entries if float(s) > 60]
        if high:
            worst = max(high, key=lambda x: x[1])
            return "cpu{} sirq={:.0f}%  [{}/{} cores >60%]".format(
                worst[0], worst[1], len(high), len(entries))
        worst = max(entries, key=lambda e: float(e[3]))
        return "max sirq={:.0f}% (cpu{})  all OK".format(float(worst[3]), worst[0])

    if label == "softnet_per_cpu":
        entries = re.findall(r'cpu(\d+) dropped=(\d+) throttled=(\d+)', t)
        if not entries:
            return ""
        total_drops     = sum(int(d) for _, d, _ in entries)
        total_throttled = sum(int(th) for _, _, th in entries)
        parts = []
        if total_drops > 0:
            worst = max(entries, key=lambda e: int(e[1]))
            parts.append("cpu{} has most ({:,}/{:,} drops)".format(worst[0], int(worst[1]), total_drops))
        if total_throttled > 0:
            throttled_cpus = [e[0] for e in entries if int(e[2]) > 0]
            parts.append("{} CPU(s) throttled: {}".format(len(throttled_cpus), ", ".join("cpu" + c for c in throttled_cpus)))
        return ", ".join(parts) if parts else "no drops per CPU"

    if label == "rps_config":
        lines   = [l for l in t.splitlines() if ': ' in l]
        enabled = sum(1 for l in lines if re.search(r'[^0\s]', l.split(': ', 1)[-1]))
        return "{}/{} queues have RPS enabled".format(enabled, len(lines)) if lines else ""

    return ""


_OFFLOAD_FEATS = [
    ("tx-checksumming",             "tx-csum"),
    ("tcp-segmentation-offload",    "tso"),
    ("generic-segmentation-offload","gso"),
    ("generic-receive-offload",     "gro"),
    ("large-receive-offload",       "lro"),
]


def _offload_table(text):
    """Full per-interface offload feature table for ANALYSIS section."""
    t = text.strip()
    sections = re.split(r'=== \S+ ===', t)
    ifaces   = re.findall(r'=== (\S+) ===', t)
    if not ifaces:
        return ""
    hdr  = "  ".join("{:>7}".format(f[1]) for f in _OFFLOAD_FEATS)
    rows = ["  {:<20}  {}  status".format("interface", hdr)]
    rows.append("  " + "-" * 77)
    for name, section in zip(ifaces, sections[1:]):
        bad  = []
        vals = []
        for feat, _ in _OFFLOAD_FEATS:
            m = re.search(r'^' + re.escape(feat) + r'\s*:\s*(\w+)', section, re.MULTILINE)
            if m:
                v = m.group(1).lower()
                vals.append("ON" if v == "on" else "off")
                if v == "on":
                    bad.append(feat.split("-")[0])
            else:
                vals.append("?")
        status = "[BAD] {} ON".format(", ".join(bad)) if bad else "OK"
        rows.append("  {:<20}  {}  {}".format(name, "  ".join("{:>7}".format(v) for v in vals), status))
    return "\n" + "\n".join(rows)


def _iface_drops_table(text):
    """Build a tabular display of interface drop counts, sorted by total drops desc."""
    t  = text.strip()
    rx = {}
    for iface, count in re.findall(r'(\S+)\s+rx_dropped=(\d+)', t):
        rx[iface] = rx.get(iface, 0) + int(count)
    tx = {}
    for iface, count in re.findall(r'(\S+)\s+tx_dropped=(\d+)', t):
        tx[iface] = tx.get(iface, 0) + int(count)
    if not rx and not tx:
        return ""
    all_ifaces = sorted(set(list(rx.keys()) + list(tx.keys())),
                        key=lambda i: -(rx.get(i, 0) + tx.get(i, 0)))
    lines = ["  {:<20} {:>14} {:>14}".format("interface", "rx_drops", "tx_drops"),
             "  " + "-" * 50]
    for iface in all_ifaces:
        r, tv = rx.get(iface, 0), tx.get(iface, 0)
        if r > 0 or tv > 0:
            lines.append("  {:<20} {:>14,} {:>14,}".format(iface, r, tv))
    return "\n".join(lines)


_GROUPED_PATTERNS = {
    "nic_hw_drops",
    "iface_rx_drops",
    "iface_tx_drops",
    "rss_queue_imbalance",
}

_GROUP_LABELS = {
    "nic_hw_drops":        "NIC hardware drops",
    "iface_rx_drops":      "Interface RX drops",
    "iface_tx_drops":      "Interface TX drops",
    "rss_queue_imbalance": "RSS queue imbalance",
}


def _iface_count(f):
    mt = f.get("matched_text", "").strip()
    m  = re.search(r'(?:rx_dropped|tx_dropped)=(\d+)', mt)
    if m:
        return mt.split()[0], int(m.group(1))
    m = re.search(r'([\d,]+)\s+packets', f.get("message", ""))
    if m:
        return mt, int(m.group(1).replace(",", ""))
    return mt, 0


def _print_collect_line(label, status, detail):
    if detail and "\n" in detail:
        print("  [{label:<20}] {status}".format(label=label, status=status))
        print(detail)
    else:
        detail_str = "  -- {}".format(detail) if detail else ""
        print("  [{label:<20}] {status}{detail}".format(label=label, status=status, detail=detail_str))


def print_findings(findings):
    if not findings:
        print("  (none)")
        return

    groups  = {}
    ordered = []
    for f in findings:
        pat = f["pattern"]
        if pat in _GROUPED_PATTERNS:
            if pat not in groups:
                groups[pat] = []
                ordered.append(("group", pat))
            groups[pat].append(f)
        else:
            ordered.append(("single", f))

    seen_suggestions = set()

    for kind, item in ordered:
        if kind == "group":
            pat    = item
            fs     = groups[pat]
            sev    = fs[0]["severity"]
            pairs  = sorted([_iface_count(f) for f in fs], key=lambda x: -x[1])
            iface_parts = [
                "{} ({:,})".format(iface, cnt) if cnt else iface
                for iface, cnt in pairs
            ]
            print("  [{sev:<7}]  {label} [{n}]:  {ifaces}".format(
                sev=sev,
                label=_GROUP_LABELS.get(pat, pat),
                n=len(pairs),
                ifaces="  ".join(iface_parts),
            ))
            sugg = fs[0].get("suggestion", "")
            if sugg and sugg not in seen_suggestions:
                top_iface = pairs[0][0] if pairs else "<iface>"
                print("             > {}".format(sugg.replace("{iface}", top_iface)))
                seen_suggestions.add(sugg)
        else:
            f = item
            print("  [{sev:<7}]  {msg}".format(sev=f["severity"], msg=f["message"]))
            if f.get("suggestion"):
                iface = re.match(r'(\S+)', f.get("matched_text", ""))
                iface_name = iface.group(1) if iface else "<iface>"
                suggestion = f["suggestion"].replace("{iface}", iface_name)
                if suggestion not in seen_suggestions:
                    print("             > {}".format(suggestion))
                    seen_suggestions.add(suggestion)


def _print_platform_settings():
    from patterns import _PLATFORM_SYSCTL
    _SEP = "─" * 70
    print("\n{sep}".format(sep=_SEP))
    print(" PLATFORM EXPECTED VALUES  (used for all checks)")
    print(_SEP)

    print("\n  SYSCTL PARAMETERS")
    print("  {:<45} {:>14}".format("parameter", "expected"))
    print("  " + "-" * 62)
    for key, val in _PLATFORM_SYSCTL.items():
        print("  {:<45} {:>14,}".format(key, val))

    print("\n  HUGEPAGES")
    print("  {:<30} {:>10}  {}".format("type", "count", "total"))
    print("  " + "-" * 52)
    print("  {:<30} {:>10,}  {}".format("hugepages-2048kB (2 MB)", 4096, "8 GB  -- DPDK/fastpath packet buffers"))
    print("  {:<30} {:>10}  {}".format("hugepages-1048576kB (1 GB)", "varies", "VM guest RAM (platform-dependent)"))

    print("\n  NIC OFFLOAD FEATURES  (all data* interfaces)")
    print("  {:<40} {}".format("feature", "expected"))
    print("  " + "-" * 52)
    for feat, _ in _OFFLOAD_FEATS:
        print("  {:<40} {}".format(feat, "OFF"))

    print("\n  INTERFACE SETTINGS")
    print("  {:<40} {}".format("setting", "expected"))
    print("  " + "-" * 52)
    print("  {:<40} {}".format("txqueuelen", "1000"))
    print("  {:<40} {}".format("ring rx / ring tx", "at pre-set hardware maximum"))
    print("  {:<40} {}".format("mgmt* interfaces", "excluded from all drop checks"))
    print()


def main():
    parser = argparse.ArgumentParser(description="Compute node debug + AI runbook generator")
    parser.add_argument("host",            nargs="?",  help="Compute hostname or IP")
    parser.add_argument("--playbook",      default="auto",
                        help="Playbook name, or 'auto' to detect host type (default: auto)")
    parser.add_argument("--list-playbooks", action="store_true", help="List available playbooks and exit")
    parser.add_argument("--show-settings",  action="store_true", help="Print all platform expected values and exit")
    parser.add_argument("--search-logs",    metavar="QUERY",
                        help="Search GCP Cloud Logging for an IP, hostname, or keyword and exit")
    parser.add_argument("--freshness",     default="1h",  metavar="WINDOW",
                        help="Relative log search window: 1h, 3d, 12h (default: 1h). Ignored when --from is set.")
    parser.add_argument("--from",          dest="time_from", metavar="DATETIME",
                        help="Absolute start time: '2026-06-17 10:00' or RFC3339")
    parser.add_argument("--to",            dest="time_to",   metavar="DATETIME",
                        help="Absolute end time (optional)")
    parser.add_argument("--log-limit",     type=int, default=50, metavar="N",
                        help="Max log entries per project for --search-logs (default: 50)")
    parser.add_argument("--log-env",       choices=["prod", "nonprod", "all"], default="all",
                        help="Which log projects to search: prod, nonprod, or all (default: all)")
    parser.add_argument("--output",        choices=["confluence", "json", "both", "stdout"], default="stdout",
                        help="Where to send the generated runbook (default: stdout)")
    parser.add_argument("--no-runbook",    action="store_true", help="Skip AI runbook generation")
    parser.add_argument("--check-gre",     action="store_true", help="Ping GRE remote IPs and report reachability")
    parser.add_argument("--collect-logs",  action="store_true",
                        help="Collect service/kernel logs (auto-triggered on ERROR findings)")
    parser.add_argument("--log-since",     default="2 hours ago",
                        help="How far back to collect logs (default: '2 hours ago')")
    parser.add_argument("--user",          help="SSH username (or set SSH_USERNAME env var)")
    parser.add_argument("--password",      help="SSH password (or set SSH_PASSWORD env var)")
    parser.add_argument("--confluence-parent",
                        default=os.environ.get("CONFLUENCE_PARENT_PAGE_ID", "CHANGE_ME"),
                        help="Confluence parent page ID for runbook pages")
    parser.add_argument("--log-dir",       default="./logs",
                        help="Directory for JSON logs (default: ./logs)")
    args = parser.parse_args()

    if args.show_settings:
        _print_platform_settings()
        return

    if args.list_playbooks:
        print("\nAvailable playbooks:\n")
        for name, pb in PLAYBOOKS.items():
            print("  {name:<20} [{ct}]  {desc}".format(
                name=name, ct=pb.get("compute_type", "ANY"), desc=pb["description"]))
        print()
        return

    if args.search_logs:
        try:
            from gcp_logs import search_logs, print_log_results, _OBS_PROJECTS
        except ImportError:
            print("ERROR: gcp_logs.py not found — ensure it is in the same directory")
            sys.exit(1)
        projects = None
        if args.log_env == "prod":
            projects = [p for p in _OBS_PROJECTS if "prod" in p and "preprod" not in p]
        elif args.log_env == "nonprod":
            projects = [p for p in _OBS_PROJECTS if "preprod" in p or "dev" in p]
        results, errors = search_logs(
            args.search_logs,
            projects=projects,
            freshness=args.freshness,
            start_time=args.time_from,
            end_time=args.time_to,
            limit=args.log_limit,
        )
        print_log_results(results, errors, args.search_logs, limit=args.log_limit)
        return

    if not args.host:
        parser.print_help()
        sys.exit(1)

    username, password = resolve_creds(args.user, args.password)

    ctype = "generic"
    if args.playbook == "auto":
        print("\nDetecting compute type on {h}...".format(h=args.host))
        sys.stdout.flush()
        try:
            ctype = detect_compute_type(args.host, username, password)
        except Exception as e:
            ctype = "generic"
            print("  Detection error ({e}) - falling back to: generic_health".format(e=_safe_err(e)))
            sys.stdout.flush()
        args.playbook = COMPUTE_TYPE_PLAYBOOK[ctype]
        print("  Detected: {t} -> playbook: {p}".format(t=ctype, p=args.playbook))
        sys.stdout.flush()

    if args.playbook not in PLAYBOOKS:
        print("ERROR: Unknown playbook '{p}'. Use --list-playbooks to see options.".format(p=args.playbook))
        sys.exit(1)

    playbook_def = PLAYBOOKS[args.playbook]

    print("\nHost    : {h}".format(h=args.host))
    print("Playbook: {p} -- {d}".format(p=args.playbook, d=playbook_def["description"]))
    print("=" * 70)

    _SEP = "─" * 70

    import time as _time
    _t_start   = _time.time()
    _t_iface   = _t_softnet = _t_logs = 0.0

    try:
        results = collect.run_playbook(args.host, playbook_def, username, password)
    except RuntimeError as e:
        print("ERROR [ssh_setup]: {e}".format(e=e))
        sys.exit(1)
    except Exception as e:
        print("ERROR [ssh_connect] {h}: {e}".format(h=args.host, e=e))
        sys.exit(1)

    _t_collect = round(sum(r.get("duration", 0) for r in results), 1)
    output_map = {r["label"]: r["stdout"] for r in results if r["rc"] == 0 or r["stdout"].strip()}

    gre_findings = []
    tunnel_output = output_map.get("tunnel_show", "")
    has_active_gre = bool(re.search(r"^gre\d+: gre/ip remote \d", tunnel_output, re.MULTILINE))
    if has_active_gre or (args.check_gre and tunnel_output):
        _, runner = make_ssh_runner(args.host, username, password)
        gre_findings = _check_gre_reachability(output_map, ssh_runner=runner)

    detail_overrides = {}
    if gre_findings:
        base = _brief_detail("tunnel_show", tunnel_output)
        gre_parts = [
            "{ip} {state}".format(
                ip=gf["matched_text"],
                state="reachable" if gf["severity"] == "INFO" else "UNREACHABLE",
            )
            for gf in gre_findings
        ]
        detail_overrides["tunnel_show"] = "{base}, remote: {gre}".format(
            base=base, gre=", ".join(gre_parts))

    # ── Section 1: Log Collection ─────────────────────────────────────────────
    print("\n{sep}".format(sep=_SEP))
    print(" LOG COLLECTION")
    print(_SEP)
    for r in results:
        if r["rc"] != 0:
            status = "✗ failed (rc={rc})".format(**r)
            detail = r["stderr"][:120] if r["stderr"] else ""
        else:
            detail = detail_overrides.get(r["label"]) or _brief_detail(r["label"], r["stdout"])
            status = "✓" if r["stdout"].strip() else "✓ (empty)"
        _print_collect_line(r["label"], status, detail)

    # ── Section 2: Analysis ───────────────────────────────────────────────────
    print("\n{sep}".format(sep=_SEP))
    print(" ANALYSIS")
    print(_SEP)
    findings = match_patterns(output_map, compute_type=ctype)
    findings.extend(f for f in gre_findings if f["severity"] != "INFO")

    # ── Interface drop deep-dive ──────────────────────────────────────────────
    iface_drop_findings = [
        f for f in findings
        if f["pattern"] in ("iface_rx_drops", "iface_tx_drops")
        and not _MGMT_IFACE_RE.match(f.get("matched_text", "").split()[0])
    ]
    if iface_drop_findings:
        dropping_ifaces = list(dict.fromkeys(
            re.match(r'(\S+)', f["matched_text"]).group(1)
            for f in iface_drop_findings if re.match(r'(\S+)', f["matched_text"])
        ))
        table = _iface_drops_table(output_map.get("iface_drops", ""))
        if table:
            print(table)
        sys.stdout.flush()
        try:
            _t0 = _time.time()
            iface_extra = collect.collect_iface_debug(args.host, username, password, dropping_ifaces)
            _t_iface    = round(_time.time() - _t0, 1)
            extra_map   = {r["label"]: r["stdout"] for r in iface_extra if r["rc"] == 0 or r["stdout"].strip()}
            output_map.update(extra_map)
            results = results + iface_extra
            for r in iface_extra:
                detail = _brief_detail(r["label"], r["stdout"])
                status = "✓" if r["stdout"].strip() else "✓ (empty)"
                _print_collect_line(r["label"], status, detail)
            findings = match_patterns(output_map, compute_type=ctype)
            findings.extend(f for f in gre_findings if f["severity"] != "INFO")
        except Exception as e:
            print("  WARNING: interface deep-dive failed: {e}".format(e=e))

    # ── Softnet / CPU deep-dive (triggered on any drop type) ─────────────────
    has_any_drops = any(f["pattern"] in (
        "softnet_drops", "softnet_drops_recent", "iface_rx_drops", "iface_tx_drops"
    ) for f in findings)
    if has_any_drops:
        print("  Drops detected -- collecting CPU/hugepage/process diagnostics...")
        sys.stdout.flush()
        try:
            _t0         = _time.time()
            softnet_extra = collect.collect_softnet_debug(args.host, username, password)
            _t_softnet  = round(_time.time() - _t0, 1)
            extra_map   = {r["label"]: r["stdout"] for r in softnet_extra if r["rc"] == 0 or r["stdout"].strip()}
            output_map.update(extra_map)
            results = results + softnet_extra
            for r in softnet_extra:
                detail = _brief_detail(r["label"], r["stdout"])
                status = "✓" if r["stdout"].strip() else "✓ (empty)"
                _print_collect_line(r["label"], status, detail)
            findings = match_patterns(output_map, compute_type=ctype)
            findings.extend(f for f in gre_findings if f["severity"] != "INFO")
        except Exception as e:
            print("  WARNING: softnet deep-dive failed: {e}".format(e=e))

    # Strip findings whose matched_text is a management interface
    _DROP_PATTERNS = {"iface_rx_drops", "iface_tx_drops", "nic_hw_drops", "nic_rx_discards", "rss_queue_imbalance"}
    findings = [
        f for f in findings
        if f["pattern"] not in _DROP_PATTERNS
        or not _MGMT_IFACE_RE.match(f.get("matched_text", "").split()[0])
    ]

    has_active_drops = any(f["pattern"] == "softnet_drops_recent" for f in findings)
    if not has_active_drops:
        findings = [f for f in findings if f["pattern"] != "softnet_drops"]

    _SYSCTL_TUNE_PATTERNS = {"netdev_backlog_low", "netdev_budget_low", "netdev_budget_usecs_low", "dev_weight_low"}
    fired = {f["pattern"] for f in findings}
    if "softnet_throttled" in fired and not (fired & _SYSCTL_TUNE_PATTERNS):
        for f in findings:
            if f["pattern"] == "softnet_throttled":
                f["suggestion"] = (
                    "Sysctls already at platform values -- throttling is from traffic volume or CPU scheduling.\n"
                    "             Next steps:\n"
                    "               1. Check CPU affinity: are NIC IRQs and services pinned to the same cores? (see process_affinity)\n"
                    "               2. Check RSS distribution: is all traffic landing on one queue? (see rss_config)\n"
                    "               3. Check NUMA: are NIC IRQs crossing NUMA nodes? (see numa_info / irq_affinity)"
                )

    for pat, cnt_key in [("iface_rx_drops", r"rx_dropped=(\d+)"), ("iface_tx_drops", r"tx_dropped=(\d+)")]:
        matching = [f for f in findings if f["pattern"] == pat]
        if len(matching) > 5:
            other = [f for f in findings if f["pattern"] != pat]
            def _cnt(f, key=cnt_key):
                m = re.search(key, f["matched_text"])
                return int(m.group(1)) if m else 0
            top5 = sorted(matching, key=_cnt, reverse=True)[:5]
            findings = other + top5

    offload_text = output_map.get("ethtool_offload", "")
    if offload_text.strip():
        _print_collect_line("ethtool_offload", "✓", _offload_table(offload_text))

    from patterns import PATTERNS as _ALL_PATTERNS
    active_patterns = sum(
        1 for p in _ALL_PATTERNS
        if not p.get("compute_type") or p.get("compute_type") == ctype
    )
    print("  Ran {n} pattern checks across {items} collected items".format(
        n=active_patterns, items=len(output_map)))

    errors   = [f for f in findings if f["severity"] == "ERROR"]
    warnings = [f for f in findings if f["severity"] == "WARNING"]
    infos    = [f for f in findings if f["severity"] == "INFO"]

    # ── Section 3: Findings ───────────────────────────────────────────────────
    print("\n{sep}".format(sep=_SEP))
    print(" FINDINGS  —  {e} ERROR(s)  {w} WARNING(s)  {i} INFO(s)".format(
        e=len(errors), w=len(warnings), i=len(infos)))
    print(_SEP)
    if findings:
        print_findings(errors + warnings + infos)
    else:
        print("  No issues detected.")

    # ── Log collection ────────────────────────────────────────────────────────
    log_results = []
    should_collect_logs = args.collect_logs or bool(errors)
    if should_collect_logs:
        reason = "--collect-logs flag" if args.collect_logs else "{n} ERROR finding(s) detected".format(n=len(errors))
        print("\nCollecting logs ({r})...".format(r=reason))
        try:
            _t0 = _time.time()
            log_results = collect.collect_logs(
                args.host, username, password,
                findings=findings,
                since=args.log_since,
            )
            _t_logs   = round(_time.time() - _t0, 1)
            collected = sum(1 for r in log_results if r["stdout"].strip())
            failed_logs = sum(1 for r in log_results if r["rc"] != 0 and not r["stdout"].strip())
            summary = "  Logs collected: {c}/{t} with content".format(c=collected, t=len(log_results))
            if failed_logs:
                summary += ", {} failed".format(failed_logs)
            print(summary)
            results = results + log_results
        except Exception as e:
            print("WARNING: Log collection failed: {e}".format(e=e))

    # ── Runbook generation ────────────────────────────────────────────────────
    runbook_text = ""
    if not args.no_runbook:
        print("\nGenerating runbook via Claude API...")
        try:
            import runbook as runbook_gen
            runbook_text = runbook_gen.generate(args.host, args.playbook, results, findings)
        except ImportError as e:
            print("WARNING: Runbook generation skipped - missing dependency: {e}".format(e=e))
            print("         Install with: pip install anthropic")
        except Exception as e:
            print("WARNING: Runbook generation failed: {e}".format(e=e))

    # ── Output ────────────────────────────────────────────────────────────────
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.output == "stdout" or not runbook_text:
        if runbook_text:
            print("\n" + "=" * 70)
            print("RUNBOOK")
            print("=" * 70)
            print(runbook_text)

    if args.output in ("json", "both"):
        import json, pathlib
        outdir = pathlib.Path(args.log_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        safe_host = re.sub(r'[^\w.-]', '_', args.host)
        filename  = "{ts}_{host}_{pb}.json".format(
            ts=ts[:10], host=safe_host[:40], pb=args.playbook)
        log_path  = outdir / filename
        payload   = {
            "host":     args.host,
            "playbook": args.playbook,
            "ts":       ts,
            "findings": findings,
            "runbook":  runbook_text,
            "results":  [{"label": r["label"], "rc": r["rc"], "stdout": r["stdout"]} for r in results],
        }
        log_path.write_text(json.dumps(payload, indent=2))
        print("\nJSON log saved: {p}".format(p=log_path))

    if args.output in ("confluence", "both") and runbook_text:
        token = os.environ.get("CONFLUENCE_TOKEN", "")
        if not token:
            print("ERROR: CONFLUENCE_TOKEN not set. Pass --confluence-token or set the env var.")
            sys.exit(1)
        base     = os.environ.get("CONFLUENCE_BASE_URL", "https://your-wiki.your-company.com")
        space    = os.environ.get("CONFLUENCE_SPACE_KEY", "CHANGE_ME")
        title    = "Runbook: {host} {pb} {ts}".format(host=args.host, pb=args.playbook, ts=ts[:10])
        body_html = "<pre>{}</pre>".format(runbook_text.replace("<", "&lt;").replace(">", "&gt;"))
        headers   = {"Authorization": "Bearer {}".format(token), "Content-Type": "application/json"}
        import requests
        try:
            resp = requests.post(
                "{}/rest/api/content".format(base),
                json={
                    "type":      "page",
                    "title":     title,
                    "space":     {"key": space},
                    "ancestors": [{"id": args.confluence_parent}],
                    "body":      {"storage": {"value": body_html, "representation": "storage"}},
                },
                headers=headers,
                timeout=15,
            )
            resp.raise_for_status()
            page_id = resp.json().get("id", "?")
            print("\nConfluence page created: {base}/wiki/spaces/{space}/pages/{pid}".format(
                base=base, space=space, pid=page_id))
        except Exception as e:
            print("ERROR posting to Confluence: {e}".format(e=e))

    _t_total = round(_time.time() - _t_start, 1)
    _timing_parts = ["collection {:.0f}s".format(_t_collect)]
    if _t_iface:
        _timing_parts.append("iface debug {:.0f}s".format(_t_iface))
    if _t_softnet:
        _timing_parts.append("softnet debug {:.0f}s".format(_t_softnet))
    if _t_logs:
        _timing_parts.append("log collection {:.0f}s".format(_t_logs))
    print("\nDone.  (total {:.0f}s  |  {parts})".format(_t_total, parts="  |  ".join(_timing_parts)))


if __name__ == "__main__":
    main()
