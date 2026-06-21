import re

# Known error signatures matched against labeled command output.
# Each pattern fires on the output of a specific label (or any label if label=None).
# severity: ERROR | WARNING | INFO

# Expected sysctl values — used for threshold checks and suggestions.
# Customize these for your platform's tuning standards.
_PLATFORM_SYSCTL = {
    "net.core.netdev_max_backlog":          48000,
    "net.core.netdev_budget":               48000,
    "net.core.netdev_budget_usecs":          5000,
    "net.core.dev_weight":                    128,
    "net.core.rmem_max":                134217728,
    "net.core.wmem_max":                134217728,
    "net.core.rmem_default":            134217728,
    "net.core.wmem_default":            134217728,
    "net.netfilter.nf_conntrack_max":      512000,
    "net.ipv4.neigh.default.gc_thresh2":     4096,
    "net.ipv4.neigh.default.gc_thresh3":     8192,
    "net.ipv6.neigh.default.gc_thresh2":     4096,
    "net.ipv6.neigh.default.gc_thresh3":     8192,
    "net.ipv4.conf.all.rp_filter":              0,
    "net.ipv4.conf.default.rp_filter":          0,
}

# Shared suggestion for packet-processing tuning (backlog/budget group) — deduplicated by print_findings
_NETDEV_TUNE = (
    "Restore platform packet-processing settings:\n"
    "             sysctl -w net.core.netdev_max_backlog=48000"
    " net.core.netdev_budget=48000 net.core.netdev_budget_usecs=5000 net.core.dev_weight=128\n"
    "             # Persist: add to /etc/sysctl.d/99-platform-tuning.conf and run:\n"
    "             # sysctl -p /etc/sysctl.d/99-platform-tuning.conf"
)

# Shared suggestion for hugepage configuration — platform standard is 4096 × 2 MB = 8 GB
_HP_TUNE = (
    "Platform standard: 4096 × 2 MB pages (8 GB total).\n"
    "             Set now:  echo 4096 > /proc/sys/vm/nr_hugepages\n"
    "             Persist:  echo 'vm.nr_hugepages=4096' >> /etc/sysctl.d/99-platform-tuning.conf\n"
    "                       sysctl -p /etc/sysctl.d/99-platform-tuning.conf\n"
    "             Verify:   for d in /sys/kernel/mm/hugepages/hugepages-*/; do\n"
    "                         echo \"$(basename $d): total=$(cat $d/nr_hugepages) free=$(cat $d/free_hugepages)\";\n"
    "                       done\n"
    "             Note:     /proc/meminfo HugePages_* only shows the DEFAULT hugepage size;\n"
    "                       use the sysfs loop above to see all sizes (2 MB and 1 GB separately)"
)

PATTERNS = [

    # ── Services ─────────────────────────────────────────────────────────────
    # Customize service names to match your environment's systemd units
    {
        "name": "service_inactive",
        "label": "services",
        "match": r"(app-controller|forwarding-agent|network-agent|openvswitch-switch|ovs-vswitchd)\.service\s+inactive",
        "severity": "ERROR",
        "message": "One or more critical services are INACTIVE",
    },
    {
        "name": "service_failed",
        "label": "services",
        "match": r"(app-controller|forwarding-agent|network-agent|openvswitch-switch|ovs-vswitchd)\.service\s+failed",
        "severity": "ERROR",
        "message": "One or more critical services are in FAILED state",
    },
    {
        "name": "service_activating",
        "label": "services",
        "match": r"(app-controller|forwarding-agent|network-agent|openvswitch-switch|ovs-vswitchd)\.service\s+activating",
        "severity": "WARNING",
        "message": "One or more services are still activating (possible restart loop)",
    },

    # ── Tunnels ───────────────────────────────────────────────────────────────
    {
        "name": "no_gre_tunnels",
        "label": "tunnel_show",
        "match": r"^gre\d+: gre/ip remote \d",  # matches active tunnels (not the gre0 default)
        "severity": "WARNING",
        "message": "No active GRE tunnels found -- only default gre0 present",
        "invert": True,
        "compute_type": "primary",
    },

    # ── secondary / VXLAN ────────────────────────────────────────────────────
    {
        "name": "no_ovs_bridges",
        "label": "ovs_show",
        "match": r"\bBridge\b",
        "severity": "ERROR",
        "message": "No OVS bridges found -- ovs-vsctl show has no Bridge entries",
        "invert": True,
        "compute_type": "secondary",
    },
    {
        "name": "no_vxlan_ports",
        "label": "vxlan_ports",
        "match": r"vxlan",
        "severity": "WARNING",
        "message": "No VXLAN ports found on any OVS bridge -- overlay network may not be configured",
        "invert": True,
        "skip_if_text": r"^\s*$",  # suppress when vxlan_ports output is empty (sudo failed or no bridges)
        "compute_type": "secondary",
    },

    # ── OVS ───────────────────────────────────────────────────────────────────
    {
        "name": "ovs_not_connected",
        "label": "ovs_show",
        "match": r"is_connected\s*:\s*false",
        "severity": "ERROR",
        "message": "OVS reports controller disconnected",
    },
    {
        "name": "ovs_no_bridges",
        "label": "ovs_bridges",
        "match": r"\A\s*\Z",  # full-string match — re.MULTILINE makes ^\s*$ match any blank line
        "severity": "ERROR",
        "message": "No OVS bridges found",
        "compute_type": "primary",
    },

    # ── Disk ──────────────────────────────────────────────────────────────────
    {
        "name": "disk_critical",
        "label": "disk",
        "match": r"\b(9[5-9]|100)%",
        "severity": "ERROR",
        "message": "Disk usage is critically high (>=95%)",
    },
    {
        "name": "disk_warn",
        "label": "disk",
        "match": r"\b(9[1-4])%",
        "severity": "WARNING",
        "message": "Disk usage is high (91-94%)",
    },

    # ── Memory ────────────────────────────────────────────────────────────────
    {
        "name": "mem_pressure",
        "label": "cpu_mem",
        "match": r"MiB Mem\s*:.*,\s*(\d+\.\d+)\s*free",
        "severity": "WARNING",
        "message": "Low free memory detected",
        "threshold_fn": lambda m: float(m.group(1)) < 512,
    },

    # ── Kernel / dmesg ────────────────────────────────────────────────────────
    {
        "name": "kernel_errors",
        "label": "dmesg_errors",
        "match": r"(?i)(error|crit|panic|oom|kill)",
        "severity": "ERROR",
        "message": "Kernel errors found in dmesg",
    },
    {
        "name": "oom_killer",
        "label": "dmesg_errors",
        "match": r"(?i)oom.kill|out of memory",
        "severity": "ERROR",
        "message": "OOM killer triggered — process(es) killed due to memory pressure",
    },

    # ── Fastpath ──────────────────────────────────────────────────────────────
    {
        "name": "fastpath_inactive",
        "label": "fp_service",
        "match": r"fast-path\.service\s+(inactive|failed)",
        "severity": "ERROR",
        "message": "Fastpath service is not running",
        "compute_type": "primary",
    },
    {
        "name": "fpcli_unavailable",
        "label": "fp_stats",
        "match": r"fp-cli unavailable",
        "severity": "WARNING",
        "message": "fp-cli is not available on this host",
        "compute_type": "primary",
    },

    # ── Inodes ────────────────────────────────────────────────────────────────
    {
        "name": "inode_critical",
        "label": "inode_check",
        "match": r"\b(9[5-9]|100)%",
        "severity": "ERROR",
        "message": "Inode usage is critically high (>=95%) -- filesystem may report 'no space left' despite free disk",
    },
    {
        "name": "inode_warn",
        "label": "inode_check",
        "match": r"\b(9[0-4])%",
        "severity": "WARNING",
        "message": "Inode usage is elevated (90-94%)",
    },

    # ── File descriptors ──────────────────────────────────────────────────────
    {
        "name": "fd_critical",
        "label": "fd_usage",
        # file-nr format: allocated  unused  max
        "match": r"(\d+)\s+(\d+)\s+(\d+)",
        "severity": "ERROR",
        "message": "File descriptor usage is critically high (>=90%) -- process failures imminent",
        "threshold_fn": lambda m: (
            int(m.group(3)) > 0
            and int(m.group(3)) < 10 ** 15  # skip INT64_MAX (effectively unlimited)
            and (int(m.group(1)) / int(m.group(3)) * 100) >= 90
        ),
    },
    {
        "name": "fd_warn",
        "label": "fd_usage",
        "match": r"(\d+)\s+(\d+)\s+(\d+)",
        "severity": "WARNING",
        "message": "File descriptor usage is elevated (>=80%)",
        "threshold_fn": lambda m: (
            int(m.group(3)) > 0
            and int(m.group(3)) < 10 ** 15
            and (int(m.group(1)) / int(m.group(3)) * 100) >= 80
        ),
    },

    # ── Softnet / kernel packet drops ────────────────────────────────────────
    {
        "name": "softnet_drops_recent",
        "label": "softnet_stat",
        "match": r"softnet_recent_delta=(\d+)",
        "severity": "WARNING",
        "message": "Active kernel softnet drops in last 5s -- NIC overload or budget exhaustion happening now",
        "threshold_fn": lambda m: int(m.group(1)) > 0,
    },
    {
        "name": "softnet_drops",
        "label": "softnet_stat",
        "match": r"softnet_dropped=(\d+)",
        "severity": "INFO",
        "message": "Kernel softnet drops detected (cumulative since boot) -- historical, not necessarily active",
        "threshold_fn": lambda m: int(m.group(1)) >= 1000,
    },

    # ── OVS port link states ──────────────────────────────────────────────────
    {
        "name": "ovs_port_down",
        "label": "ovs_port_states",
        "match": r"[^\n,]+,[^\n,]+,down",
        "severity": "WARNING",
        "message": "One or more OVS interfaces have link_state=down",
        "skip_if_text": r"unavailable",
    },

    # ── Memory pressure ───────────────────────────────────────────────────────
    {
        "name": "mem_pressure_high",
        "label": "mem_pressure",
        "match": r"full avg10=(\d+\.\d+)",
        "severity": "WARNING",
        "message": "Memory pressure (full avg10 >=1.0) -- tasks stalling waiting for memory",
        "threshold_fn": lambda m: float(m.group(1)) >= 1.0,
    },

    # ── IO pressure ───────────────────────────────────────────────────────────
    {
        "name": "io_pressure_high",
        "label": "io_pressure",
        "match": r"full avg10=(\d+\.\d+)",
        "severity": "WARNING",
        "message": "IO pressure (full avg10 >=1.0) -- tasks stalling on disk IO",
        "threshold_fn": lambda m: float(m.group(1)) >= 1.0,
    },

    # ── Interface drops ───────────────────────────────────────────────────────
    {
        "name": "iface_rx_drops",
        "label": "iface_drops",
        "match": r"(\S+)\s+rx_dropped=([1-9]\d*)",
        "severity": "WARNING",
        "message_fn": lambda m: "RX drops on {} -- {:,} packets lost (kernel drop before software processing)".format(
            m.group(1), int(m.group(2))),
        "message": "Interface RX drops detected",
        "per_match": True,
        "suggestion": (
            "ethtool -S {iface} | grep -vE ': 0$'  -- hardware counters\n"
            "             ethtool -i {iface}  -- check driver/binding\n"
            "             fp-cli port show  -- verify fastpath is consuming the VF queue\n"
            "             TX=0 with RX drops = DPDK-managed (fastpath owns TX, kernel counters unused)"
        ),
    },
    {
        "name": "iface_tx_drops",
        "label": "iface_drops",
        "match": r"(\S+)\s+tx_dropped=([1-9]\d*)",
        "severity": "WARNING",
        "message_fn": lambda m: "TX drops on {} -- {:,} packets failed to transmit".format(
            m.group(1), int(m.group(2))),
        "message": "Interface TX drops detected",
        "per_match": True,
        "suggestion": (
            "ip link show {iface} | grep txqueuelen  -- check queue depth\n"
            "             ip link set {iface} txqueuelen 10000  -- increase if low\n"
            "             ethtool -g {iface} / ethtool -G {iface} tx 4096  -- check/increase ring buffer"
        ),
    },

    # ── ethtool deep-dive (triggered after interface drops detected) ─────────
    {
        "name": "nic_rx_discards",
        "label": "ethtool_stats",
        "match": r"=== (\S+) ===[\s\S]*?rx_discards:\s+([1-9]\d*)",
        "severity": "ERROR",
        "message_fn": lambda m: (
            "VXLAN kernel queue discards on {}: {:,} packets dropped (not a NIC ring buffer issue)".format(m.group(1), int(m.group(2)))
            if re.match(r'^vxlan', m.group(1))
            else "NIC hardware discards on {}: {:,} packets dropped at ring buffer (before kernel)".format(m.group(1), int(m.group(2)))
        ),
        "message": "NIC hardware rx_discards detected",
        "per_match": True,
        "iface_group": 1,
        "suggestion_fn": lambda m: (
            # VXLAN interfaces — no NIC ring buffer; drops = OVS can't dequeue VXLAN packets fast enough.
            "OVS is not dequeuing VXLAN packets fast enough — kernel drops on the UDP receive socket.\n"
            "             1. Check OVS slow-path load:    sudo ovs-dpctl show  (look for lost > 0)\n"
            "             2. Check handler thread count:  sudo ovs-appctl upcall/show\n"
            "             3. Increase OVS handler threads:\n"
            "                  sudo ovs-vsctl set Open_vSwitch . other_config:n-handler-threads=4\n"
            "             4. Check VXLAN UDP socket:      ss -unt | grep 4789\n"
            "             5. Verify VXLAN port config:    sudo ovs-vsctl show | grep -A5 vxlan"
            if re.match(r'^vxlan', m.group(1))
            else
            # Physical / VF NIC — ring buffer + RSS
            "Ring buffer full — NIC discarding before kernel sees packets.\n"
            "             Check current size:   ethtool -g {iface}\n"
            "             Increase ring buffer: ethtool -G {iface} rx <max>\n"
            "             If already at max: RSS imbalance is the root cause.\n"
            "             See rss_config table in ANALYSIS section above for queue distribution.\n"
            "             Fix on PF: ethtool -N <pf> rx-flow-hash gre4 sd"
        ),
    },
    {
        "name": "rss_queue_imbalance",
        "label": "ethtool_stats",
        "match": r"=== (\S+) ===[\s\S]*?rx-0\.packets:\s+(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "RSS queue imbalance on {} -- rx-0 has {:,} packets (GRE flows hash identically to same queue)".format(m.group(1), int(m.group(2))),
        "message": "RSS queue imbalance detected",
        "threshold_fn": lambda m: int(m.group(2)) > 1000000,
        "iface_group": 1,
        "suggestion": (
            "GRE/tunnel flows hash to same queue because outer IPs are identical.\n"
            "             Check RSS fields: ethtool -n {iface}\n"
            "             Check indirection table: ethtool -x {iface}\n"
            "             Find PF: ls /sys/bus/pci/devices/<bus-info>/physfn/net/\n"
            "             Fix on PF: ethtool -N <pf> rx-flow-hash gre4 sd\n"
            "             Spread evenly: ethtool -X <pf> equal <num_queues>"
        ),
    },

    # ── Softnet deep-dive (triggered after drops detected) ───────────────────
    {
        "name": "softnet_throttled",
        "label": "softnet_per_cpu",
        "match": r"throttled=([1-9]\d*)",
        "severity": "WARNING",
        "message": "CPU softirq budget exhausted (throttled CPUs found) -- kernel stopped processing early",
        "suggestion": _NETDEV_TUNE,
    },
    {
        "name": "netdev_backlog_low",
        "label": "netdev_sysctls",
        "match": r"netdev_max_backlog\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.core.netdev_max_backlog={} -- below platform expected (48000); packet backlog drops likely under burst".format(m.group(1)),
        "message": "net.core.netdev_max_backlog below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 48000,
        "suggestion": _NETDEV_TUNE,
    },
    {
        "name": "netdev_budget_low",
        "label": "netdev_sysctls",
        "match": r"netdev_budget\b\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.core.netdev_budget={} -- below platform expected (48000); kernel exits softirq too soon".format(m.group(1)),
        "message": "net.core.netdev_budget below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 48000,
        "suggestion": _NETDEV_TUNE,
    },
    {
        "name": "netdev_budget_usecs_low",
        "label": "netdev_sysctls",
        "match": r"netdev_budget_usecs\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.core.netdev_budget_usecs={} -- below platform expected (5000); time budget too short under load".format(m.group(1)),
        "message": "net.core.netdev_budget_usecs below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 5000,
        "suggestion": _NETDEV_TUNE,
    },
    {
        "name": "dev_weight_low",
        "label": "netdev_sysctls",
        "match": r"dev_weight\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.core.dev_weight={} -- below platform expected (128); NAPI processes fewer packets per poll cycle".format(m.group(1)),
        "message": "net.core.dev_weight below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 128,
        "suggestion": _NETDEV_TUNE,
    },
    {
        "name": "socket_buffers_low",
        "label": "netdev_sysctls",
        "match": r"rmem_max\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.core.rmem_max={:,} -- below platform expected (134217728 / 128MB); throughput limited by small socket buffers".format(int(m.group(1))),
        "message": "net.core.rmem_max below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 134217728,
        "suggestion": (
            "sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728"
            " net.core.rmem_default=134217728 net.core.wmem_default=134217728"
        ),
    },
    {
        "name": "conntrack_low",
        "label": "netdev_sysctls",
        "match": r"nf_conntrack_max\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "net.netfilter.nf_conntrack_max={:,} -- below platform expected (512000); connection table may fill, new connections dropped".format(int(m.group(1))),
        "message": "nf_conntrack_max below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 512000,
        "suggestion": "sysctl -w net.netfilter.nf_conntrack_max=512000",
    },
    {
        "name": "neigh_thresh_low",
        "label": "netdev_sysctls",
        "match": r"gc_thresh2\s*=\s*(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "neigh gc_thresh2={} -- below platform expected (4096); ARP/neighbor table evicts entries under load".format(m.group(1)),
        "message": "neigh gc_thresh2 below platform expected value",
        "threshold_fn": lambda m: int(m.group(1)) < 4096,
        "suggestion": (
            "sysctl -w net.ipv4.neigh.default.gc_thresh2=4096"
            " net.ipv4.neigh.default.gc_thresh3=8192"
            " net.ipv6.neigh.default.gc_thresh2=4096"
            " net.ipv6.neigh.default.gc_thresh3=8192"
        ),
    },
    {
        "name": "rp_filter_nonzero",
        "label": "netdev_sysctls",
        "match": r"(ipv4\.conf\.\S+\.rp_filter)\s*=\s*([1-9]\d*)",
        "severity": "ERROR",
        "message_fn": lambda m: "{} is {} -- reverse path filtering ACTIVE; asymmetric overlay/GRE routes will be silently dropped".format(m.group(1), m.group(2)),
        "message": "rp_filter is not 0 -- overlay/GRE traffic will be dropped",
        "per_match": True,
        "suggestion": (
            "Disable reverse path filtering (required for GRE/overlay traffic):\n"
            "             sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0"
        ),
    },
    {
        "name": "nic_hw_drops",
        "label": "nic_drops",
        "match": r"=== (\S+) ===[\s\S]*?(drop|miss|rx_no_buffer)\s*:\s*[1-9]",
        "severity": "WARNING",
        "message_fn": lambda m: "NIC hardware drops on {} -- ring buffer overflow or RSS queue imbalance".format(m.group(1)),
        "message": "NIC hardware drops detected",
        "per_match": True,
        "iface_group": 1,
        "suggestion": (
            "Check ring size: ethtool -g {iface}\n"
            "             If current < max: ethtool -G {iface} rx <max>\n"
            "             If already at max: ring increase won't help -- fix RSS queue distribution:\n"
            "               Find PF: ls /sys/bus/pci/devices/<bus-info>/physfn/net/\n"
            "               Enable tunnel hashing on PF: ethtool -N <pf> rx-flow-hash gre4 sd\n"
            "               Spread queues evenly: ethtool -X <pf> equal <num_queues>"
        ),
    },
    {
        "name": "rps_disabled",
        "label": "rps_config",
        "match": r":\s*0+\s*$",
        "severity": "INFO",
        "message": "RPS disabled on one or more queues -- all RX traffic may land on a single CPU",
        "suggestion": "Enable RPS: echo ff > /sys/class/net/<iface>/queues/rx-0/rps_cpus  (use bitmask for your CPU count)",
    },

    # ── Hugepages ─────────────────────────────────────────────────────────────
    {
        "name": "hugepages_exhausted",
        "label": "hugepages",
        "match": r"HugePages_Free:\s+(\d+)",
        "severity": "ERROR",
        "message": "Hugepages fully exhausted (Free=0) -- DPDK/fastpath will fail to allocate packet buffers",
        "threshold_fn": lambda m: int(m.group(1)) == 0,
        "suggestion": _HP_TUNE,
    },
    {
        "name": "hugepages_low",
        "label": "hugepages",
        "match": r"HugePages_Free:\s+(\d+)",
        "severity": "WARNING",
        "message": "Hugepages running low (<=64 free) -- DPDK packet drops likely under high load",
        "threshold_fn": lambda m: 0 < int(m.group(1)) <= 64,
        "suggestion": _HP_TUNE,
    },
    {
        "name": "hugepages_none",
        "label": "hugepages",
        "match": r"HugePages_Total:\s+0",
        "severity": "WARNING",
        "message": "No hugepages configured -- DPDK/fastpath requires hugepages for packet buffers",
        "compute_type": "primary",
        "suggestion": _HP_TUNE,
    },
    {
        "name": "hugepages_2mb_low",
        "label": "hugepages",
        "match": r"hugepages-2048kB\s+nr_hugepages=(\d+)",
        "severity": "WARNING",
        "message_fn": lambda m: "2 MB hugepages: {} configured -- below platform standard (4096 × 2 MB = 8 GB)".format(m.group(1)),
        "message": "2 MB hugepage count below platform standard of 4096",
        "threshold_fn": lambda m: int(m.group(1)) < 4096,
        "suggestion": _HP_TUNE,
    },

    # ── CPU governor ──────────────────────────────────────────────────────────
    {
        "name": "cpu_powersave",
        "label": "cpu_governor",
        "match": r"powersave",
        "severity": "WARNING",
        "message": "CPU frequency governor is 'powersave' -- CPU throttling can cause packet drops under burst",
        "suggestion": "Switch to performance: echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
    },

    # ── CPU steal (VM overhead) ───────────────────────────────────────────────
    {
        "name": "cpu_steal_high",
        "label": "cpu_steal",
        "match": r"(\d+\.\d+)\s*st",
        "severity": "WARNING",
        "message": "High CPU steal time detected -- hypervisor is taking CPU cycles, causing packet drops",
        "threshold_fn": lambda m: float(m.group(1)) >= 5.0,
        "suggestion": "CPU steal is a hypervisor-level issue. Check host VM load; consider pinning vCPUs.",
    },

    # ── NIC offload features ──────────────────────────────────────────────────
    {
        "name": "offload_feature_on",
        "label": "ethtool_offload",
        # Fires once per interface that has any offload feature ON
        "match": r"=== (\S+) ===[\s\S]*?^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload)\s*:\s*on\b",
        "severity": "WARNING",
        "message_fn": lambda m: "NIC offload '{}' is ON on {} -- platform standard requires OFF; can cause softpath CPU overhead or DPDK bypass issues".format(m.group(2), m.group(1)),
        "message": "NIC offload feature enabled -- platform standard requires OFF",
        "per_match": True,
        "iface_group": 1,
        "suggestion": "ethtool -K {iface} tx-checksumming off tso off gso off gro off lro off",
    },

    # ── QEMU VMs on primary nodes ─────────────────────────────────────────────
    {
        "name": "no_qemu_vms",
        "label": "qemu_count",
        "match": r"\w",
        "severity": "WARNING",
        "message": "No QEMU/KVM VM processes found on primary host -- expected VMs may have crashed or not started",
        "invert": True,
        "compute_type": "primary",
    },

    # ── Conntrack table fill ──────────────────────────────────────────────────
    {
        "name": "conntrack_warn",
        "label": "conntrack_usage",
        "match": r"nf_conntrack_count=(\d+) nf_conntrack_max=(\d+)",
        "severity": "WARNING",
        "threshold_fn": lambda m: int(m.group(2)) > 0 and 0.70 <= int(m.group(1)) / int(m.group(2)) < 0.85,
        "message_fn": lambda m: "Conntrack table {:.0f}% full ({:,}/{:,}) — approaching drop threshold".format(
            int(m.group(1)) / int(m.group(2)) * 100, int(m.group(1)), int(m.group(2))),
        "message": "Conntrack table above 70% capacity",
        "suggestion": (
            "Monitor growth: watch -n5 'cat /proc/sys/net/netfilter/nf_conntrack_count'\n"
            "             If rising: sysctl -w net.netfilter.nf_conntrack_max=1048576\n"
            "             Persist: echo 'net.netfilter.nf_conntrack_max=1048576' >> /etc/sysctl.d/99-platform-tuning.conf"
        ),
    },
    {
        "name": "conntrack_critical",
        "label": "conntrack_usage",
        "match": r"nf_conntrack_count=(\d+) nf_conntrack_max=(\d+)",
        "severity": "ERROR",
        "threshold_fn": lambda m: int(m.group(2)) > 0 and int(m.group(1)) / int(m.group(2)) >= 0.85,
        "message_fn": lambda m: "Conntrack table {:.0f}% full ({:,}/{:,}) — new flows silently dropped".format(
            int(m.group(1)) / int(m.group(2)) * 100, int(m.group(1)), int(m.group(2))),
        "message": "Conntrack table critical — new connections being dropped",
        "suggestion": (
            "URGENT — increase limit immediately:\n"
            "             sysctl -w net.netfilter.nf_conntrack_max=2097152\n"
            "             Persist: echo 'net.netfilter.nf_conntrack_max=2097152' >> /etc/sysctl.d/99-platform-tuning.conf\n"
            "             Top talkers: conntrack -L 2>/dev/null | awk '{print $3,$4}' | sort | uniq -c | sort -rn | head"
        ),
    },

    # ── TC qdisc TX drops ─────────────────────────────────────────────────────
    {
        "name": "tc_qdisc_drops",
        "label": "tc_qdisc_drops",
        "match": r"=== (\S+) ===[\s\S]*?dropped ([1-9]\d*)",
        "severity": "WARNING",
        "per_match": True,
        "iface_group": 1,
        "message_fn": lambda m: "TC qdisc drops on {}: {:,} packets dropped at TX queue".format(
            m.group(1), int(m.group(2))),
        "message": "TC qdisc drops detected",
        "suggestion": (
            "TX queue dropping before packets reach the NIC.\n"
            "             Check queue type/depth: tc -s qdisc show dev {iface}\n"
            "             Increase txqueuelen: ip link set {iface} txqueuelen 10000\n"
            "             Or switch to fq_codel: tc qdisc replace dev {iface} root fq_codel"
        ),
    },

    # ── Kernel nstat drop counters ────────────────────────────────────────────
    {
        "name": "nstat_tcp_listen_drops",
        "label": "nstat_drops",
        "match": r"TcpExtListenDrops\s+([1-9]\d*)",
        "severity": "ERROR",
        "message_fn": lambda m: "TCP listen queue drops: {:,} connections refused (backlog full)".format(int(m.group(1))),
        "message": "TCP listen queue overflow — connections being dropped",
        "suggestion": (
            "TCP SYN backlog overflow:\n"
            "             sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535\n"
            "             Overloaded sockets: ss -lnt | awk 'NR>1 && $2>0'"
        ),
    },
    {
        "name": "nstat_tcp_backlog_drop",
        "label": "nstat_drops",
        "match": r"TcpExtTCPBacklogDrop\s+([1-9]\d*)",
        "severity": "WARNING",
        "message_fn": lambda m: "TCP socket receive backlog drops: {:,} (app not draining fast enough)".format(int(m.group(1))),
        "message": "TCP receive backlog drops",
        "suggestion": (
            "TCP socket receive buffer full:\n"
            "             sysctl -w net.core.rmem_max=134217728\n"
            "             Slow sockets: ss -tmn | awk 'NR>1 && $2+0>0'"
        ),
    },
    {
        "name": "nstat_udp_rcvbuf",
        "label": "nstat_drops",
        "match": r"UdpRcvbufErrors\s+([1-9]\d*)",
        "severity": "WARNING",
        "message_fn": lambda m: "UDP receive buffer overflow: {:,} datagrams dropped".format(int(m.group(1))),
        "message": "UDP receive buffer drops",
        "suggestion": (
            "UDP socket receive buffer too small:\n"
            "             sysctl -w net.core.rmem_max=134217728 net.core.rmem_default=134217728"
        ),
    },
    {
        "name": "nstat_ip_discards",
        "label": "nstat_drops",
        "match": r"IpInDiscards\s+([1-9]\d*)",
        "severity": "WARNING",
        "message_fn": lambda m: "IP input discards: {:,} packets dropped at IP layer (no buffer or route)".format(int(m.group(1))),
        "message": "IP input discards detected",
        "suggestion": (
            "Packets dropped at IP receive path — possible causes:\n"
            "             1. No route: ip route show; ip rule show\n"
            "             2. rp_filter blocking asymmetric traffic: sysctl net.ipv4.conf.all.rp_filter\n"
            "             3. Receive buffer exhaustion: check rmem_max"
        ),
    },

    # ── CPU softirq saturation ────────────────────────────────────────────────
    {
        "name": "cpu_softirq_high",
        "label": "cpu_softirq",
        "match": r"cpu(\d+) usr=\S+ sys=\S+ sirq=(\d+(?:\.\d+)?)",
        "severity": "WARNING",
        "per_match": True,
        "iface_group": 1,
        "threshold_fn": lambda m: float(m.group(2)) > 80.0,
        "message_fn": lambda m: "CPU {} softirq at {:.0f}% — NIC poll saturated, packets being dropped".format(
            m.group(1), float(m.group(2))),
        "message": "CPU softirq saturation detected",
        "suggestion": (
            "Core saturated processing NIC interrupts — spread the load:\n"
            "             Check IRQ assignment: cat /proc/interrupts | grep <iface>\n"
            "             Rebalance: service irqbalance restart\n"
            "             Manual: echo <cpu_mask> > /proc/irq/<N>/smp_affinity\n"
            "             Enable RPS to spread across cores: echo <cpu_mask> > /sys/class/net/<iface>/queues/rx-0/rps_cpus"
        ),
    },

    # ── OVS datapath packet loss ──────────────────────────────────────────────
    {
        "name": "ovs_datapath_lost",
        "label": "ovs_dpif",
        "match": r"lost:([1-9]\d*)",
        "severity": "ERROR",
        "message_fn": lambda m: "OVS datapath lost {:,} packets (kernel→upcall queue full)".format(int(m.group(1))),
        "message": "OVS datapath packet loss — upcall queue overflow",
        "suggestion": (
            "OVS is dropping packets it can't hand to vswitchd (slow path overloaded).\n"
            "             Check OVS handler threads: ovs-appctl upcall/show\n"
            "             Increase handler threads: ovs-vsctl set Open_vSwitch . other_config:n-handler-threads=4\n"
            "             Check miss rate: ovs-dpctl show  (lookups: hit/missed/lost)\n"
            "             Add proactive flows to reduce slow-path traffic: ovs-ofctl dump-flows br-int | wc -l"
        ),
    },
]


def _check_gre_reachability(collected_output, ssh_runner=None):
    """
    Parse tunnel_show output, extract remote IPs from active GRE tunnels,
    ping each one via the host (using ssh_runner), and report unreachable as ERROR.
    ssh_runner: callable(cmd) -> (stdout, stderr, rc)
    """
    findings = []
    text = collected_output.get("tunnel_show", "")
    remote_ips = re.findall(r"remote\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    remote_ips = [ip for ip in remote_ips if ip != "0.0.0.0"]

    if not remote_ips or ssh_runner is None:
        return findings

    for ip in remote_ips:
        stdout, _, rc = ssh_runner("ping -c 2 -W 1 {ip}".format(ip=ip))
        reachable = rc == 0 and ("1 received" in stdout or "2 received" in stdout)
        if not reachable:
            findings.append({
                "pattern": "gre_remote_unreachable",
                "severity": "ERROR",
                "message": "GRE tunnel exists, remote IP {ip} is NOT reachable".format(ip=ip),
                "label": "tunnel_show",
                "matched_text": ip,
            })
        else:
            findings.append({
                "pattern": "gre_remote_reachable",
                "severity": "INFO",
                "message": "GRE tunnel exists, remote IP {ip} is reachable".format(ip=ip),
                "label": "tunnel_show",
                "matched_text": ip,
            })
    return findings


def match_patterns(collected_output, compute_type="generic"):
    """
    Run all patterns against collected output.
    collected_output: dict of {label: output_text}
    compute_type: 'primary', 'secondary', or 'generic' -- patterns tagged with compute_type
                  are skipped unless the type matches.
    Returns list of findings: {name, severity, message, label, matched_text}
    """
    findings = []
    for pattern in PATTERNS:
        pattern_type = pattern.get("compute_type")
        if pattern_type and pattern_type != compute_type:
            continue
        label = pattern.get("label")
        targets = {label: collected_output[label]} if label and label in collected_output else collected_output
        invert = pattern.get("invert", False)
        threshold_fn = pattern.get("threshold_fn")

        for lbl, text in targets.items():
            if label and lbl != label:
                continue
            skip_if = pattern.get("skip_if_text")
            if skip_if and re.search(skip_if, text, re.MULTILINE):
                continue
            matches = list(re.finditer(pattern["match"], text, re.MULTILINE | re.DOTALL))
            fired = bool(matches)
            if invert:
                fired = not fired

            if fired:
                msg_fn = pattern.get("message_fn")
                ig = pattern.get("iface_group")
                sugg_fn = pattern.get("suggestion_fn")
                if pattern.get("per_match") and matches:
                    for m in matches:
                        if threshold_fn and not threshold_fn(m):
                            continue
                        findings.append({
                            "pattern": pattern["name"],
                            "severity": pattern["severity"],
                            "message": msg_fn(m) if msg_fn else pattern["message"],
                            "suggestion": sugg_fn(m) if sugg_fn else pattern.get("suggestion", ""),
                            "label": lbl,
                            "matched_text": m.group(ig) if ig else m.group(0),
                        })
                else:
                    if threshold_fn and matches:
                        if not threshold_fn(matches[0]):
                            continue
                    first = matches[0] if matches else None
                    findings.append({
                        "pattern": pattern["name"],
                        "severity": pattern["severity"],
                        "message": msg_fn(first) if msg_fn and first else pattern["message"],
                        "suggestion": (sugg_fn(first) if sugg_fn and first else pattern.get("suggestion", "")),
                        "label": lbl,
                        "matched_text": (first.group(ig) if ig else first.group(0)) if first else "",
                    })
    return findings
