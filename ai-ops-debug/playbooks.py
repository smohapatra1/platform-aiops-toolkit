# Named debug playbooks — each is a labeled set of commands to run on a compute node.
# Commands are run in order; label is used in output, pattern matching, and runbook sections.
#
# Customize service names (app-controller.service, forwarding-agent.service, etc.)
# to match the systemd units in your environment.

# OVS service name changed in Ubuntu 24.04: ovs-vswitchd.service (>=24.04) vs openvswitch-switch.service (<24.04)
_OVS_SVC = (
    "$(systemctl list-unit-files ovs-vswitchd.service openvswitch-switch.service --no-legend 2>/dev/null"
    " | awk '$2!=\"not-found\" {print $1}' | head -1)"
)

PLAYBOOKS = {

    "primary_health": {
        "description": "Full primary compute node health check — services, tunnels, OVS, routing, system",
        "compute_type": "primary",
        "commands": [
            {"label": "hostname",        "cmd": "hostname"},
            {"label": "uptime",          "cmd": "uptime"},
            {"label": "cpu_mem",         "cmd": "top -bn1 | head -8"},
            {"label": "disk",            "cmd": "df -h"},
            {"label": "inode_check",     "cmd": "df -i"},
            {"label": "fd_usage",        "cmd": "cat /proc/sys/fs/file-nr"},
            {"label": "mem_pressure",    "cmd": "cat /proc/pressure/memory 2>/dev/null || echo 'unavailable'"},
            {"label": "io_pressure",     "cmd": "cat /proc/pressure/io 2>/dev/null || echo 'unavailable'"},
            {"label": "softnet_stat",    "cmd": "bash -c 'sum(){ local d=0; while read -r t v r; do [ -n \"$v\" ] && d=$(( d + 16#${v} )) || true; done </proc/net/softnet_stat 2>/dev/null; echo $d; }; t1=$(sum); sleep 5; t2=$(sum); echo \"softnet_dropped=${t2} softnet_recent_delta=$(( t2 - t1 ))\"'"},
            {"label": "conntrack_usage", "cmd": (
                "cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0);"
                " cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0);"
                " echo \"nf_conntrack_count=$cc nf_conntrack_max=$cm\""
            )},
            # Customize: replace service names with your environment's systemd units
            {"label": "services",        "cmd": "systemctl status app-controller.service forwarding-agent.service network-agent.service {ovs} --no-pager".format(ovs=_OVS_SVC)},
            {"label": "fp_service",      "cmd": "systemctl status fast-path.service --no-pager"},
            {"label": "tunnel_show",     "cmd": "ip tunnel show"},
            {"label": "ip_route",        "cmd": "ip route show"},
            {"label": "ip_rule",         "cmd": "ip rule show"},
            {"label": "ovs_show",        "cmd": "sudo ovs-vsctl show"},
            {"label": "ovs_dpif",        "cmd": "sudo ovs-dpctl show"},
            {"label": "ovs_port_states", "cmd": "sudo ovs-vsctl --format=csv --data=bare --no-headings --columns=name,admin_state,link_state list Interface 2>/dev/null || echo 'unavailable'"},
            {"label": "interfaces",      "cmd": "ip -s link show"},
            {"label": "iface_drops",     "cmd": "ip -s link show | awk '/^[0-9]+:/{split($2,a,\":\");iface=a[1];phase=\"\"} /^    RX:/{phase=\"rx\";next} /^    TX:/{phase=\"tx\";next} phase==\"rx\"&&$4+0>0{rx[iface]+=$4;phase=\"\"} phase==\"tx\"&&$4+0>0{tx[iface]+=$4;phase=\"\"} END{for(i in rx)printf \"%s rx_dropped=%d\\n\",i,rx[i]; for(i in tx)printf \"%s tx_dropped=%d\\n\",i,tx[i]}' 2>/dev/null || true"},
            {"label": "tc_qdisc_drops",  "cmd": (
                "for iface in $(ip -o link show | awk -F': ' '$2!~/lo|gre0|gretap|erspan|ovs-system|^mgmt/{print $2}' | head -12); do"
                " echo \"=== $iface ===\";"
                " tc -s qdisc show dev \"$iface\" 2>/dev/null | grep -E '^qdisc|dropped';"
                " done 2>/dev/null || true"
            )},
            {"label": "ethtool_offload", "cmd": (
                "for iface in $(ip link show | awk -F': ' '/^[0-9]+: data/{print $2}' | cut -d@ -f1 | head -12); do"
                " echo \"=== $iface ===\";"
                " ethtool -k \"$iface\" 2>/dev/null"
                " | grep -E '^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload)\\s*:'"
                " || echo '  unavailable';"
                " done"
            )},
            {"label": "qemu_count",      "cmd": "ps -eo pid,cmd 2>/dev/null | awk '$2~/^(kvm|qemu-system|qemu-kvm)$/' | grep -oP \"(?<=-name ')[^']+|(?<=-name )[^', ]+\" || true"},
            {"label": "fp_stats",        "cmd": "sudo fp-cli stats 2>/dev/null || echo 'fp-cli unavailable'"},
            {"label": "dmesg_errors",    "cmd": "sudo dmesg -T --level=err,crit | tail -30"},
        ],
    },

    "secondary_health": {
        "description": "Secondary compute node health check — services, OVS/VXLAN, routing, system",
        "compute_type": "secondary",
        "commands": [
            {"label": "hostname",        "cmd": "hostname"},
            {"label": "uptime",          "cmd": "uptime"},
            {"label": "cpu_mem",         "cmd": "top -bn1 | head -8"},
            {"label": "disk",            "cmd": "df -h"},
            {"label": "inode_check",     "cmd": "df -i"},
            {"label": "fd_usage",        "cmd": "cat /proc/sys/fs/file-nr"},
            {"label": "mem_pressure",    "cmd": "cat /proc/pressure/memory 2>/dev/null || echo 'unavailable'"},
            {"label": "io_pressure",     "cmd": "cat /proc/pressure/io 2>/dev/null || echo 'unavailable'"},
            {"label": "softnet_stat",    "cmd": "bash -c 'd=0; while read t v rest; do d=$((d+16#v)); done </proc/net/softnet_stat 2>/dev/null; echo \"softnet_dropped=$d\"'"},
            {"label": "conntrack_usage", "cmd": (
                "cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0);"
                " cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0);"
                " echo \"nf_conntrack_count=$cc nf_conntrack_max=$cm\""
            )},
            # Customize: replace service names with your environment's systemd units
            {"label": "services",        "cmd": "systemctl status app-controller.service forwarding-agent.service network-agent.service {ovs} --no-pager".format(ovs=_OVS_SVC)},
            {"label": "tunnel_show",     "cmd": "ip tunnel show"},
            {"label": "vxlan_ports",     "cmd": "sudo ovs-vsctl list-br 2>/dev/null | while read br; do echo \"[$br]\"; sudo ovs-vsctl list-ports \"$br\" 2>/dev/null || true; done"},
            {"label": "ip_route",        "cmd": "ip route show"},
            {"label": "ovs_show",        "cmd": "sudo ovs-vsctl show"},
            {"label": "ovs_flows",       "cmd": "sudo ovs-ofctl dump-flows br-int | head -50"},
            {"label": "ovs_port_states", "cmd": "sudo ovs-vsctl --format=csv --data=bare --no-headings --columns=name,admin_state,link_state list Interface 2>/dev/null || echo 'unavailable'"},
            {"label": "interfaces",      "cmd": "ip -s link show"},
            {"label": "iface_drops",     "cmd": "ip -s link show | awk '/^[0-9]+:/{split($2,a,\":\");iface=a[1];phase=\"\"} /^    RX:/{phase=\"rx\";next} /^    TX:/{phase=\"tx\";next} phase==\"rx\"&&$4+0>0{rx[iface]+=$4;phase=\"\"} phase==\"tx\"&&$4+0>0{tx[iface]+=$4;phase=\"\"} END{for(i in rx)printf \"%s rx_dropped=%d\\n\",i,rx[i]; for(i in tx)printf \"%s tx_dropped=%d\\n\",i,tx[i]}' 2>/dev/null || true"},
            {"label": "tc_qdisc_drops",  "cmd": (
                "for iface in $(ip -o link show | awk -F': ' '$2!~/lo|gre0|gretap|erspan|ovs-system|^mgmt/{print $2}' | head -12); do"
                " echo \"=== $iface ===\";"
                " tc -s qdisc show dev \"$iface\" 2>/dev/null | grep -E '^qdisc|dropped';"
                " done 2>/dev/null || true"
            )},
            {"label": "ethtool_offload", "cmd": (
                "for iface in $(ip link show | awk -F': ' '/^[0-9]+: data/{print $2}' | cut -d@ -f1 | head -12); do"
                " echo \"=== $iface ===\";"
                " ethtool -k \"$iface\" 2>/dev/null"
                " | grep -E '^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload)\\s*:'"
                " || echo '  unavailable';"
                " done"
            )},
            {"label": "dmesg_errors",    "cmd": "sudo dmesg -T --level=err,crit | tail -30"},
        ],
    },

    "tunnel_debug": {
        "description": "Deep tunnel and GRE/VXLAN connectivity debug",
        "compute_type": "ANY",
        "commands": [
            {"label": "hostname",         "cmd": "hostname"},
            {"label": "tunnel_show",      "cmd": "ip tunnel show"},
            {"label": "ip_tun_detail",    "cmd": "ip -d tunnel show"},
            {"label": "gre_interfaces",   "cmd": "ip link show type gre"},
            {"label": "vxlan_interfaces", "cmd": "ip link show type vxlan"},
            {"label": "ip_route",         "cmd": "ip route show"},
            {"label": "ip_rule",          "cmd": "ip rule show"},
            {"label": "arp_table",        "cmd": "arp -n | head -30"},
            {"label": "ping_test",        "cmd": "ping -c 3 -W 1 8.8.8.8 || true"},
            {"label": "ovs_show",         "cmd": "sudo ovs-vsctl show"},
            {"label": "dmesg_net",        "cmd": "sudo dmesg -T | grep -i 'gre\\|vxlan\\|tunnel\\|err' | tail -20"},
        ],
    },

    "ovs_debug": {
        "description": "OVS and datapath deep dive",
        "compute_type": "ANY",
        "commands": [
            {"label": "hostname",       "cmd": "hostname"},
            {"label": "ovs_show",       "cmd": "sudo ovs-vsctl show"},
            {"label": "ovs_bridges",    "cmd": "sudo ovs-vsctl list-br"},
            {"label": "ovs_dpif",       "cmd": "sudo ovs-dpctl show"},
            {"label": "ovs_flows_int",  "cmd": "sudo ovs-ofctl dump-flows br-int 2>/dev/null | wc -l"},
            {"label": "ovs_dpif_stats", "cmd": "sudo ovs-dpctl dump-dps"},
            {"label": "ovs_service",    "cmd": "systemctl status {ovs} --no-pager".format(ovs=_OVS_SVC)},
            {"label": "ovs_version",    "cmd": "ovs-vsctl --version"},
        ],
    },

    "generic_health": {
        "description": "Full health check for any compute node — services, network, drops, OVS, system",
        "compute_type": "ANY",
        "commands": [
            {"label": "hostname",        "cmd": "hostname"},
            {"label": "uptime",          "cmd": "uptime"},
            {"label": "cpu_mem",         "cmd": "top -bn1 | head -8"},
            {"label": "disk",            "cmd": "df -h"},
            {"label": "inode_check",     "cmd": "df -i"},
            {"label": "fd_usage",        "cmd": "cat /proc/sys/fs/file-nr"},
            {"label": "mem_pressure",    "cmd": "cat /proc/pressure/memory 2>/dev/null || echo 'unavailable'"},
            {"label": "io_pressure",     "cmd": "cat /proc/pressure/io 2>/dev/null || echo 'unavailable'"},
            {"label": "softnet_stat",    "cmd": "bash -c 'sum(){ local d=0; while read -r t v r; do [ -n \"$v\" ] && d=$(( d + 16#${v} )) || true; done </proc/net/softnet_stat 2>/dev/null; echo $d; }; t1=$(sum); sleep 5; t2=$(sum); echo \"softnet_dropped=${t2} softnet_recent_delta=$(( t2 - t1 ))\"'"},
            {"label": "conntrack_usage", "cmd": (
                "cc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0);"
                " cm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0);"
                " echo \"nf_conntrack_count=$cc nf_conntrack_max=$cm\""
            )},
            # Customize: replace service names with your environment's systemd units
            {"label": "services",        "cmd": "systemctl status app-controller.service forwarding-agent.service network-agent.service {ovs} --no-pager".format(ovs=_OVS_SVC)},
            {"label": "tunnel_show",     "cmd": "ip tunnel show"},
            {"label": "ip_route",        "cmd": "ip route show"},
            {"label": "ip_rule",         "cmd": "ip rule show"},
            {"label": "ovs_show",        "cmd": "sudo ovs-vsctl show"},
            {"label": "ovs_dpif",        "cmd": "sudo ovs-dpctl show"},
            {"label": "ovs_port_states", "cmd": "sudo ovs-vsctl --format=csv --data=bare --no-headings --columns=name,admin_state,link_state list Interface 2>/dev/null || echo 'unavailable'"},
            {"label": "interfaces",      "cmd": "ip -s link show"},
            {"label": "iface_drops",     "cmd": "ip -s link show | awk '/^[0-9]+:/{split($2,a,\":\");iface=a[1];phase=\"\"} /^    RX:/{phase=\"rx\";next} /^    TX:/{phase=\"tx\";next} phase==\"rx\"&&$4+0>0{rx[iface]+=$4;phase=\"\"} phase==\"tx\"&&$4+0>0{tx[iface]+=$4;phase=\"\"} END{for(i in rx)printf \"%s rx_dropped=%d\\n\",i,rx[i]; for(i in tx)printf \"%s tx_dropped=%d\\n\",i,tx[i]}' 2>/dev/null || true"},
            {"label": "tc_qdisc_drops",  "cmd": (
                "for iface in $(ip -o link show | awk -F': ' '$2!~/lo|gre0|gretap|erspan|ovs-system|^mgmt/{print $2}' | head -12); do"
                " echo \"=== $iface ===\";"
                " tc -s qdisc show dev \"$iface\" 2>/dev/null | grep -E '^qdisc|dropped';"
                " done 2>/dev/null || true"
            )},
            {"label": "ethtool_offload", "cmd": (
                "for iface in $(ip link show | awk -F': ' '/^[0-9]+: data/{print $2}' | cut -d@ -f1 | head -12); do"
                " echo \"=== $iface ===\";"
                " ethtool -k \"$iface\" 2>/dev/null"
                " | grep -E '^(tx-checksumming|tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload)\\s*:'"
                " || echo '  unavailable';"
                " done"
            )},
            {"label": "dmesg_errors",    "cmd": "sudo dmesg -T --level=err,crit | tail -30"},
        ],
    },

    "quick_check": {
        "description": "Fast triage — services, tunnels, disk in under 10 seconds",
        "compute_type": "ANY",
        "commands": [
            {"label": "hostname",     "cmd": "hostname"},
            {"label": "uptime",       "cmd": "uptime"},
            # Customize: replace service names with your environment's systemd units
            {"label": "services",     "cmd": "systemctl is-active app-controller.service forwarding-agent.service network-agent.service {ovs}".format(ovs=_OVS_SVC)},
            {"label": "tunnel_show",  "cmd": "ip tunnel show"},
            {"label": "disk",         "cmd": "df -h | grep -v tmpfs"},
            {"label": "inode_check",  "cmd": "df -i | grep -v tmpfs"},
            {"label": "mem",          "cmd": "free -h"},
            {"label": "fd_usage",     "cmd": "cat /proc/sys/fs/file-nr"},
        ],
    },

    "log_collection": {
        "description": "Collect service logs, kernel errors, OVS logs, and system journal for triage",
        "compute_type": "ANY",
        "commands": [
            {"label": "hostname",          "cmd": "hostname"},
            {"label": "os_version",        "cmd": "cat /etc/os-release | grep -E '^(NAME|VERSION)='"},
            {"label": "journal_errors",    "cmd": "sudo journalctl -p err..crit --since '2 hours ago' --no-pager -o short-iso | tail -100"},
            # Customize: replace service names with your environment's systemd units
            {"label": "journal_svc1",      "cmd": "sudo journalctl -u app-controller.service --since '2 hours ago' --no-pager | tail -80"},
            {"label": "journal_svc2",      "cmd": "sudo journalctl -u forwarding-agent.service --since '2 hours ago' --no-pager | tail -80"},
            {"label": "journal_svc3",      "cmd": "sudo journalctl -u network-agent.service --since '2 hours ago' --no-pager | tail -80"},
            {"label": "journal_ovs",       "cmd": "sudo journalctl -u {ovs} --since '2 hours ago' --no-pager | tail -80".format(ovs=_OVS_SVC)},
            {"label": "ovs_log_file",      "cmd": "sudo tail -100 /var/log/openvswitch/ovs-vswitchd.log 2>/dev/null || echo 'OVS log file not found'"},
            {"label": "dmesg_errors",      "cmd": "sudo dmesg -T --level=err,crit,warn | tail -50"},
            {"label": "dmesg_oom",         "cmd": "sudo dmesg -T | grep -i 'oom\\|killed process\\|out of memory' | tail -30"},
            {"label": "dmesg_net",         "cmd": "sudo dmesg -T | grep -iE 'gre|vxlan|tunnel|openvswitch|ovs' | tail -30"},
            {"label": "journal_fastpath",  "cmd": "sudo journalctl -u fast-path.service --since '2 hours ago' --no-pager | tail -50"},
            {"label": "syslog_errors",     "cmd": "sudo grep -iE 'error|crit|panic|emerg|alert' /var/log/syslog 2>/dev/null | tail -50 || sudo grep -iE 'error|crit|panic' /var/log/messages 2>/dev/null | tail -50 || echo 'syslog not found'"},
            {"label": "failed_units",      "cmd": "systemctl list-units --state=failed --no-legend 2>/dev/null"},
        ],
    },

    "fastpath_debug": {
        "description": "Fastpath / fp-cli health check (DPDK-based primary nodes)",
        "compute_type": "primary",
        "commands": [
            {"label": "hostname",     "cmd": "hostname"},
            {"label": "fp_service",   "cmd": "systemctl status fast-path.service --no-pager"},
            {"label": "fp_procs",     "cmd": "ps aux | grep -E 'fp-rte|fpmd|hitflagsd|cmgrd|fpsd' | grep -v grep"},
            {"label": "fp_affinity",  "cmd": "sudo fp-cli cpu affinity list 2>/dev/null || echo 'fp-cli unavailable'"},
            {"label": "fp_stats",     "cmd": "sudo fp-cli stats 2>/dev/null || echo 'fp-cli unavailable'"},
            {"label": "fp_dpdk",      "cmd": "sudo fp-cli dpdk stats 2>/dev/null || echo 'fp-cli unavailable'"},
        ],
    },
}
