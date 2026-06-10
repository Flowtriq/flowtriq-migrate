"""Map parsed FastNetMon config to a Flowtriq ftagent configuration."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple

# Flowtriq ftagent default config — mirrors ftagent/agent.py DEFAULT_CONFIG
FLOWTRIQ_DEFAULTS = {
    "api_key": "",
    "node_uuid": "",
    "api_base": "https://flowtriq.com/api/v1",
    "interface": "auto",
    "pcap_enabled": True,
    "pcap_mode": "tcpdump",
    "pcap_dir": "/var/lib/ftagent/pcaps",
    "log_file": "/var/log/ftagent.log",
    "log_level": "INFO",
    "dynamic_threshold": True,
    "baseline_window": 300,
    "health_port": 9100,
    "auto_update": True,
    "flow_enabled": False,
    "flow_protocol": "auto",
    "flow_port": 0,
    "flow_bind": "0.0.0.0",
    "flow_sample_rate": 0,
    "flow_source_ips": [],
    "gre_mode": "auto",
    "gre_max_depth": 3,
    "hypervisor_mode": False,
    "vm_labels": {},
    "mirror_mode": False,
    "mirror_interface": "",
    "mirror_subnets": [],
    "mirror_ip_labels": {},
    "mirror_capture_mode": "af_packet",
    "heartbeat_interval": 30,
    "metrics_interval": 10,
}


def map_to_flowtriq(
    parsed: Dict[str, Any],
    api_key: str = "",
    node_uuid: str = "",
) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Convert parsed FastNetMon config to a Flowtriq ftagent config.

    Returns (config_dict, notes) where notes is a list of
    {"type": "mapped"|"manual"|"info", "message": str} entries.
    """
    config = copy.deepcopy(FLOWTRIQ_DEFAULTS)
    notes: List[Dict[str, str]] = []

    # Credentials
    config["api_key"] = api_key or "YOUR_API_KEY_HERE"
    config["node_uuid"] = node_uuid or "YOUR_NODE_UUID_HERE"

    # --- Interface ---
    interfaces = parsed.get("interfaces", [])
    if interfaces:
        config["interface"] = interfaces[0]
        notes.append({
            "type": "mapped",
            "message": f"Interface: {interfaces[0]}",
        })
        if len(interfaces) > 1:
            notes.append({
                "type": "info",
                "message": (
                    f"FastNetMon had {len(interfaces)} interfaces configured "
                    f"({', '.join(interfaces)}). Flowtriq uses one agent per "
                    "server — deploy ftagent on each server individually."
                ),
            })

    # --- Collection mode ---
    coll = parsed.get("collection", {})

    if coll.get("sflow"):
        config["flow_enabled"] = True
        config["flow_protocol"] = "sflow"
        config["flow_port"] = coll.get("sflow_port", 6343)
        if coll.get("sflow_host", "0.0.0.0") != "0.0.0.0":
            config["flow_bind"] = coll["sflow_host"]
        notes.append({
            "type": "mapped",
            "message": f"sFlow collection on port {config['flow_port']}",
        })
    elif coll.get("netflow"):
        config["flow_enabled"] = True
        config["flow_protocol"] = "netflow_v5"
        config["flow_port"] = coll.get("netflow_port", 2055)
        if coll.get("netflow_host", "0.0.0.0") != "0.0.0.0":
            config["flow_bind"] = coll["netflow_host"]
        notes.append({
            "type": "mapped",
            "message": f"NetFlow collection on port {config['flow_port']}",
        })
    elif coll.get("mirror"):
        config["mirror_mode"] = True
        if interfaces:
            config["mirror_interface"] = interfaces[0]
        if coll.get("mirror_afpacket"):
            config["mirror_capture_mode"] = "af_packet"
        notes.append({
            "type": "mapped",
            "message": (
                f"Mirror/SPAN mode (AF_PACKET) on {config['mirror_interface']}"
            ),
        })
        if coll.get("mirror_netmap"):
            notes.append({
                "type": "info",
                "message": (
                    "FastNetMon netmap mode detected. Flowtriq uses AF_PACKET "
                    "for mirror capture, which provides comparable performance "
                    "without kernel module dependencies."
                ),
            })
    else:
        notes.append({
            "type": "mapped",
            "message": (
                "Agent mode (per-packet monitoring on the server itself)"
            ),
        })

    # --- Networks ---
    networks = parsed.get("networks", [])
    if networks:
        if config["mirror_mode"]:
            config["mirror_subnets"] = networks
            notes.append({
                "type": "mapped",
                "message": (
                    f"Monitored subnets: {', '.join(networks)}"
                ),
            })
        else:
            notes.append({
                "type": "info",
                "message": (
                    f"Networks list ({', '.join(networks)}) noted. In agent "
                    "mode, Flowtriq monitors the server's own traffic "
                    "automatically — no network list needed."
                ),
            })

    # --- Thresholds ---
    thresholds = parsed.get("thresholds", {})
    pps = thresholds.get("pps", 0)
    mbps = thresholds.get("mbps", 0)
    flows = thresholds.get("flows", 0)

    config["dynamic_threshold"] = True
    threshold_parts = []
    if pps:
        threshold_parts.append(f"{pps:,} PPS")
    if mbps:
        threshold_parts.append(f"{mbps:,} Mbps")
    if flows:
        threshold_parts.append(f"{flows:,} flows")

    if threshold_parts:
        notes.append({
            "type": "mapped",
            "message": (
                f"FastNetMon static thresholds: {', '.join(threshold_parts)}. "
                "Flowtriq uses adaptive baselining instead — the agent learns "
                "your normal traffic pattern and alerts at 3.0x baseline. This "
                "eliminates false positives from legitimate traffic spikes and "
                "catches attacks that stay below a static threshold."
            ),
        })

    if flows:
        notes.append({
            "type": "info",
            "message": (
                "Flow-count threshold (ban_for_flows) has no direct Flowtriq "
                "equivalent. Flowtriq's per-packet analysis provides deeper "
                "visibility than flow counting."
            ),
        })

    # --- Ban / mitigation ---
    ban = parsed.get("ban", {})
    if ban.get("enabled"):
        notes.append({
            "type": "manual",
            "message": (
                "FastNetMon ban/mitigation was enabled "
                f"(ban_time: {ban.get('time', 1900)}s). Configure "
                "auto-mitigation rules in your Flowtriq dashboard: "
                "iptables, nftables, XDP/eBPF, BGP FlowSpec, or RTBH."
            ),
        })

    # --- Notification ---
    notify = parsed.get("notify_script", "")
    if notify:
        notes.append({
            "type": "manual",
            "message": (
                f"FastNetMon notify script: {notify}\n"
                "     Configure alert channels in your Flowtriq dashboard:\n"
                "     Slack, Discord, PagerDuty, OpsGenie, email, SMS, "
                "Telegram, webhook, and more."
            ),
        })

    # --- BGP ---
    exabgp = parsed.get("exabgp", {})
    gobgp = parsed.get("gobgp", {})
    if exabgp.get("enabled"):
        community = exabgp.get("community", "")
        next_hop = exabgp.get("next_hop", "")
        parts = ["ExaBGP integration detected"]
        if community:
            parts.append(f"community {community}")
        if next_hop:
            parts.append(f"next-hop {next_hop}")
        notes.append({
            "type": "manual",
            "message": (
                f"{', '.join(parts)}. "
                "Configure BGP mitigation (FlowSpec/RTBH) in your Flowtriq "
                "dashboard. Flowtriq supports ExaBGP, GoBGP, BIRD 2, and "
                "FRRouting as BGP adapters — your existing BGP sessions "
                "stay unchanged."
            ),
        })
    elif gobgp.get("enabled"):
        notes.append({
            "type": "manual",
            "message": (
                "GoBGP integration detected. Configure BGP mitigation in "
                "your Flowtriq dashboard — GoBGP is natively supported."
            ),
        })

    # --- Email (Advanced) ---
    email = parsed.get("email", {})
    if email.get("enabled"):
        notes.append({
            "type": "manual",
            "message": (
                f"Email alerts configured (SMTP: {email.get('smtp_host', '')}). "
                "Add an email alert channel in your Flowtriq dashboard — "
                "built-in, no SMTP configuration needed."
            ),
        })

    # --- Graphite / InfluxDB ---
    graphite = parsed.get("graphite", {})
    if graphite.get("enabled"):
        notes.append({
            "type": "info",
            "message": (
                f"Graphite export to {graphite.get('host', '')} detected. "
                "Flowtriq includes a built-in real-time dashboard. For "
                "external metrics, use webhook alerts to feed custom pipelines."
            ),
        })

    influx = parsed.get("influxdb", {})
    if influx.get("enabled"):
        notes.append({
            "type": "info",
            "message": (
                f"InfluxDB export to {influx.get('host', '')} detected. "
                "Flowtriq's API provides full metrics access for SIEM and "
                "observability integrations."
            ),
        })

    # --- Per-host thresholds (Advanced) ---
    hostgroups = parsed.get("hostgroups", {})
    if hostgroups:
        notes.append({
            "type": "info",
            "message": (
                f"Per-host threshold groups detected ({len(hostgroups)} groups). "
                "Flowtriq supports per-node thresholds natively — each server "
                "runs its own agent with independent baselines."
            ),
        })

    # --- Strip internal keys from output ---
    output = {k: v for k, v in config.items() if not k.startswith("_")}

    return output, notes
