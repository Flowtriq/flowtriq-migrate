"""Parse DDoS platform configuration files (FastNetMon, Wanguard, Corero)."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

# Vendor constants
VENDOR_FASTNETMON = "fastnetmon"
VENDOR_WANGUARD = "wanguard"
VENDOR_CORERO = "corero"


def parse_config(
    path: str,
    networks_file: Optional[str] = None,
    vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """Parse a DDoS platform config file and return a normalized dict.

    Supports FastNetMon (Community INI / Advanced JSON), Wanguard (JSON export),
    and Corero SmartWall (JSON API export).

    If vendor is None, auto-detects the platform from the file contents.
    """
    with open(path, "r") as f:
        raw = f.read()

    # Explicit vendor override
    if vendor:
        v = vendor.lower().replace(" ", "").replace("-", "").replace("_", "")
        if v in ("wanguard", "andrisoft"):
            data = json.loads(raw)
            return _normalize_wanguard(data, path, networks_file)
        elif v in ("corero", "smartwall"):
            data = json.loads(raw)
            return _normalize_corero(data, path)
        elif v in ("fastnetmon", "fnm"):
            pass  # fall through to FastNetMon auto-detect
        else:
            pass  # unknown vendor, try auto-detect

    # Try JSON first
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            # Detect vendor from JSON structure
            detected = _detect_json_vendor(data)
            if detected == VENDOR_WANGUARD:
                return _normalize_wanguard(data, path, networks_file)
            elif detected == VENDOR_CORERO:
                return _normalize_corero(data, path)
            else:
                return _normalize_advanced(data, path, networks_file)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to INI-style key=value (FastNetMon Community)
    return _normalize_community(raw, path, networks_file)


def _detect_json_vendor(data: Dict[str, Any]) -> str:
    """Detect vendor from JSON config structure."""
    # Wanguard: has "vendor": "wanguard" or sensor/filter/console keys
    if data.get("vendor", "").lower() in ("wanguard", "andrisoft"):
        return VENDOR_WANGUARD
    if any(k in data for k in ("sensors", "filters", "anomaly_profiles", "sensor_type")):
        return VENDOR_WANGUARD

    # Corero: has "vendor": "corero" or protection_profiles/smart_rules/managed_objects
    if data.get("vendor", "").lower() in ("corero", "smartwall"):
        return VENDOR_CORERO
    if any(k in data for k in ("protection_profiles", "smart_rules", "managed_objects")):
        return VENDOR_CORERO

    # Default: FastNetMon Advanced
    return VENDOR_FASTNETMON


# ---------------------------------------------------------------------------
# Community edition parser
# ---------------------------------------------------------------------------

_BOOL_TRUE = {"on", "yes", "true", "1", "enable", "enabled"}
_BOOL_FALSE = {"off", "no", "false", "0", "disable", "disabled"}


def _coerce_value(val: str) -> Any:
    """Convert a string value to its Python type."""
    low = val.lower().strip()
    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False
    # Try int
    try:
        return int(val)
    except ValueError:
        pass
    # Try float
    try:
        return float(val)
    except ValueError:
        pass
    return val.strip()


def _parse_ini(raw: str) -> Dict[str, Any]:
    """Parse FastNetMon Community INI-style config into a flat dict."""
    result: Dict[str, Any] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Handle key = value  (or key=value)
        m = re.match(r"^([a-zA-Z0-9_./-]+)\s*=\s*(.*?)$", line)
        if not m:
            continue
        key = m.group(1).strip()
        val = m.group(2).strip()
        # Strip inline comments
        if " #" in val:
            val = val[: val.index(" #")].strip()
        result[key] = _coerce_value(val)
    return result


def _read_networks_file(path: str) -> List[str]:
    """Read a networks_list file (one CIDR per line)."""
    networks: List[str] = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    networks.append(line)
    except (OSError, IOError):
        pass
    return networks


def _normalize_community(
    raw: str, config_path: str, networks_file: Optional[str]
) -> Dict[str, Any]:
    """Normalize Community config into the standard parsed structure."""
    flat = _parse_ini(raw)
    config_dir = os.path.dirname(os.path.abspath(config_path))

    result: Dict[str, Any] = {"edition": "community", "_raw": flat}

    # Interfaces
    ifaces = flat.get("interfaces", flat.get("listen_interfaces", ""))
    if isinstance(ifaces, str):
        result["interfaces"] = [s.strip() for s in ifaces.split(",") if s.strip()]
    else:
        result["interfaces"] = [str(ifaces)]

    # Thresholds
    result["thresholds"] = {
        "pps": flat.get("ban_for_pps", flat.get("threshold_pps", 0)),
        "mbps": flat.get("ban_for_bandwidth", flat.get("threshold_mbps", 0)),
        "flows": flat.get("ban_for_flows", flat.get("threshold_flows", 0)),
    }

    # Ban / mitigation
    result["ban"] = {
        "enabled": flat.get("enable_ban", False),
        "time": flat.get("ban_time", 1900),
        "unban_only_if_attack_finished": flat.get(
            "unban_only_if_attack_finished", False
        ),
    }

    # Collection method
    result["collection"] = {
        "mirror": flat.get("mirror", False),
        "mirror_afpacket": flat.get("mirror_afpacket", False),
        "mirror_netmap": flat.get("mirror_netmap", False),
        "netflow": flat.get("netflow", False),
        "sflow": flat.get("sflow", False),
        "netflow_port": flat.get("netflow_port", 2055),
        "sflow_port": flat.get("sflow_port", 6343),
        "netflow_host": flat.get("netflow_host", "0.0.0.0"),
        "sflow_host": flat.get("sflow_host", "0.0.0.0"),
    }

    # Networks
    nets_path = networks_file
    if not nets_path:
        nets_path = flat.get(
            "networks_list", flat.get("networks_list_path", "")
        )
        if isinstance(nets_path, str) and nets_path and not os.path.isabs(nets_path):
            nets_path = os.path.join(config_dir, nets_path)
    result["networks_list_path"] = nets_path or ""
    result["networks"] = _read_networks_file(nets_path) if nets_path else []

    # Notification
    result["notify_script"] = str(flat.get("notify_script_path", ""))
    result["notify_script_pass_details"] = flat.get(
        "notify_script_pass_details", False
    )

    # Graphite / InfluxDB (rarely used in Community, but some configs have it)
    result["graphite"] = {
        "enabled": flat.get("graphite", False),
        "host": str(flat.get("graphite_host", "")),
        "port": flat.get("graphite_port", 2003),
        "prefix": str(flat.get("graphite_prefix", "fastnetmon")),
    }

    # ExaBGP
    result["exabgp"] = {
        "enabled": flat.get("exabgp", False),
        "community": str(flat.get("exabgp_community", "")),
        "next_hop": str(flat.get("exabgp_next_hop", "")),
        "announce_host": str(flat.get("exabgp_announce_host", "")),
        "announce_port": flat.get("exabgp_announce_port", 5555),
    }

    # GoBGP
    result["gobgp"] = {
        "enabled": flat.get("gobgp", False),
        "next_hop": str(flat.get("gobgp_next_hop", "")),
        "announce_host": str(flat.get("gobgp_announce_host", "")),
        "announce_port": flat.get("gobgp_announce_port", 50051),
        "community": str(flat.get("gobgp_community", "")),
    }

    return result


# ---------------------------------------------------------------------------
# Advanced edition parser
# ---------------------------------------------------------------------------


def _normalize_advanced(
    data: Dict[str, Any], config_path: str, networks_file: Optional[str]
) -> Dict[str, Any]:
    """Normalize Advanced (JSON) config into the standard parsed structure."""
    config_dir = os.path.dirname(os.path.abspath(config_path))

    result: Dict[str, Any] = {"edition": "advanced", "_raw": data}

    # Interfaces
    ifaces = data.get("interfaces", data.get("listen_interfaces", []))
    if isinstance(ifaces, str):
        result["interfaces"] = [s.strip() for s in ifaces.split(",") if s.strip()]
    elif isinstance(ifaces, list):
        result["interfaces"] = ifaces
    else:
        result["interfaces"] = [str(ifaces)]

    # Thresholds (may be nested under "main" or top-level)
    main = data.get("main", data)
    result["thresholds"] = {
        "pps": main.get("ban_for_pps", main.get("threshold_pps", 0)),
        "mbps": main.get(
            "ban_for_bandwidth", main.get("threshold_mbps", 0)
        ),
        "flows": main.get("ban_for_flows", main.get("threshold_flows", 0)),
    }

    # Per-host thresholds (Advanced feature)
    hostgroups = data.get("hostgroups", data.get("host_groups", {}))
    if hostgroups:
        result["hostgroups"] = hostgroups

    # Ban / mitigation
    result["ban"] = {
        "enabled": main.get("enable_ban", False),
        "time": main.get("ban_time", 1900),
        "unban_only_if_attack_finished": main.get(
            "unban_only_if_attack_finished", False
        ),
    }

    # Collection method
    result["collection"] = {
        "mirror": main.get("mirror", False),
        "mirror_afpacket": main.get("mirror_afpacket", False),
        "mirror_netmap": main.get("mirror_netmap", False),
        "netflow": main.get("netflow", False),
        "sflow": main.get("sflow", False),
        "netflow_port": main.get("netflow_port", 2055),
        "sflow_port": main.get("sflow_port", 6343),
        "netflow_host": main.get("netflow_host", "0.0.0.0"),
        "sflow_host": main.get("sflow_host", "0.0.0.0"),
    }

    # Networks
    nets_path = networks_file
    if not nets_path:
        nets_path = main.get(
            "networks_list", main.get("networks_list_path", "")
        )
        if isinstance(nets_path, str) and nets_path and not os.path.isabs(nets_path):
            nets_path = os.path.join(config_dir, nets_path)
    result["networks_list_path"] = nets_path or ""
    result["networks"] = _read_networks_file(nets_path) if nets_path else []

    # Notification
    result["notify_script"] = str(main.get("notify_script_path", ""))
    result["notify_script_pass_details"] = main.get(
        "notify_script_pass_details", False
    )

    # Email (Advanced feature)
    email_cfg = data.get("email", {})
    if not email_cfg:
        email_cfg = {
            k.replace("email_", "", 1): v
            for k, v in main.items()
            if k.startswith("email_")
        }
    if email_cfg:
        result["email"] = {
            "enabled": email_cfg.get("enabled", bool(email_cfg)),
            "from": email_cfg.get("from", email_cfg.get("from_address", "")),
            "to": email_cfg.get("to", email_cfg.get("to_address", "")),
            "smtp_host": email_cfg.get("smtp_host", email_cfg.get("host", "")),
            "smtp_port": email_cfg.get("smtp_port", email_cfg.get("port", 25)),
        }

    # Graphite / InfluxDB
    result["graphite"] = {
        "enabled": main.get("graphite", False),
        "host": str(main.get("graphite_host", "")),
        "port": main.get("graphite_port", 2003),
        "prefix": str(main.get("graphite_prefix", "fastnetmon")),
    }
    influx = data.get("influxdb", {})
    if not influx:
        influx = {
            k.replace("influxdb_", "", 1): v
            for k, v in main.items()
            if k.startswith("influxdb_")
        }
    if influx:
        result["influxdb"] = {
            "enabled": influx.get("enabled", bool(influx)),
            "host": influx.get("host", ""),
            "port": influx.get("port", 8086),
            "database": influx.get("database", influx.get("db", "fastnetmon")),
        }

    # ExaBGP
    exabgp = data.get("exabgp", {})
    if not exabgp:
        exabgp = {
            k.replace("exabgp_", "", 1): v
            for k, v in main.items()
            if k.startswith("exabgp_")
        }
    result["exabgp"] = {
        "enabled": exabgp.get("enabled", main.get("exabgp", False)),
        "community": str(exabgp.get("community", "")),
        "next_hop": str(exabgp.get("next_hop", "")),
        "announce_host": str(exabgp.get("announce_host", "")),
        "announce_port": exabgp.get("announce_port", 5555),
    }

    # GoBGP
    gobgp = data.get("gobgp", {})
    if not gobgp:
        gobgp = {
            k.replace("gobgp_", "", 1): v
            for k, v in main.items()
            if k.startswith("gobgp_")
        }
    result["gobgp"] = {
        "enabled": gobgp.get("enabled", main.get("gobgp", False)),
        "next_hop": str(gobgp.get("next_hop", "")),
        "announce_host": str(gobgp.get("announce_host", "")),
        "announce_port": gobgp.get("announce_port", 50051),
        "community": str(gobgp.get("community", "")),
    }

    return result


# ---------------------------------------------------------------------------
# Wanguard (Andrisoft) parser
# ---------------------------------------------------------------------------
# Wanguard stores config in a database behind a web console. There is no
# standard config file. We accept a JSON document that operators fill in
# from their Console settings, or export via database queries.
#
# Expected JSON structure:
# {
#   "vendor": "wanguard",
#   "sensors": [{"type": "netflow"|"sflow"|"packet", "interface": "...", "port": 2055}],
#   "thresholds": {"pps": 50000, "mbps": 2048},
#   "networks": ["10.0.0.0/24"],
#   "bgp": {"enabled": true, "community": "65001:666", "next_hop": "192.0.2.1"},
#   "alerts": {"email": "noc@example.com", "snmp_trap": "10.0.0.50", "script": "/path"},
#   "anomaly_profiles": [{"name": "default", "threshold_pps": 50000}],
#   "filter": {"enabled": true, "type": "flowspec"|"rtbh"|"iptables"},
#   "ban_time": 1800
# }


def _normalize_wanguard(
    data: Dict[str, Any],
    config_path: str,
    networks_file: Optional[str],
) -> Dict[str, Any]:
    """Normalize Wanguard JSON export into the standard parsed structure."""
    config_dir = os.path.dirname(os.path.abspath(config_path))
    result: Dict[str, Any] = {"edition": "wanguard", "_raw": data}

    # Sensors -> interfaces and collection
    sensors = data.get("sensors", [])
    ifaces = []
    coll = {
        "mirror": False, "mirror_afpacket": False, "mirror_netmap": False,
        "netflow": False, "sflow": False,
        "netflow_port": 2055, "sflow_port": 6343,
        "netflow_host": "0.0.0.0", "sflow_host": "0.0.0.0",
    }
    for sensor in sensors:
        stype = str(sensor.get("type", sensor.get("sensor_type", ""))).lower()
        iface = sensor.get("interface", "")
        if iface and iface not in ifaces:
            ifaces.append(iface)
        if stype in ("netflow", "netflow_v5", "netflow_v9", "ipfix"):
            coll["netflow"] = True
            coll["netflow_port"] = sensor.get("port", sensor.get("listen_port", 2055))
        elif stype == "sflow":
            coll["sflow"] = True
            coll["sflow_port"] = sensor.get("port", sensor.get("listen_port", 6343))
        elif stype in ("packet", "packet_capture", "pf_ring", "dpdk", "af_packet"):
            coll["mirror"] = True
            coll["mirror_afpacket"] = True

    # If no sensors defined, check top-level sensor_type
    if not sensors:
        stype = str(data.get("sensor_type", "")).lower()
        if stype in ("netflow", "netflow_v5", "netflow_v9", "ipfix"):
            coll["netflow"] = True
            coll["netflow_port"] = data.get("netflow_port", data.get("listen_port", 2055))
        elif stype == "sflow":
            coll["sflow"] = True
            coll["sflow_port"] = data.get("sflow_port", data.get("listen_port", 6343))
        elif stype in ("packet", "pf_ring", "dpdk"):
            coll["mirror"] = True
            coll["mirror_afpacket"] = True

    iface_str = data.get("interface", data.get("interfaces", ""))
    if isinstance(iface_str, str) and iface_str and iface_str not in ifaces:
        ifaces.append(iface_str)
    elif isinstance(iface_str, list):
        for i in iface_str:
            if i not in ifaces:
                ifaces.append(i)

    result["interfaces"] = ifaces
    result["collection"] = coll

    # Thresholds
    thresh = data.get("thresholds", {})
    if not thresh:
        # Try anomaly_profiles
        profiles = data.get("anomaly_profiles", [])
        if profiles:
            p = profiles[0] if isinstance(profiles, list) else profiles
            thresh = {
                "pps": p.get("threshold_pps", p.get("pps", 0)),
                "mbps": p.get("threshold_mbps", p.get("mbps", 0)),
            }
    result["thresholds"] = {
        "pps": thresh.get("pps", thresh.get("threshold_pps", 0)),
        "mbps": thresh.get("mbps", thresh.get("threshold_mbps", 0)),
        "flows": thresh.get("flows", 0),
    }

    # Ban / mitigation (Wanguard Filter)
    filt = data.get("filter", {})
    result["ban"] = {
        "enabled": filt.get("enabled", bool(filt)),
        "time": data.get("ban_time", filt.get("ban_time", 1800)),
        "unban_only_if_attack_finished": False,
    }
    result["filter_type"] = filt.get("type", "")

    # Networks
    nets = data.get("networks", data.get("subnets", data.get("prefixes", [])))
    if isinstance(nets, str):
        nets = [s.strip() for s in nets.split(",") if s.strip()]
    nets_from_file = []
    if networks_file:
        nets_from_file = _read_networks_file(networks_file)
    elif not nets:
        npath = data.get("networks_file", "")
        if npath:
            if not os.path.isabs(npath):
                npath = os.path.join(config_dir, npath)
            nets_from_file = _read_networks_file(npath)
    result["networks"] = nets or nets_from_file
    result["networks_list_path"] = ""

    # Notification / alerts
    alerts = data.get("alerts", data.get("notifications", {}))
    result["notify_script"] = str(alerts.get("script", ""))
    if alerts.get("email"):
        result["email"] = {
            "enabled": True,
            "to": alerts["email"],
            "from": alerts.get("from", ""),
            "smtp_host": alerts.get("smtp_host", alerts.get("smtp", "")),
            "smtp_port": alerts.get("smtp_port", 25),
        }
    if alerts.get("snmp_trap"):
        result["snmp"] = {
            "enabled": True,
            "host": alerts["snmp_trap"],
            "community": alerts.get("snmp_community", "public"),
        }

    # BGP
    bgp = data.get("bgp", {})
    result["exabgp"] = {
        "enabled": bgp.get("enabled", False),
        "community": str(bgp.get("community", "")),
        "next_hop": str(bgp.get("next_hop", "")),
        "announce_host": str(bgp.get("announce_host", bgp.get("peer", ""))),
        "announce_port": bgp.get("announce_port", bgp.get("port", 5555)),
    }
    result["gobgp"] = {"enabled": False}
    result["graphite"] = {"enabled": False}

    return result


# ---------------------------------------------------------------------------
# Corero SmartWall parser
# ---------------------------------------------------------------------------
# Corero configs come from the CMS REST API (JSON) or CLI show commands.
# We accept JSON from the API or a structured JSON export.
#
# Expected JSON structure:
# {
#   "vendor": "corero",
#   "protection_profiles": [
#     {
#       "name": "default",
#       "smart_rules": [
#         {"type": "service"|"reflection"|"server", "protocol": "udp",
#          "threshold_pps": 50000, "rate_limit_pps": 0, "action": "drop"}
#       ]
#     }
#   ],
#   "managed_objects": [
#     {"name": "Web Servers", "prefixes": ["10.0.0.0/24"], "profile": "default"}
#   ],
#   "deployment_mode": "inline"|"out_of_band",
#   "interfaces": ["eth0", "eth1"],
#   "bgp": {"enabled": true, "type": "rtbh"|"flowspec", "community": "65001:666",
#           "next_hop": "192.0.2.1", "peer": "10.0.0.1"},
#   "alerts": {
#     "syslog": {"enabled": true, "host": "10.0.0.50", "port": 514},
#     "snmp": {"enabled": true, "host": "10.0.0.50", "community": "public"},
#     "email": "noc@example.com",
#     "webhook": "https://hooks.example.com/alerts"
#   }
# }


def _normalize_corero(
    data: Dict[str, Any],
    config_path: str,
) -> Dict[str, Any]:
    """Normalize Corero SmartWall JSON export into the standard parsed structure."""
    result: Dict[str, Any] = {"edition": "corero", "_raw": data}

    # Interfaces
    ifaces = data.get("interfaces", [])
    if isinstance(ifaces, str):
        ifaces = [s.strip() for s in ifaces.split(",") if s.strip()]
    result["interfaces"] = ifaces

    # Deployment mode
    result["deployment_mode"] = data.get("deployment_mode", "inline")

    # Collection -- Corero is inline hardware, not flow-based
    result["collection"] = {
        "mirror": False, "mirror_afpacket": False, "mirror_netmap": False,
        "netflow": False, "sflow": False,
        "netflow_port": 2055, "sflow_port": 6343,
        "netflow_host": "0.0.0.0", "sflow_host": "0.0.0.0",
        "inline": result["deployment_mode"] == "inline",
    }

    # Protection profiles -> thresholds
    profiles = data.get("protection_profiles", [])
    rules = []
    max_pps = 0
    max_mbps = 0
    for profile in profiles:
        smart_rules = profile.get("smart_rules", profile.get("rules", []))
        for rule in smart_rules:
            rules.append(rule)
            pps = rule.get("threshold_pps", rule.get("threshold", 0))
            mbps = rule.get("threshold_mbps", 0)
            if pps > max_pps:
                max_pps = pps
            if mbps > max_mbps:
                max_mbps = mbps

    result["thresholds"] = {
        "pps": max_pps or data.get("threshold_pps", 0),
        "mbps": max_mbps or data.get("threshold_mbps", 0),
        "flows": 0,
    }
    result["protection_profiles"] = profiles
    result["smart_rules_count"] = len(rules)

    # Managed objects -> networks
    managed = data.get("managed_objects", [])
    networks = []
    for obj in managed:
        prefixes = obj.get("prefixes", obj.get("networks", obj.get("subnets", [])))
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        networks.extend(prefixes)
    if not networks:
        networks = data.get("networks", data.get("prefixes", []))
        if isinstance(networks, str):
            networks = [s.strip() for s in networks.split(",") if s.strip()]
    result["networks"] = networks
    result["networks_list_path"] = ""
    result["managed_objects_count"] = len(managed)

    # Ban / mitigation
    has_drop = any(
        r.get("action", "").lower() in ("drop", "rate-limit", "rate_limit", "police")
        for r in rules
    )
    result["ban"] = {
        "enabled": has_drop,
        "time": data.get("ban_time", 0),
        "unban_only_if_attack_finished": False,
    }

    # Alerts
    alerts = data.get("alerts", data.get("notifications", {}))
    result["notify_script"] = ""

    if isinstance(alerts, dict):
        # Syslog
        syslog = alerts.get("syslog", {})
        if syslog and syslog.get("enabled", True):
            result["syslog"] = {
                "enabled": True,
                "host": syslog.get("host", ""),
                "port": syslog.get("port", 514),
            }

        # SNMP
        snmp = alerts.get("snmp", {})
        if snmp and snmp.get("enabled", True):
            result["snmp"] = {
                "enabled": True,
                "host": snmp.get("host", ""),
                "community": snmp.get("community", "public"),
            }

        # Email
        email_val = alerts.get("email", "")
        if email_val:
            addr = email_val if isinstance(email_val, str) else email_val.get("to", "")
            result["email"] = {
                "enabled": True,
                "to": addr,
                "from": "",
                "smtp_host": "",
                "smtp_port": 25,
            }

        # Webhook
        webhook = alerts.get("webhook", "")
        if webhook:
            result["webhook"] = webhook

    # BGP
    bgp = data.get("bgp", {})
    result["exabgp"] = {
        "enabled": bgp.get("enabled", False),
        "community": str(bgp.get("community", "")),
        "next_hop": str(bgp.get("next_hop", "")),
        "announce_host": str(bgp.get("peer", bgp.get("announce_host", ""))),
        "announce_port": bgp.get("port", bgp.get("announce_port", 179)),
    }
    result["bgp_type"] = bgp.get("type", "")  # "rtbh" or "flowspec"
    result["gobgp"] = {"enabled": False}
    result["graphite"] = {"enabled": False}

    return result
