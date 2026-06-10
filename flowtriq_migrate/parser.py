"""Parse FastNetMon Community and Advanced configuration files."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional


def parse_config(path: str, networks_file: Optional[str] = None) -> Dict[str, Any]:
    """Parse a FastNetMon config file and return a normalized dict.

    Auto-detects Community (INI-style key=value) vs Advanced (JSON) format.
    """
    with open(path, "r") as f:
        raw = f.read()

    # Try JSON first (Advanced edition stores config as JSON)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return _normalize_advanced(data, path, networks_file)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to INI-style key=value (Community edition)
    return _normalize_community(raw, path, networks_file)


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
