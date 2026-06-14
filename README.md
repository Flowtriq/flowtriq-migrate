# flowtriq-migrate

**Migrate to Flowtriq from FastNetMon, Wanguard, or Corero in under 5 minutes.**

`flowtriq-migrate` reads your existing DDoS platform configuration and generates a working [Flowtriq](https://flowtriq.com) agent config. Every threshold, every network definition, every collection method -- mapped automatically.

Supports **FastNetMon** (Community and Advanced), **Andrisoft Wanguard**, and **Corero SmartWall**.

Zero dependencies. Works with Python 3.8+.

## Quick Start

```bash
git clone https://github.com/flowtriq/flowtriq-migrate.git
cd flowtriq-migrate

# FastNetMon
python3 -m flowtriq_migrate /etc/fastnetmon.conf -o /etc/ftagent/config.json

# Wanguard (JSON export from Console)
python3 -m flowtriq_migrate wanguard-export.json --vendor wanguard

# Corero SmartWall (REST API export)
python3 -m flowtriq_migrate corero-api-export.json --vendor corero
```

Done. Install the Flowtriq agent, paste in your API key, and you're live.

## What Gets Migrated

### FastNetMon

| Setting | Flowtriq Equivalent | Auto-migrated? |
|---|---|---|
| `interfaces` | `interface` | Yes |
| `mirror` + `mirror_afpacket` | `mirror_mode` + `mirror_capture_mode` | Yes |
| `sflow` + `sflow_port` | `flow_enabled` + `flow_protocol` + `flow_port` | Yes |
| `netflow` + `netflow_port` | `flow_enabled` + `flow_protocol` + `flow_port` | Yes |
| `networks_list` | `mirror_subnets` | Yes (mirror mode) |
| `ban_for_pps` / `threshold_pps` | `dynamic_threshold` (adaptive baseline) | Mapped with guidance |
| `enable_ban` / `ban_time` | Auto-mitigation rules | Dashboard setup guide |
| `notify_script_path` | Alert channels (12+ options) | Dashboard setup guide |
| `exabgp` / `gobgp` config | BGP adapter (FlowSpec/RTBH) | Dashboard setup guide |

### Wanguard (Andrisoft)

| Setting | Flowtriq Equivalent | Auto-migrated? |
|---|---|---|
| Sensor type (NetFlow/sFlow/packet) | `flow_enabled` + `flow_protocol` | Yes |
| Sensor interface + port | `interface` + `flow_port` | Yes |
| Threshold PPS/Mbps | `dynamic_threshold` (adaptive baseline) | Mapped with guidance |
| Anomaly profiles | Per-node adaptive baselines | Mapped with guidance |
| Filter type (FlowSpec/RTBH) | Auto-mitigation rules | Dashboard setup guide |
| SNMP traps / email / scripts | Alert channels (12+ options) | Dashboard setup guide |
| BGP community + next-hop | BGP adapter config | Dashboard setup guide |
| Networks / subnets | `mirror_subnets` or agent mode | Yes |

### Corero SmartWall

| Setting | Flowtriq Equivalent | Auto-migrated? |
|---|---|---|
| Interfaces | `interface` | Yes |
| Protection profiles | Per-node adaptive baselines | Mapped with guidance |
| Smart-Rules (thresholds) | `dynamic_threshold` (adaptive baseline) | Mapped with guidance |
| Managed objects (prefixes) | Agent deployments per subnet | Mapped with guidance |
| BGP RTBH / FlowSpec | BGP adapter config | Dashboard setup guide |
| Syslog / SNMP / webhook alerts | Alert channels (12+ options) | Dashboard setup guide |
| Deployment mode (inline/OOB) | Per-server agent mode | Guidance provided |

## Feature Comparison

| Capability | FastNetMon | Wanguard | Corero SmartWall | Flowtriq |
|---|---|---|---|---|
| Detection source | NetFlow/sFlow | NetFlow/sFlow/PF_RING | Inline hardware | Per-packet at kernel level |
| Detection latency | 30-60 seconds | 10-60 seconds | Sub-second (inline) | Sub-second |
| L7 detection | No | No | Limited | Yes (HTTP floods, DNS) |
| Attack classification | Protocol only | Protocol only | Rule-based | 8+ families with confidence |
| PCAP forensics | No | No | No | Automatic pre-attack capture |
| Alert channels | Script / email | Email / SNMP / script | Syslog / SNMP / webhook | Alerts wherever your NOC works (Slack, PagerDuty, Discord, SMS, and more) |
| Dashboard | None / LiveView | Web Console | CMS Web UI | Included (unlimited users) |
| Per-host thresholds | Advanced only | Per-sensor | Per-managed-object | Automatic per-server baselines |
| BGP FlowSpec | Advanced only | Yes | Yes | Yes |
| XDP/eBPF mitigation | No | No | No | Yes |
| Hardware required | Server | Server | Dedicated appliance | No (runs on existing servers) |
| Pricing | Free / $115+/mo | $1,500+/yr | $10K+/appliance | $9.99/node/month |

## Installation

```bash
git clone https://github.com/flowtriq/flowtriq-migrate.git
cd flowtriq-migrate
```

No dependencies. Runs with Python 3.8+ out of the box.

## Usage

### FastNetMon

```bash
python3 -m flowtriq_migrate /etc/fastnetmon.conf
python3 -m flowtriq_migrate /etc/fastnetmon.conf -o /etc/ftagent/config.json
python3 -m flowtriq_migrate fastnetmon-advanced.json  # Advanced edition auto-detected
```

### Wanguard

Export your settings from Wanguard Console into a JSON file (see `examples/wanguard-export.json` for the format), then:

```bash
python3 -m flowtriq_migrate wanguard-export.json --vendor wanguard
```

### Corero SmartWall

Export your protection profiles and managed objects from the CMS REST API (see `examples/corero-api-export.json` for the format), then:

```bash
python3 -m flowtriq_migrate corero-api-export.json --vendor corero
```

### Other options

```bash
# Pre-fill Flowtriq credentials
python3 -m flowtriq_migrate config.conf --api-key "your-key" --node-uuid "your-uuid"

# Dry run (preview without writing a file)
python3 -m flowtriq_migrate config.conf --dry-run

# Specify networks file manually
python3 -m flowtriq_migrate config.conf --networks-file ./my-networks.txt
```

The tool auto-detects the platform from the config format. Use `--vendor` to override.

## Example Output

Running against a typical FastNetMon Community config:

```
============================================================
  Flowtriq Migration Report
  Source: /etc/fastnetmon.conf (Community Edition)
============================================================

  + MAPPED SETTINGS
    Interface: eth0
    Mirror/SPAN mode (AF_PACKET) on eth0
    Monitored subnets: 10.0.0.0/24, 192.168.1.0/24
    FastNetMon static thresholds: 20,000 PPS, 1,024 Mbps.
    Flowtriq uses adaptive baselining instead.

  ! MANUAL STEPS REQUIRED
    1. Get your API key and Node UUID from https://flowtriq.com/dashboard
    2. Configure alert channels (replaces notify_about_attack.sh)
    3. Configure auto-mitigation rules (replaces enable_ban)
    4. Configure BGP mitigation in dashboard (replaces ExaBGP config)

  * NEW IN FLOWTRIQ (not available in FastNetMon)
    - Sub-second attack detection (vs 30-60s with flow sampling)
    - L7 application-layer DDoS detection
    - Per-packet PCAP forensics with automatic capture
    - Adaptive baseline learning (no manual threshold tuning)
    - Real-time dashboard with attack timelines
    - Alerts wherever your NOC works
    - XDP/eBPF kernel-level filtering
    - Service port awareness

  Config written to: ./config.json
  Next: pip install ftagent && sudo ftagent --test
```

## After Migration

1. **Install ftagent** on your servers:
   ```bash
   pip install ftagent
   sudo ftagent --setup
   ```

2. **Run both in parallel** for 24-72 hours while Flowtriq baselines form

3. **Configure alert channels** in the [Flowtriq dashboard](https://flowtriq.com/dashboard) (Slack, Discord, PagerDuty, email, webhook, etc.)

4. **Decommission FastNetMon** once you've validated Flowtriq detections

Full migration guide: [flowtriq.com/blog/migrate-from-fastnetmon-to-flowtriq](https://flowtriq.com/blog/migrate-from-fastnetmon-to-flowtriq)

## FAQ

### Which platforms are supported?

FastNetMon (Community INI config and Advanced JSON config), Andrisoft Wanguard (JSON export from Console), and Corero SmartWall (REST API JSON export). The tool auto-detects the format or you can specify `--vendor`.

### How do I export my Wanguard config?

Wanguard stores configuration in its web Console database. Create a JSON file with your sensor settings, thresholds, networks, BGP config, and alert channels. See `examples/wanguard-export.json` for the exact format.

### How do I export my Corero config?

Query the CMS REST API endpoints (`/api/v1/protection-profiles/`, `/api/v1/managed-objects/`, `/api/v1/smart-rules/`) and combine the responses into a single JSON file. See `examples/corero-api-export.json` for the format.

### Do I need to stop my current platform first?

No. Run both systems in parallel while Flowtriq learns your traffic baselines (24-72 hours). Decommission your old platform only after you've validated Flowtriq's detection and alerting.

### What about my BGP blackhole setup?

Your BGP sessions stay unchanged. Flowtriq supports ExaBGP, GoBGP, BIRD 2, and FRRouting as BGP adapters. Configure the BGP peer in the Flowtriq dashboard and Flowtriq orchestrates announcements through the same sessions.

### Corero is inline hardware. How does Flowtriq replace it?

Flowtriq deploys lightweight agents on your servers instead of inline appliances. Detection happens per-packet at the kernel level. Mitigation uses iptables/nftables/XDP locally, plus BGP FlowSpec/RTBH for upstream filtering. No dedicated hardware required.

### Is this tool open source?

Yes. MIT licensed. Use it, modify it, contribute to it.

## Contributing

Issues and pull requests welcome at [github.com/flowtriq/flowtriq-migrate](https://github.com/flowtriq/flowtriq-migrate).

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Built by [Flowtriq](https://flowtriq.com) -- real-time DDoS detection and mitigation for hosting providers, ISPs, and game networks.
