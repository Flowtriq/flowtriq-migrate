# flowtriq-migrate

**Migrate from FastNetMon to Flowtriq in under 5 minutes.**

`flowtriq-migrate` reads your existing FastNetMon configuration (Community or Advanced) and generates a working [Flowtriq](https://flowtriq.com) agent config. Every threshold, every network definition, every collection method -- mapped automatically.

Zero dependencies. Works with Python 3.8+.

## Quick Start

```bash
pip install flowtriq-migrate

flowtriq-migrate /etc/fastnetmon.conf -o /etc/ftagent/config.json
```

Done. Install the Flowtriq agent, paste in your API key, and you're live.

## What Gets Migrated

| FastNetMon Setting | Flowtriq Equivalent | Auto-migrated? |
|---|---|---|
| `interfaces` | `interface` | Yes |
| `mirror` + `mirror_afpacket` | `mirror_mode` + `mirror_capture_mode` | Yes |
| `sflow` + `sflow_port` | `flow_enabled` + `flow_protocol` + `flow_port` | Yes |
| `netflow` + `netflow_port` | `flow_enabled` + `flow_protocol` + `flow_port` | Yes |
| `networks_list` | `mirror_subnets` | Yes (mirror mode) |
| `ban_for_pps` / `threshold_pps` | `dynamic_threshold` (adaptive baseline) | Mapped with guidance |
| `ban_for_bandwidth` | `dynamic_threshold` (adaptive baseline) | Mapped with guidance |
| `enable_ban` / `ban_time` | Auto-mitigation rules | Dashboard setup guide |
| `notify_script_path` | Alert channels (12+ options) | Dashboard setup guide |
| `exabgp` / `gobgp` config | BGP adapter (FlowSpec/RTBH) | Dashboard setup guide |
| Per-host thresholds | Per-node agents with independent baselines | Dashboard setup guide |

## Feature Comparison: FastNetMon vs Flowtriq

| Capability | FastNetMon Community | FastNetMon Advanced | Flowtriq |
|---|---|---|---|
| Detection source | NetFlow/sFlow sampling | NetFlow/sFlow sampling | Per-packet at kernel level |
| Detection latency | 30-60 seconds | 30-60 seconds | Sub-second |
| L7 detection (HTTP floods) | No | No | Yes |
| Attack classification | Protocol only (UDP/TCP) | Protocol only | 8+ attack families with confidence scores |
| PCAP forensics | No | No | Automatic pre-attack capture |
| Alert channels | Custom shell script | Script + email + Slack | 12+ native (Slack, Discord, PagerDuty, email, SMS, ...) |
| Dashboard | None | LiveView ($70/user/mo) | Included (unlimited users) |
| Per-host thresholds | No | Yes (manual) | Yes (automatic baselines) |
| BGP FlowSpec | No | Yes | Yes |
| XDP/eBPF mitigation | No | No | Yes |
| API access | No | REST (extra cost) | Full REST API included |
| Pricing | Free (limited) | $115+/month + server | $9.99/node/month |

## Installation

**pip (recommended):**
```bash
pip install flowtriq-migrate
```

**pipx (isolated install):**
```bash
pipx install flowtriq-migrate
```

**From source:**
```bash
git clone https://github.com/flowtriq/flowtriq-migrate.git
cd flowtriq-migrate
pip install .
```

**No install (run directly):**
```bash
git clone https://github.com/flowtriq/flowtriq-migrate.git
cd flowtriq-migrate
python3 -m flowtriq_migrate /etc/fastnetmon.conf --dry-run
```

## Usage

### Basic migration

```bash
flowtriq-migrate /etc/fastnetmon.conf
```

Generates `config.json` in the current directory with a migration report.

### Specify output path

```bash
flowtriq-migrate /etc/fastnetmon.conf -o /etc/ftagent/config.json
```

### Pre-fill credentials

```bash
flowtriq-migrate /etc/fastnetmon.conf \
  --api-key "your-api-key" \
  --node-uuid "your-node-uuid" \
  -o /etc/ftagent/config.json
```

### Dry run (preview without writing)

```bash
flowtriq-migrate /etc/fastnetmon.conf --dry-run
```

### Specify networks file manually

If your `networks_list` file is on a different machine:

```bash
flowtriq-migrate /etc/fastnetmon.conf --networks-file ./my-networks.txt
```

### FastNetMon Advanced (JSON config)

```bash
flowtriq-migrate /etc/fastnetmon-advanced.json
```

The tool auto-detects the config format.

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
    - 12+ native alert channels
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

### Does this work with FastNetMon Community (free edition)?

Yes. The tool parses the standard `/etc/fastnetmon.conf` INI-style configuration used by FastNetMon Community.

### Does this work with FastNetMon Advanced?

Yes. FastNetMon Advanced configs (JSON format) are auto-detected and parsed. Advanced-specific features like per-host thresholds, email alerts, and InfluxDB export are mapped with migration guidance.

### Do I need to stop FastNetMon first?

No. Run both systems in parallel while Flowtriq learns your traffic baselines (24-72 hours). Decommission FastNetMon only after you've validated Flowtriq's detection and alerting.

### What about my BGP blackhole setup?

Your BGP sessions stay unchanged. Flowtriq supports ExaBGP, GoBGP, BIRD 2, and FRRouting as BGP adapters. Configure the BGP peer in the Flowtriq dashboard and Flowtriq orchestrates announcements through the same sessions.

### What if I use sFlow or NetFlow?

Both are fully supported. The tool maps your sFlow/NetFlow collection settings directly to Flowtriq's flow collector configuration. Flowtriq can also run in per-packet agent mode alongside flow collection for combined visibility.

### Is this tool open source?

Yes. MIT licensed. Use it, modify it, contribute to it.

## Contributing

Issues and pull requests welcome at [github.com/flowtriq/flowtriq-migrate](https://github.com/flowtriq/flowtriq-migrate).

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Built by [Flowtriq](https://flowtriq.com) -- real-time DDoS detection and mitigation for hosting providers, ISPs, and game networks.
