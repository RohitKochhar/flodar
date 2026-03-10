# Installation Guide

This guide covers installing and running Flodar as a persistent systemd service on a Raspberry Pi running Raspberry Pi OS (Debian-based). The same steps apply to any arm64 or armv7 Linux host.

---

## Supported hardware

| Model | Architecture | Supported |
|---|---|---|
| Raspberry Pi 4 / 5 | `aarch64` (arm64) | Yes |
| Raspberry Pi 3 | `aarch64` or `armv7` | Yes |
| Raspberry Pi 2 | `armv7` | Yes |
| Raspberry Pi Zero / Zero W | `armv6` | Not tested |

Raspberry Pi 4 with 2 GB RAM or more is the recommended minimum for production use with storage enabled.

---

## Step 1 — Build the binary

You have two options: build directly on the Pi, or cross-compile on a faster machine and copy the binary over.

### Option A — Build natively on the Pi

This is the simplest approach. Install Rust on the Pi and build there.

```bash
# On the Raspberry Pi
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/RohitKochhar/flodar
cd flodar
cargo build --release --package flodar
```

The binary is at `target/release/flodar`. Native builds on a Pi 4 take roughly 5–10 minutes.

### Option B — Cross-compile from a macOS or Linux x86_64 machine

Install [`cross`](https://github.com/cross-rs/cross), which uses Docker to provide the correct cross-compilation toolchain:

```bash
cargo install cross --git https://github.com/cross-rs/cross
```

Then build for the appropriate target:

```bash
# Raspberry Pi 4 / 5 (64-bit OS)
cross build --release --package flodar --target aarch64-unknown-linux-gnu

# Raspberry Pi 3 (32-bit OS) or Pi 2
cross build --release --package flodar --target armv7-unknown-linux-gnueabihf
```

The binary is at `target/<target>/release/flodar`. Copy it to the Pi:

```bash
scp target/aarch64-unknown-linux-gnu/release/flodar pi@<pi-ip>:/tmp/flodar
```

---

## Step 2 — Install the binary

On the Pi, move the binary to `/usr/local/bin` and set permissions:

```bash
sudo mv /tmp/flodar /usr/local/bin/flodar
sudo chown root:root /usr/local/bin/flodar
sudo chmod 755 /usr/local/bin/flodar
```

Verify it runs:

```bash
flodar --version
```

---

## Step 3 — Create a dedicated user

Running flodar as a dedicated unprivileged user limits the blast radius if the process is ever compromised.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin flodar
```

---

## Step 4 — Write the configuration file

Create the config directory and a `flodar.toml`. The example below is a good starting point for a Pi acting as a persistent network monitor with storage enabled.

```bash
sudo mkdir -p /etc/flodar
sudo nano /etc/flodar/flodar.toml
```

```toml
[collector]
bind_address = "0.0.0.0"
bind_port = 2055

[logging]
level = "info"
format = "json"

[analytics]
snapshot_interval_secs = 10

[detection]
enabled = true
cooldown_secs = 60

[api]
bind_address = "0.0.0.0"
bind_port = 9090
enabled = true

[storage]
enabled = true
flow_db_path = "/var/lib/flodar/flows.duckdb"
alert_db_path = "/var/lib/flodar/alerts.db"
```

Using `/var/lib/flodar` for storage rather than the default `~/.local/share/flodar` is recommended for a system service — it is a predictable, standard location that does not depend on a home directory.

Create the storage directory and set ownership:

```bash
sudo mkdir -p /var/lib/flodar
sudo chown flodar:flodar /var/lib/flodar
sudo chmod 750 /var/lib/flodar
```

Set ownership on the config:

```bash
sudo chown root:flodar /etc/flodar/flodar.toml
sudo chmod 640 /etc/flodar/flodar.toml
```

See [configuration.md](configuration.md) for all available options.

---

## Step 5 — Create the systemd unit

```bash
sudo nano /etc/systemd/system/flodar.service
```

```ini
[Unit]
Description=Flodar network flow analyzer
Documentation=https://github.com/RohitKochhar/flodar
After=network.target
Wants=network.target

[Service]
Type=simple
User=flodar
Group=flodar
ExecStart=/usr/local/bin/flodar --config /etc/flodar/flodar.toml
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/flodar
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Note on ports:** The default collector port (2055 UDP) and API port (9090 TCP) are both above 1024, so no special capabilities are needed. If you change `bind_port` to a privileged port (< 1024), add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the `[Service]` block.

---

## Step 6 — Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable flodar
sudo systemctl start flodar
```

Check that it started cleanly:

```bash
sudo systemctl status flodar
```

---

## Step 7 — Open firewall ports

If `ufw` is active on the Pi, allow the collector and API ports:

```bash
# NetFlow / IPFIX collector
sudo ufw allow 2055/udp

# HTTP API and Prometheus metrics
sudo ufw allow 9090/tcp
```

Then point your router's NetFlow export destination at the Pi's IP on port 2055.

---

## Viewing logs

Flodar writes structured JSON logs to stdout, which systemd captures and routes to the journal.

```bash
# Live log stream
sudo journalctl -u flodar -f

# Last 100 lines
sudo journalctl -u flodar -n 100

# Since last boot
sudo journalctl -u flodar -b

# Filter by log level (requires jq)
sudo journalctl -u flodar -f -o json | jq 'select(.PRIORITY <= "4")'
```

If you prefer plain text output during initial setup, temporarily change `format = "pretty"` in `flodar.toml` and restart the service.

---

## Verifying the installation

```bash
# Health check
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics

# Recent alerts (empty until traffic arrives)
curl http://localhost:9090/api/alerts
```

---

## Updating the binary

```bash
# Build or download new binary, then:
sudo systemctl stop flodar
sudo mv /tmp/flodar /usr/local/bin/flodar
sudo chown root:root /usr/local/bin/flodar
sudo chmod 755 /usr/local/bin/flodar
sudo systemctl start flodar
```

---

## Uninstalling

```bash
sudo systemctl stop flodar
sudo systemctl disable flodar
sudo rm /etc/systemd/system/flodar.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/flodar
sudo rm -rf /etc/flodar
sudo rm -rf /var/lib/flodar     # removes all stored flow and alert data
sudo userdel flodar
```
