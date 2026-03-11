# Installation

Flodar ships as a single static binary with no runtime dependencies. There are three supported installation methods:

- **[Docker (pre-built)](#docker)** — pull from GHCR; no build toolchain required; fastest way to get started
- **[Docker (build locally)](#build-the-image-locally)** — build the image yourself from source
- **[From source](#from-source)** — build with Cargo; required for custom targets (e.g. Raspberry Pi) or when you want full control over the binary

All methods end with the same running binary. If you want flodar to start automatically on boot, see [Running as a service](#running-as-a-service) after completing either install.

---

## Docker

Every merge to `main` publishes a multi-arch image (`linux/amd64`, `linux/arm64`) to the GitHub Container Registry. Pull it directly — no clone or build required:

```bash
docker pull ghcr.io/rohitkochhar/flodar:latest
```

### Run with default config

```bash
docker run -d \
  --name flodar \
  -p 2055:2055/udp \
  -p 9090:9090 \
  ghcr.io/rohitkochhar/flodar:latest
```

Check it started correctly:

```bash
curl http://localhost:9090/health
```

### Run with a custom config

Mount your `flodar.toml` over the default one baked into the image:

```bash
docker run -d \
  --name flodar \
  -p 2055:2055/udp \
  -p 9090:9090 \
  -v /path/to/your/flodar.toml:/app/flodar.toml:ro \
  ghcr.io/rohitkochhar/flodar:latest
```

See [configuration.md](configuration.md) for all available options. A fully annotated example is in [`examples/flodar.full.toml`](../examples/flodar.full.toml).

### Persist storage across container restarts

By default, flodar stores flow and alert data inside the container — it is lost when the container is removed. To persist it, mount a host directory over the storage paths:

```bash
mkdir -p /var/lib/flodar

docker run -d \
  --name flodar \
  -p 2055:2055/udp \
  -p 9090:9090 \
  -v /path/to/your/flodar.toml:/app/flodar.toml:ro \
  -v /var/lib/flodar:/var/lib/flodar \
  ghcr.io/rohitkochhar/flodar:latest
```

And in your `flodar.toml`:

```toml
[storage]
enabled = true
flow_db_path  = "/var/lib/flodar/flows.duckdb"
alert_db_path = "/var/lib/flodar/alerts.db"
```

### View logs

```bash
docker logs flodar -f
```

### Upgrade

```bash
docker stop flodar && docker rm flodar
docker pull ghcr.io/rohitkochhar/flodar:latest
docker run -d ...   # same flags as before
```

### Build the image locally

If you need to build the image yourself (e.g. to test local changes):

```bash
git clone https://github.com/RohitKochhar/flodar
cd flodar
docker build -f docker/Dockerfile -t flodar .
```

Then use `flodar` in place of `ghcr.io/rohitkochhar/flodar:latest` in the run commands above.

---

## From source

### Prerequisites

Install the Rust toolchain via [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Rust 1.75 or later is required.

### Build

```bash
git clone https://github.com/RohitKochhar/flodar
cd flodar
cargo build --release --package flodar
```

The binary is at `target/release/flodar`. Build time is roughly 2–3 minutes on a modern laptop and 5–10 minutes on a Raspberry Pi 4.

> **Note:** flodar bundles DuckDB and compiles it from C++ source during the first build. This is expected — DuckDB is a large embedded database engine and can add 10–15 minutes to the initial build time on a modern laptop (longer on a Raspberry Pi). Subsequent builds are fast because Cargo caches the compiled artifact.

### Run

```bash
./target/release/flodar --config flodar.toml
```

Flodar looks for `flodar.toml` in the current directory by default. Pass `--config /path/to/flodar.toml` to specify a different location.

To copy the binary to a system-wide location:

```bash
sudo cp target/release/flodar /usr/local/bin/flodar
flodar --config /etc/flodar/flodar.toml
```

### Cross-compile for Raspberry Pi

If building on a macOS or Linux x86_64 machine for a Raspberry Pi, install [`cross`](https://github.com/cross-rs/cross) (requires Docker):

```bash
cargo install cross --git https://github.com/cross-rs/cross
```

Then build for the appropriate target:

```bash
# Raspberry Pi 4 / 5 running 64-bit OS
cross build --release --package flodar --target aarch64-unknown-linux-gnu

# Raspberry Pi 3 or 2 running 32-bit OS
cross build --release --package flodar --target armv7-unknown-linux-gnueabihf
```

Copy the binary to the Pi and install it:

```bash
scp target/aarch64-unknown-linux-gnu/release/flodar pi@<pi-ip>:/tmp/flodar
ssh pi@<pi-ip> "sudo mv /tmp/flodar /usr/local/bin/flodar && sudo chmod 755 /usr/local/bin/flodar"
```

---

## Running as a service

If you installed flodar from source and want it to start on boot and restart on failure, set it up as a systemd service. These steps work on any systemd-based Linux host — Raspberry Pi OS, Ubuntu, Debian, etc.

### 1. Create a dedicated user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin flodar
```

### 2. Create the config directory

```bash
sudo mkdir -p /etc/flodar
sudo cp /path/to/your/flodar.toml /etc/flodar/flodar.toml
sudo chown root:flodar /etc/flodar/flodar.toml
sudo chmod 640 /etc/flodar/flodar.toml
```

### 3. Create the storage directory (if using persistent storage)

```bash
sudo mkdir -p /var/lib/flodar
sudo chown flodar:flodar /var/lib/flodar
sudo chmod 750 /var/lib/flodar
```

And in `/etc/flodar/flodar.toml`:

```toml
[storage]
enabled = true
flow_db_path  = "/var/lib/flodar/flows.duckdb"
alert_db_path = "/var/lib/flodar/alerts.db"
```

### 4. Write the systemd unit

```bash
sudo nano /etc/systemd/system/flodar.service
```

```ini
[Unit]
Description=Flodar network flow analyzer
Documentation=https://github.com/RohitKochhar/flodar
After=network.target

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

> **Note on privileged ports:** The default collector port (2055 UDP) and API port (9090 TCP) are both above 1024 and require no special privileges. If you change either to a port below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the `[Service]` block.

### 5. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now flodar
```

### 6. Open firewall ports (if using ufw)

```bash
sudo ufw allow 2055/udp   # NetFlow / IPFIX collector
sudo ufw allow 9090/tcp   # HTTP API and Prometheus metrics
```

---

## Verifying the installation

These checks work regardless of install method:

```bash
# Service status
curl http://localhost:9090/health

# Prometheus metrics
curl http://localhost:9090/metrics

# Recent alerts (empty until traffic arrives)
curl http://localhost:9090/api/alerts
```

### Viewing logs

**Docker:**
```bash
docker logs flodar -f
```

**systemd:**
```bash
# Live stream
sudo journalctl -u flodar -f

# Since last boot
sudo journalctl -u flodar -b
```

---

## Uninstalling

**Docker:**
```bash
docker stop flodar && docker rm flodar
docker rmi ghcr.io/rohitkochhar/flodar:latest
```

**From source (with systemd service):**
```bash
sudo systemctl stop flodar && sudo systemctl disable flodar
sudo rm /etc/systemd/system/flodar.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/flodar
sudo rm -rf /etc/flodar
sudo rm -rf /var/lib/flodar   # deletes all stored flow and alert data
sudo userdel flodar
```
