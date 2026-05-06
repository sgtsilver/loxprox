# LoxProx Grafana Integration

For users who already run Prometheus + Grafana (+ optional Loki). Adds LoxProx-specific security metrics and log panels to your existing stack.

## What You Get

| Component | Source | Purpose |
|-----------|--------|---------|
| `node_exporter` + textfile | System + custom script | CPU, RAM, disk, CrowdSec blocks, nginx errors, AppSec hits |
| `promtail` | Log shipper | nginx access/error logs, CrowdSec logs, monitor logs → Loki |
| `grafana-dashboard.json` | Importable dashboard | Security overview, system health, live logs |

## Gateway-Side Setup (LoxProx VM)

### 1. Install node_exporter

```bash
# Debian 12 — official Prometheus repo
wget -qO- https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

# Or just grab the binary
curl -sL https://github.com/prometheus/node_exporter/releases/download/v1.8.1/node_exporter-1.8.1.linux-amd64.tar.gz | \
  tar -xzf - -C /tmp
sudo mv /tmp/node_exporter-1.8.1.linux-amd64/node_exporter /usr/local/bin/
sudo useradd --no-create-home --shell /bin/false node_exporter || true

# Systemd service
cat <<EOF | sudo tee /etc/systemd/system/node_exporter.service
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
User=node_exporter
ExecStart=/usr/local/bin/node_exporter \
  --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p /var/lib/node_exporter/textfile_collector
sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
```

### 2. Install the LoxProx metrics collector

```bash
sudo cp loxprox-metrics.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/loxprox-metrics.sh
sudo mkdir -p /var/lib/node_exporter/textfile_collector

# Run every 60 seconds via systemd timer
cat <<EOF | sudo tee /etc/systemd/system/loxprox-metrics.service
[Unit]
Description=LoxProx Prometheus Metrics Collector

[Service]
Type=oneshot
ExecStart=/usr/local/bin/loxprox-metrics.sh
EOF

cat <<EOF | sudo tee /etc/systemd/system/loxprox-metrics.timer
[Unit]
Description=Run LoxProx metrics every 60s

[Timer]
OnBootSec=60
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now loxprox-metrics.timer
```

### 3. Install Promtail (optional — only if you run Loki)

```bash
curl -sL "https://github.com/grafana/loki/releases/download/v2.9.8/promtail-linux-amd64.zip" -o /tmp/promtail.zip
unzip -o /tmp/promtail.zip -d /tmp
sudo mv /tmp/promtail-linux-amd64 /usr/local/bin/promtail
sudo chmod +x /usr/local/bin/promtail

# Config
sudo mkdir -p /etc/promtail
sudo cp promtail-config.yaml /etc/promtail/config.yml

# Systemd service
cat <<EOF | sudo tee /etc/systemd/system/promtail.service
[Unit]
Description=Promtail log shipper
After=network.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now promtail
```

**Edit `promtail-config.yaml`** and set your Loki URL (`http://your-loki:3100/loki/api/v1/push`).

## Prometheus-Side Setup

Add this job to your `prometheus.yml`:

```yaml
  - job_name: 'loxprox-gateway'
    static_configs:
      - targets: ['loxprox-vm-ip:9100']
        labels:
          instance: 'loxprox-gateway'
```

Or use the provided `prometheus-scrape.yml` snippet and include it.

## Grafana-Side Setup

1. **Import the dashboard:**
   - Grafana → Dashboards → Import
   - Upload `grafana-dashboard.json`
   - Select your Prometheus and Loki data sources

2. **Done.** The dashboard auto-discovers metrics via the `instance="loxprox-gateway"` label.

## Firewall Note

If your gateway VM has nftables input DROP, allow Prometheus scrapes from your monitoring subnet:

```bash
sudo nft add rule inet filter input ip sdr 192.168.100.0/24 tcp dport 9100 accept
```

(Replace `192.168.100.0/24` with your Prometheus/Loki network.)
