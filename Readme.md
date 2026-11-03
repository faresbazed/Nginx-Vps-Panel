# Nginx Allowed-Website Camouflage & Stealth Tunnel (Port 80 & Port 443)

A VPS installer (`install.sh`) and standalone SOCKS5/tunnel client (`client.py`) designed for networks where your ISP **only allows connections to specific Nginx websites** (using Deep Packet Inspection on HTTP `Host` headers, TLS `SNI`, URL paths, or active server probing).

## How This Differs from a Regular Xray Setup

1. **Live Reverse-Proxy Camouflage of the Allowed Nginx Website (`--allowed-site`)**:
   - A regular Xray setup serves a static dummy page or returns `400 Bad Request` / `404 Not Found`, which ISP active probes and DPI easily detect.
   - This script configures Nginx on **Port 80 and Port 443** to transparently reverse-proxy the **real ISP-allowed Nginx website** (`https://<allowed-site>`). Any browser or ISP probe visiting your VPS receives the genuine website content, status codes, and `Server: nginx` headers of the allowed website.
2. **Root-Path (`/`) Stealth Routing via Session Cookie**:
   - Instead of connecting to a conspicuous path like `/vless-ws`, `client.py` connects to the **root path `/`** with `Host: <allowed-nginx-site>` and a normal-looking session cookie (`Cookie: __ngx_sid=<SECRET_TOKEN>`).
   - Nginx inspects the cookie internally: if the secret token matches, Nginx hijacks the connection into the tunnel backend (`127.0.0.1:10080`); if not, it proxies the request to the real allowed Nginx website.
3. **TCP Payload Fragmentation (`--split-payload`) & Built-In SOCKS5 Proxy (`--socks5`)**:
   - `client.py` can split the initial HTTP request across multiple TCP segments (`--split-payload`) to evade stateless DPI packet matchers on Port 80, and runs a **complete local SOCKS5 proxy (`127.0.0.1:1080`)** using only the Python 3 standard library—no third-party client required.

> **Important Note on ISP Filtering Types:**
> - **SNI / Host Header / Active-Probe Whitelisting (Most Common)**: Your ISP inspects the `Host` header (Port 80) or TLS `SNI` (Port 443) and checks if the server behaves like the allowed Nginx website. This script bypasses this directly.
> - **Strict Destination IP Whitelisting**: If your ISP blocks all destination IP addresses except the allowed website's own IP, a direct connection to your VPS IP will be dropped unless the allowed website shares a CDN/reverse-proxy network (e.g., Cloudflare/Fastly) that can route traffic to your origin VPS, or has an open proxy/redirect endpoint.

## Quick Start (One-Line Install from Your GitHub)

After uploading `install.sh`, `client.py`, and `README.md` to your GitHub repository, run this on your VPS as `root` (replace `allowed-nginx-site.com` with the website your ISP allows):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/<your-username>/<your-repo>/main/install.sh) --allowed-site allowed-nginx-site.com
```

### Installer Flags

```bash
# Mimic and reverse-proxy a specific ISP-allowed Nginx website
sudo bash install.sh --allowed-site allowed-nginx-site.com

# Specify a custom secret token
sudo bash install.sh --allowed-site allowed-nginx-site.com --token mysecrettoken123

# Check status and print ready client commands
sudo bash install.sh --status

# Uninstall
sudo bash install.sh --uninstall
```

## Connecting with `client.py` (No Third-Party Client Needed)

`client.py` requires only Python 3 (zero `pip` packages) and includes a full **SOCKS5 proxy server**:

```bash
# 1. Test Port 443 (TLS) disguised as the allowed Nginx website
python3 client.py --server YOUR_VPS_IP --port 443 --tls \
  --host allowed-nginx-site.com --sni allowed-nginx-site.com \
  --token YOUR_SECRET_TOKEN --test

# 2. Test Port 80 (HTTP) with DPI TCP payload fragmentation
python3 client.py --server YOUR_VPS_IP --port 80 \
  --host allowed-nginx-site.com \
  --token YOUR_SECRET_TOKEN --split-payload --test

# 3. Start a Local SOCKS5 Proxy on 127.0.0.1:1080 (for browsers, curl, or system proxy)
python3 client.py --server YOUR_VPS_IP --port 443 --tls \
  --host allowed-nginx-site.com --sni allowed-nginx-site.com \
  --token YOUR_SECRET_TOKEN --socks5 127.0.0.1:1080
```

Once the SOCKS5 proxy is running on `127.0.0.1:1080`, test it from another terminal:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

## Using Mobile / Desktop Clients (HTTP Custom, v2rayNG, Sing-box)

If you also want to connect from mobile apps like **HTTP Custom** or **v2rayNG**, `install.sh` outputs both an HTTP Custom payload (using the `Cookie: __ngx_sid=<TOKEN>` header on `/`) and standard `vless://` links on Port 80 and Port 443 with `host` and `sni` pre-filled to your `--allowed-site`.
