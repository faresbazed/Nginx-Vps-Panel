#!/usr/bin/env bash
# ==============================================================================
# Nginx Allowed-Website Camouflage & Custom-Protocol VPS Installer (Port 80 & 443)
#
# Designed for networks/ISPs that only allow connections to specific Nginx
# websites (via SNI, Host header, DPI path inspection, or active probing).
#
# Key Capabilities:
#   1. Live Allowed-Site Reverse Proxy: Any request without your secret session
#      token is transparently proxied to the real ISP-allowed Nginx website
#      (--allowed-site), returning its exact HTML, assets, and `Server: nginx`
#      headers on both Port 80 and Port 443.
#   2. Root-Path (`/`) Stealth Protocol (Custom Python SOCKS5/TCP Multiplexer):
#      No suspicious `/ws` or `/vless` URL paths required. Clients connect to `/`
#      with `Host: <allowed-nginx-site>` and a normal-looking session cookie
#      (`Cookie: __ngx_sid=<TOKEN>`), and Nginx upgrades the stream into a full
#      SOCKS5/TCP tunnel.
#   3. Port 443 TLS SNI Impersonation & VLESS-REALITY / WebSocket Fallback:
#      Generates a certificate matching `--allowed-site` (so TLS SNI and cert
#      Common Name match the allowed website) and also configures Xray-core for
#      standard clients (HTTP Custom, v2rayNG, Sing-box, Nekoray).
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_DIR="/etc/nginx-custom-proto"
CERT_DIR="${CONFIG_DIR}/certs"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
CLIENT_INFO="${CONFIG_DIR}/client-configs.txt"

# Default parameters (override with flags, e.g., --allowed-site allowed.example.com)
ALLOWED_SITE="${ALLOWED_SITE:-www.nginx.org}"
WS_PATH="${WS_PATH:-/ws-tunnel}"
VLESS_WS_PATH="${VLESS_WS_PATH:-/vless-ws}"
UUID="${UUID:-}"
SECRET_TOKEN="${SECRET_TOKEN:-}"

usage() {
    cat <<EOF
Usage: sudo bash install.sh [OPTIONS]

Options:
  -a, --allowed-site DOMAIN  The ISP-allowed Nginx website domain to mimic & proxy
                             (e.g., allowed-site.com) [default: www.nginx.org]
  -t, --token TOKEN          Secret authentication token for the custom protocol
                             (auto-generated if omitted)
  -p, --ws-path PATH         Fallback WebSocket path for standard clients (default: /ws-tunnel)
  -u, --uuid UUID            Custom UUID for Xray VLESS/VMess (auto-generated if omitted)
  -s, --status               Show current service status and client connection commands
  -r, --uninstall            Remove configurations and stop services
  -h, --help                 Show this help message
EOF
}

log_info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root (use: sudo bash install.sh)"
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--allowed-site|-d|--domain) ALLOWED_SITE="$2"; shift 2 ;;
            -t|--token) SECRET_TOKEN="$2"; shift 2 ;;
            -p|--ws-path) WS_PATH="$2"; shift 2 ;;
            -u|--uuid) UUID="$2"; shift 2 ;;
            -s|--status) check_root; show_status; exit 0 ;;
            -r|--uninstall) check_root; uninstall_all; exit 0 ;;
            -h|--help) usage; exit 0 ;;
            *) log_err "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
    # Strip any leading http:// or https:// or trailing slash from ALLOWED_SITE
    ALLOWED_SITE="${ALLOWED_SITE#http://}"
    ALLOWED_SITE="${ALLOWED_SITE#https://}"
    ALLOWED_SITE="${ALLOWED_SITE%%/*}"
}

install_dependencies() {
    log_info "Detecting OS and installing required packages (nginx, openssl, curl, unzip, python3)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y nginx openssl curl unzip uuid-runtime python3
    elif command -v dnf &>/dev/null; then
        dnf install -y epel-release || true
        dnf install -y nginx openssl curl unzip util-linux python3
    elif command -v yum &>/dev/null; then
        yum install -y epel-release || true
        yum install -y nginx openssl curl unzip util-linux python3
    else
        log_err "Unsupported package manager. Please use Ubuntu, Debian, CentOS, Rocky, or AlmaLinux."
        exit 1
    fi
    log_ok "System dependencies installed."
}

generate_credentials() {
    if [[ -z "${UUID}" ]]; then
        if command -v uuidgen &>/dev/null; then
            UUID="$(uuidgen)"
        else
            UUID="$(cat /proc/sys/kernel/random/uuid)"
        fi
    fi
    if [[ -z "${SECRET_TOKEN}" ]]; then
        SECRET_TOKEN="$(openssl rand -hex 16)"
    fi
    log_ok "Allowed Nginx Website to mimic : ${ALLOWED_SITE}"
    log_ok "Custom Protocol Secret Token   : ${SECRET_TOKEN}"
    log_ok "Xray Client UUID               : ${UUID}"
}

setup_certificates() {
    mkdir -p "${CERT_DIR}"
    local base_domain="${ALLOWED_SITE#www.}"
    log_info "Generating TLS certificate matching allowed website (${ALLOWED_SITE}) for Port 443..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${CERT_DIR}/privkey.pem" \
        -out "${CERT_DIR}/fullchain.pem" \
        -subj "/C=US/ST=State/L=City/O=Nginx/CN=${ALLOWED_SITE}" \
        -addext "subjectAltName=DNS:${ALLOWED_SITE},DNS:*.${base_domain},DNS:${base_domain}"
    chmod 600 "${CERT_DIR}/privkey.pem"
    log_ok "TLS certificate created with CN=${ALLOWED_SITE} at ${CERT_DIR}/fullchain.pem"
}

setup_custom_stealth_backend() {
    log_info "Installing Custom Stealth Tunnel Backend on 127.0.0.1:10080..."
    mkdir -p "${CONFIG_DIR}"
    cat > "${CONFIG_DIR}/custom_backend.py" <<'EOF'
#!/usr/bin/env python3
"""
Stealth Custom-Protocol Backend Server (127.0.0.1:10080 behind Nginx).
Designed to bypass ISP DPI that only allows specific Nginx websites:
  - Authenticates the client via `Cookie: __ngx_sid=<SECRET_TOKEN>` or `X-Ngx-Token`
  - Responds with realistic Nginx HTTP headers (`Server: nginx`)
  - Bridges multiplexed TCP streams to any destination requested by `client.py`
    (which runs a local SOCKS5 proxy + port forwarder for the user).
"""
import asyncio
import base64
import hashlib
import os

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("BACKEND_PORT", "10080"))
EXPECTED_TOKEN = os.environ.get("SECRET_TOKEN", "")


async def pipe_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(32768)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def extract_cookie_token(cookie_header: str) -> str:
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("__ngx_sid="):
            return part.split("=", 1)[1].strip()
    return ""


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw_headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
    except Exception:
        writer.close()
        return

    header_text = raw_headers.decode("utf-8", errors="replace")
    lines = header_text.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    custom_host = headers.get("x-custom-host", headers.get("host", "unknown"))
    forwarded_proto = headers.get("x-forwarded-proto", "http")
    target_dest = headers.get("x-target-dest", "")
    ws_key = headers.get("sec-websocket-key", "")
    token = headers.get("x-ngx-token", "") or extract_cookie_token(headers.get("cookie", ""))

    if EXPECTED_TOKEN and token != EXPECTED_TOKEN:
        resp = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Server: nginx\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<html><head><title>403 Forbidden</title></head>"
            "<body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>\r\n"
        )
        writer.write(resp.encode("utf-8"))
        await writer.drain()
        writer.close()
        return

    # Decode base64 target destination if provided via X-Target-B64 (avoids plain-text target in DPI)
    target_b64 = headers.get("x-target-b64", "")
    if target_b64 and not target_dest:
        try:
            target_dest = base64.b64decode(target_b64.encode("ascii")).decode("utf-8")
        except Exception:
            target_dest = ""

    accept_val = ""
    if ws_key:
        accept_val = base64.b64encode(
            hashlib.sha1((ws_key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Server: nginx\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_val}\r\n"
        f"X-Accepted-Host: {custom_host}\r\n"
        f"X-Ingress-Proto: {forwarded_proto}\r\n"
        "\r\n"
    )
    writer.write(response.encode("utf-8"))
    await writer.drain()

    # If client requested a remote TCP tunnel (from SOCKS5 or port-forwarder), connect and bridge
    if target_dest and ":" in target_dest:
        t_host, t_port_str = target_dest.rsplit(":", 1)
        try:
            t_port = int(t_port_str)
            rem_reader, rem_writer = await asyncio.wait_for(
                asyncio.open_connection(t_host, t_port), timeout=10.0
            )
            await asyncio.gather(
                pipe_stream(reader, rem_writer),
                pipe_stream(rem_reader, writer),
            )
            return
        except Exception as exc:
            writer.write(f"ERR_CONNECT: {exc}\n".encode("utf-8"))
            await writer.drain()
            writer.close()
            return

    # Diagnostic echo mode (--test)
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
EOF
    chmod +x "${CONFIG_DIR}/custom_backend.py"

    cat > /etc/systemd/system/custom-proto-backend.service <<EOF
[Unit]
Description=Stealth Nginx Custom-Protocol Backend (Port 80 & 443)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${CONFIG_DIR}/custom_backend.py
Restart=always
RestartSec=3
Environment=BACKEND_PORT=10080
Environment=SECRET_TOKEN=${SECRET_TOKEN}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now custom-proto-backend.service
    systemctl restart custom-proto-backend.service
    log_ok "Stealth custom protocol backend running on 127.0.0.1:10080."
}

install_xray_backend() {
    log_info "Installing Xray-core for mobile/desktop third-party clients (HTTP Custom, v2rayNG, Sing-box)..."
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
        mkdir -p /usr/local/etc/xray
        cat > "${XRAY_CONFIG}" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${VLESS_WS_PATH}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
        systemctl enable --now xray
        systemctl restart xray
        log_ok "Xray-core configured on 127.0.0.1:10001."
    else
        log_warn "Xray-core download skipped. Built-in Python stealth protocol (127.0.0.1:10080) is active."
    fi
}

configure_nginx() {
    log_info "Configuring Nginx on Port 80 & 443 to mimic and reverse-proxy ${ALLOWED_SITE}..."
    rm -f /etc/nginx/sites-enabled/default

    cat > /etc/nginx/conf.d/custom-proto.conf <<EOF
# ==============================================================================
# Nginx Allowed-Website Camouflage & Stealth Tunnel Config (Port 80 & Port 443)
# Allowed Website Target: ${ALLOWED_SITE}
#
# How it works:
#   1. If the incoming request on `/` (or any path) carries the secret token in
#      `Cookie: __ngx_sid=${SECRET_TOKEN}` or `X-Ngx-Token: ${SECRET_TOKEN}`,
#      Nginx routes the connection to the local Stealth Tunnel Backend (10080).
#   2. Otherwise, Nginx acts as a live reverse proxy to https://${ALLOWED_SITE},
#      returning the exact web pages, status codes, and headers of the ISP-allowed
#      Nginx website so DPI and active probes see the genuine allowed site.
# ==============================================================================

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# Detect whether the request is an authenticated stealth tunnel connection
map "\$http_x_ngx_token:\$http_cookie" \$upstream_stealth_target {
    default                     "allowed_website";
    "~*${SECRET_TOKEN}"         "stealth_tunnel";
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;

    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;

    # Accept ANY Host header or SNI (specifically ${ALLOWED_SITE})
    server_name _ ${ALLOWED_SITE};

    ssl_certificate     ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    resolver 8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout 5s;

    # 1. Dedicated Custom Tunnel Path (also accepts token auth)
    location ${WS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Custom-Host \$http_host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }

    # 2. VLESS WebSocket Endpoint (for v2rayNG / HTTP Custom / Sing-box)
    location ${VLESS_WS_PATH} {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_read_timeout 86400s;
    }

    # 3. Root Path (`/`) Stealth Multiplexer:
    #    - Authenticated clients (`Cookie: __ngx_sid=${SECRET_TOKEN}`) -> Tunnel (127.0.0.1:10080)
    #    - ISP probes & normal browsers -> Live Reverse Proxy to https://${ALLOWED_SITE}
    location / {
        error_page 418 = @stealth_tunnel_backend;
        if (\$upstream_stealth_target = "stealth_tunnel") {
            return 418;
        }

        proxy_pass https://${ALLOWED_SITE};
        proxy_ssl_server_name on;
        proxy_ssl_name ${ALLOWED_SITE};
        proxy_ssl_verify off;
        proxy_set_header Host ${ALLOWED_SITE};
        proxy_set_header Accept-Encoding "";
        proxy_redirect off;
    }

    location @stealth_tunnel_backend {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Custom-Host \$http_host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_buffering off;
    }
}
EOF

    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    log_ok "Nginx configured: camouflaged as ${ALLOWED_SITE} on Port 80 and Port 443."
}

save_client_info() {
    local vps_ip
    vps_ip="$(curl -s4 https://api.ipify.org || hostname -I | awk '{print $1}')"

    cat > "${CLIENT_INFO}" <<EOF
================================================================================
   NGINX ALLOWED-SITE CAMOUFLAGE & STEALTH TUNNEL READY (PORT 80 & 443)
================================================================================
VPS IP Address          : ${vps_ip}
Mimicked Allowed Site   : ${ALLOWED_SITE}
Supported Ports         : 80 (HTTP) and 443 (TLS/HTTPS)
Stealth Secret Token    : ${SECRET_TOKEN}
Xray Client UUID        : ${UUID}
--------------------------------------------------------------------------------
1. CONNECT USING THE STANDALONE STEALTH CLIENT (client.py)
   (Connects to root path '/' disguised as ${ALLOWED_SITE} and starts a full
    local SOCKS5 proxy on 127.0.0.1:1080 for your browser or apps!)

   [Step A] Test Handshake on Port 80 (HTTP Bug-Host / Split Payload):
     python3 client.py --server ${vps_ip} --port 80 --host ${ALLOWED_SITE} --token ${SECRET_TOKEN} --test

   [Step B] Test Handshake on Port 443 (TLS SNI + Host = ${ALLOWED_SITE}):
     python3 client.py --server ${vps_ip} --port 443 --tls --host ${ALLOWED_SITE} --sni ${ALLOWED_SITE} --token ${SECRET_TOKEN} --test

   [Step C] Start Full SOCKS5 Proxy on 127.0.0.1:1080 (Port 443 or Port 80):
     python3 client.py --server ${vps_ip} --port 443 --tls --host ${ALLOWED_SITE} --sni ${ALLOWED_SITE} --token ${SECRET_TOKEN} --socks5 127.0.0.1:1080

   (Optional: Enable ISP Split-Payload / Bug-Host Preludes with --split-payload)
--------------------------------------------------------------------------------
2. HTTP CUSTOM / INJECTOR PAYLOAD (FOR ANDROID / WINDOWS CLIENTS)
   GET / HTTP/1.1[crlf]Host: ${ALLOWED_SITE}[crlf]Cookie: __ngx_sid=${SECRET_TOKEN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]

3. VLESS LINK (v2rayNG / Sing-box / Nekoray)
   [Port 80]
   vless://${UUID}@${vps_ip}:80?encryption=none&security=none&type=ws&host=${ALLOWED_SITE}&path=${VLESS_WS_PATH}#AllowedSite-Port80

   [Port 443]
   vless://${UUID}@${vps_ip}:443?encryption=none&security=tls&sni=${ALLOWED_SITE}&allowInsecure=1&type=ws&host=${ALLOWED_SITE}&path=${VLESS_WS_PATH}#AllowedSite-Port443
================================================================================
EOF
    cat "${CLIENT_INFO}"
}

show_status() {
    echo -e "${CYAN}=== Service Status ===${NC}"
    systemctl status nginx --no-pager -l || true
    systemctl status custom-proto-backend --no-pager -l || true
    systemctl status xray --no-pager -l || true
    if [[ -f "${CLIENT_INFO}" ]]; then
        cat "${CLIENT_INFO}"
    fi
}

uninstall_all() {
    log_warn "Uninstalling custom protocol services and Nginx config..."
    systemctl disable --now custom-proto-backend.service || true
    rm -f /etc/systemd/system/custom-proto-backend.service
    rm -f /etc/nginx/conf.d/custom-proto.conf
    rm -rf "${CONFIG_DIR}"
    systemctl daemon-reload
    systemctl reload nginx || true
    log_ok "Uninstalled."
}

main() {
    parse_args "$@"
    check_root
    install_dependencies
    generate_credentials
    setup_certificates
    setup_custom_stealth_backend
    install_xray_backend
    configure_nginx
    save_client_info
}

main "$@"