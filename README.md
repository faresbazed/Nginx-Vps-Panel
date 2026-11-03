Nginx Allowed-Website Camouflage & Stealth Tunnel (Port 80 & Port 443)
A VPS installer (⁠install.sh⁠) and standalone SOCKS5/tunnel client (⁠client.py⁠) designed for networks where your ISP only allows connections to specific Nginx websites (using Deep Packet Inspection on HTTP ⁠Host⁠ headers, TLS ⁠SNI⁠, URL paths, or active server probing).
How This Differs from a Regular Xray Setup
1. Live Reverse-Proxy Camouflage of the Allowed Nginx Website (⁠--allowed-site⁠):
￼ A regular Xray setup serves a static dummy page or returns ⁠400 Bad Request⁠ / ⁠404 Not Found⁠, which ISP active probes and DPI easily detect.
￼ This script configures Nginx on Port 80 and Port 443 to transparently reverse-proxy the real ISP-allowed Nginx website (⁠https://<allowed-site>⁠). Any browser or ISP probe visiting your VPS receives the genuine website content, status codes, and ⁠Server: nginx⁠ headers of the allowed website.
2. Root-Path (⁠/⁠) Stealth Routing via Session Cookie:
￼ Instead of connecting to a conspicuous path like ⁠/vless-ws⁠, ⁠client.py⁠ connects to the root path ⁠/⁠ with ⁠Host: <allowed-nginx-site>⁠ and a normal-looking session cookie (⁠Cookie: __ngx_sid=<SECRET_TOKEN>⁠).
￼ Nginx inspects the cookie internally: if the secret token matches, Nginx hijacks the connection into the tunnel backend (⁠127.0.0.1:10080⁠); if not, it proxies the request to the real allowed Nginx website.
3. TCP Payload Fragmentation (⁠--split-payload⁠) & Built-In SOCKS5 Proxy (⁠--socks5⁠):
￼ ⁠client.py⁠ can split the initial HTTP request across multiple TCP segments (⁠--split-payload⁠) to evade stateless DPI packet matchers on Port 80, and runs a complete local SOCKS5 proxy (⁠127.0.0.1:1080⁠) using only the Python 3 standard library—no third-party client required.
Quick Start (One-Line Install from Your GitHub)
After uploading ⁠install.sh⁠, ⁠client.py⁠, and ⁠README.md⁠ to your GitHub repository, run this on your VPS as ⁠root⁠ (replace ⁠allowed-nginx-site.com⁠ with the website your ISP allows):
Installer Flags
Connecting with ⁠client.py⁠ (No Third-Party Client Needed)
⁠client.py⁠ requires only Python 3 (zero ⁠pip⁠ packages) and includes a full SOCKS5 proxy server:
Once the SOCKS5 proxy is running on ⁠127.0.0.1:1080⁠, test it from another terminal:
Using Mobile / Desktop Clients (HTTP Custom, v2rayNG, Sing-box)
If you also want to connect from mobile apps like HTTP Custom or v2rayNG, ⁠install.sh⁠ outputs both an HTTP Custom payload (using the ⁠Cookie: __ngx_sid=<TOKEN>⁠ header on ⁠/⁠) and standard ⁠vless://⁠ links on Port 80 and Port 443 with ⁠host⁠ and ⁠sni⁠ pre-filled to your ⁠--allowed-site⁠.