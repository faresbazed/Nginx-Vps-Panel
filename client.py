#!/usr/bin/env python3
"""
Stealth Custom-Protocol Client for ISP Allowed-Nginx Websites (Port 80 & Port 443).
Unlike regular Xray clients, this standalone client:
  1. Connects to the root path (`/`) rather than suspicious `/vless` or `/ws` paths.
  2. Spoofs the HTTP `Host` header and TLS `SNI` to match the ISP-allowed Nginx
     website (`--host allowed-site.com --sni allowed-site.com`).
  3. Authenticates using a normal-looking Nginx session cookie (`Cookie: __ngx_sid=<TOKEN>`)
     so any unauthenticated ISP probe to your VPS receives the real allowed website.
  4. Supports optional Split-Payload / Bug-Host injection (`--split-payload`) for
     ISPs that inspect the first TCP packet on Port 80.
  5. Includes a built-in local **SOCKS5 Proxy Server** (`--socks5 127.0.0.1:1080`)
     so you can connect any browser, system proxy, or app without needing a third-party client.
"""

import argparse
import asyncio
import base64
import os
import socket
import ssl
import struct
import sys


def build_stealth_handshake(
    path: str,
    allowed_host: str,
    token: str,
    target_dest: str = "",
    split_payload: bool = False,
) -> list[bytes]:
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {allowed_host}",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {ws_key}",
        "Sec-WebSocket-Version: 13",
    ]
    if token:
        headers.append(f"Cookie: __ngx_sid={token}")
    if target_dest:
        target_b64 = base64.b64encode(target_dest.encode("utf-8")).decode("ascii")
        headers.append(f"X-Target-B64: {target_b64}")

    full_req = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")

    # If --split-payload is enabled, split the HTTP request across multiple TCP writes
    # to evade simple stateless DPI packet matching on the first TCP segment.
    if split_payload and len(full_req) > 24:
        return [full_req[:16], full_req[16:48], full_req[48:]]
    return [full_req]


async def open_vps_stream(
    server: str,
    port: int,
    use_tls: bool,
    sni: str,
    verify_tls: bool,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_ctx = None
    server_hostname = None
    if use_tls or port == 443:
        ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        server_hostname = sni

    return await asyncio.wait_for(
        asyncio.open_connection(
            host=server,
            port=port,
            ssl=ssl_ctx,
            server_hostname=server_hostname,
        ),
        timeout=10.0,
    )


async def establish_tunnel_stream(
    args: argparse.Namespace,
    target_dest: str = "",
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await open_vps_stream(
        args.server, args.port, args.tls, args.sni, args.verify_tls
    )
    chunks = build_stealth_handshake(
        path=args.path,
        allowed_host=args.host,
        token=args.token,
        target_dest=target_dest,
        split_payload=args.split_payload,
    )
    for chunk in chunks:
        writer.write(chunk)
        await writer.drain()
        if len(chunks) > 1:
            await asyncio.sleep(0.02)

    resp_raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
    if b"101 Switching Protocols" not in resp_raw:
        writer.close()
        resp_preview = resp_raw.decode("utf-8", errors="replace").splitlines()[0]
        raise RuntimeError(
            f"Server did not switch protocols (got '{resp_preview}'). "
            "Check --token matches the VPS install.sh token."
        )
    return reader, writer


async def run_test(args: argparse.Namespace):
    proto_label = "TLS/HTTPS (Port 443)" if args.tls else "HTTP (Port 80)"
    print(f"[*] Connecting to VPS {args.server}:{args.port} via {proto_label}")
    print(f"[*] Allowed Nginx Host : {args.host}")
    if args.tls:
        print(f"[*] TLS SNI            : {args.sni}")
    print(f"[*] Request Path       : {args.path}")
    print(f"[*] Split TCP Payload  : {args.split_payload}")

    reader, writer = await establish_tunnel_stream(args, target_dest="")
    print("[+] Stealth Handshake Accepted (101 Switching Protocols, Server: nginx)!")

    test_payload = b"ping-stealth-nginx-tunnel"
    writer.write(test_payload)
    await writer.drain()
    echoed = await asyncio.wait_for(reader.read(len(test_payload)), timeout=5.0)
    if echoed == test_payload:
        print("[+] Bidirectional tunnel stream verified! Ready for SOCKS5 or port forwarding.")
    else:
        print(f"[!] Unexpected echo response: {echoed!r}")

    writer.close()
    await writer.wait_closed()


async def pipe_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            chunk = await reader.read(32768)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_socks5_client(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
):
    """Built-in SOCKS5 server handler that tunnels each connection through the Nginx VPS."""
    try:
        # 1. SOCKS5 Greeting (VER, NMETHODS, METHODS)
        hdr = await asyncio.wait_for(local_reader.readexactly(2), timeout=10.0)
        ver, nmethods = hdr[0], hdr[1]
        if ver != 5:
            local_writer.close()
            return
        await local_reader.readexactly(nmethods)
        # Respond: SOCKS5, No Auth (0x00)
        local_writer.write(b"\x05\x00")
        await local_writer.drain()

        # 2. SOCKS5 Request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)
        req_hdr = await asyncio.wait_for(local_reader.readexactly(4), timeout=10.0)
        ver, cmd, _, atyp = req_hdr
        if cmd != 1:  # Only CONNECT (0x01) is needed for TCP tunneling
            local_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await local_writer.drain()
            local_writer.close()
            return

        if atyp == 1:  # IPv4
            raw_ip = await local_reader.readexactly(4)
            dst_host = socket.inet_ntoa(raw_ip)
        elif atyp == 3:  # Domain name
            domain_len = (await local_reader.readexactly(1))[0]
            dst_host = (await local_reader.readexactly(domain_len)).decode("utf-8", errors="replace")
        elif atyp == 4:  # IPv6
            raw_ip6 = await local_reader.readexactly(16)
            dst_host = f"[{socket.inet_ntop(socket.AF_INET6, raw_ip6)}]"
        else:
            local_writer.close()
            return

        dst_port = struct.unpack("!H", await local_reader.readexactly(2))[0]
        target_dest = f"{dst_host}:{dst_port}"

        # 3. Open stealth stream through the Nginx VPS to target_dest
        rem_reader, rem_writer = await establish_tunnel_stream(args, target_dest=target_dest)

        # 4. Send SOCKS5 success reply
        local_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await local_writer.drain()

        # 5. Pipe data bidirectionally
        await asyncio.gather(
            pipe_data(local_reader, rem_writer),
            pipe_data(rem_reader, local_writer),
        )
    except Exception:
        try:
            local_writer.close()
        except Exception:
            pass


async def handle_port_forward_client(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    args: argparse.Namespace,
):
    try:
        rem_reader, rem_writer = await establish_tunnel_stream(args, target_dest=args.target)
        await asyncio.gather(
            pipe_data(local_reader, rem_writer),
            pipe_data(rem_reader, local_writer),
        )
    except Exception as exc:
        print(f"[!] Tunnel connection error: {exc}")
        local_writer.close()


async def run_socks5_server(args: argparse.Namespace):
    listen_host, listen_port_str = args.socks5.rsplit(":", 1)
    listen_port = int(listen_port_str)
    server = await asyncio.start_server(
        lambda r, w: handle_socks5_client(r, w, args),
        listen_host,
        listen_port,
    )
    print(f"[*] Local SOCKS5 Proxy listening on socks5://{listen_host}:{listen_port}")
    print(f"    -> Disguised as Allowed Nginx Host : {args.host} (Port {args.port})")
    print(f"    -> Point your browser, system proxy, or curl to {listen_host}:{listen_port}")
    print(f"       Example test: curl --socks5-hostname {listen_host}:{listen_port} https://api.ipify.org")
    async with server:
        await server.serve_forever()


async def run_port_forward_server(args: argparse.Namespace):
    listen_host, listen_port_str = args.listen.rsplit(":", 1)
    listen_port = int(listen_port_str)
    server = await asyncio.start_server(
        lambda r, w: handle_port_forward_client(r, w, args),
        listen_host,
        listen_port,
    )
    print(f"[*] Port Forwarder listening on {listen_host}:{listen_port} -> {args.target}")
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="Stealth Client for ISP-Allowed Nginx Websites (Port 80 & Port 443)"
    )
    parser.add_argument("--server", required=True, help="VPS IP address (or front IP)")
    parser.add_argument("--port", type=int, default=443, help="VPS port (80 or 443, default: 443)")
    parser.add_argument("--host", required=True, help="ISP-allowed Nginx website domain (Host header)")
    parser.add_argument("--sni", default="", help="TLS SNI hostname (defaults to --host)")
    parser.add_argument("--token", default="", help="Secret token generated by install.sh")
    parser.add_argument("--path", default="/", help="Request path (default: '/' root path for stealth)")
    parser.add_argument("--tls", action="store_true", help="Use TLS (automatically enabled on port 443)")
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS certificate chain")
    parser.add_argument("--split-payload", action="store_true", help="Fragment HTTP request across TCP segments to evade DPI")
    parser.add_argument("--test", action="store_true", help="Run handshake and echo test")
    parser.add_argument("--socks5", default="", help="Start local SOCKS5 proxy (e.g. 127.0.0.1:1080)")
    parser.add_argument("--listen", default="127.0.0.1:1080", help="Local bind address for fixed --target mode")
    parser.add_argument("--target", default="", help="Fixed remote host:port to forward traffic to")

    args = parser.parse_args()
    if args.port == 443:
        args.tls = True
    if not args.sni:
        args.sni = args.host

    try:
        if args.socks5:
            asyncio.run(run_socks5_server(args))
        elif args.target:
            asyncio.run(run_port_forward_server(args))
        else:
            asyncio.run(run_test(args))
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()