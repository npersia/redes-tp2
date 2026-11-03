"""
Cliente standalone que muestra en tiempo real la tabla ARP exportada por
arp_monitor_agent.py.
"""

import argparse
import json
import socket
import sys
import time

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9997
REFRESH_INTERVAL = 2.0


def _fetch(host, port):
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.sendall(b"GET\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8"))


def _clear_screen():
    print("\033[2J\033[H", end="")


def _print_snapshot(snapshot, clear):
    if clear:
        _clear_screen()

    stamp = time.strftime("%H:%M:%S", time.localtime(snapshot.get("time", time.time())))
    routers = snapshot.get("routers", [])

    if not routers:
        print(f"[ARP MONITOR] Sin instancias de ProtoRouter (hora={stamp})")
        return

    for router in routers:
        entries = router.get("entries", [])
        print(f"[ARP MONITOR] dpid={router.get('dpid')} estado={router.get('state')} "
              f"entradas={len(entries)} hora={stamp}")

        if not entries:
            print("  (sin entradas ARP)")
            print()
            continue

        print(f"  {'IP':<16} {'MAC':<18} {'PUERTO':<7} {'EDAD':>8}")
        print("  " + "-" * 53)

        for entry in entries:
            print(f"  {entry.get('ip', ''):<16} {entry.get('mac', ''):<18} "
                  f"{entry.get('port', ''):<7} {entry.get('age', 0):>7.1f}s")
        print()


def _main():
    parser = argparse.ArgumentParser(description="Monitor de la tabla ARP de protorouter")
    parser.add_argument("--host", default=MONITOR_HOST)
    parser.add_argument("--port", type=int, default=MONITOR_PORT)
    parser.add_argument("--interval", type=float, default=REFRESH_INTERVAL)
    parser.add_argument("--no-clear", action="store_true")
    args = parser.parse_args()

    clear = (not args.no_clear) and sys.stdout.isatty()

    try:
        while True:
            try:
                _print_snapshot(_fetch(args.host, args.port), clear)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                if clear:
                    _clear_screen()
                print(f"[ARP MONITOR] No se pudo conectar a {args.host}:{args.port}: {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    _main()
