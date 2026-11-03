"""
Exporta por TCP la tabla ARP de protorouter para que arp_monitor.py pueda
mostrarla desde otra terminal.
"""

import gc
import json
import socket
import threading
import time

from pox.core import core
import protorouter

log = core.getLogger()

MONITOR_HOST = "127.0.0.1"
MONITOR_PORT = 9997

_instances = set()
_hook_installed = False
_server_socket = None
_server_stop = threading.Event()


def _remember(instance):
    _instances.add(instance)


def _install_hook():
    global _hook_installed

    if _hook_installed:
        return

    if getattr(protorouter.ProtoRouter, "_arp_monitor_hooked", False):
        _hook_installed = True
        return

    original_init = protorouter.ProtoRouter.__init__

    def monitored_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        _remember(self)

    protorouter.ProtoRouter.__init__ = monitored_init
    protorouter.ProtoRouter._arp_monitor_hooked = True
    _hook_installed = True
    log.info("[ARP MONITOR] Enganchado a protorouter.ProtoRouter")


def _scan_existing_routers():
    for obj in gc.get_objects():
        if isinstance(obj, protorouter.ProtoRouter):
            _remember(obj)


def _discover_routers():
    return list(_instances)


def _router_snapshot(router, now):
    connection = getattr(router, "connection", None)
    arp_mgr = getattr(router, "arp_mgr", None)
    table = getattr(arp_mgr, "arp_table", {}) if arp_mgr is not None else {}

    entries = []
    for ip, entry in list(table.items()):
        last_seen = getattr(entry, "last_seen", now)
        entries.append({
            "ip": str(ip),
            "mac": str(getattr(entry, "mac", "?")),
            "port": str(getattr(entry, "port", "?")),
            "age": round(max(0.0, now - last_seen), 1),
        })
    entries.sort(key=lambda item: item["ip"])

    return {
        "dpid": str(getattr(connection, "dpid", "?")),
        "state": "DOWN" if getattr(connection, "disconnected", False) else "UP",
        "entries": entries,
    }


def _snapshot():
    now = time.time()
    routers = [_router_snapshot(router, now) for router in _discover_routers()]
    routers.sort(key=lambda item: item["dpid"])
    return {"time": now, "routers": routers}


def _serve_connection(conn):
    try:
        conn.settimeout(2.0)
        if conn.recv(64).strip().upper() != b"GET":
            return
        payload = json.dumps(_snapshot()).encode("utf-8") + b"\n"
        conn.sendall(payload)
    except Exception as exc:
        log.debug("[ARP MONITOR] Error atendiendo cliente: %s", exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _server_loop():
    global _server_socket

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((MONITOR_HOST, MONITOR_PORT))
        server.listen(5)
        server.settimeout(0.5)
        _server_socket = server
    except Exception as exc:
        log.error("[ARP MONITOR] No se pudo abrir %s:%s: %s", MONITOR_HOST, MONITOR_PORT, exc)
        return

    log.info("[ARP MONITOR] Servidor escuchando en %s:%s", MONITOR_HOST, MONITOR_PORT)

    while not _server_stop.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_serve_connection, args=(conn,), daemon=True).start()

    try:
        server.close()
    except Exception:
        pass


def _handle_DownEvent(event):
    _server_stop.set()
    if _server_socket is not None:
        try:
            _server_socket.close()
        except Exception:
            pass


def launch():
    _install_hook()
    _scan_existing_routers()
    _server_stop.clear()
    threading.Thread(target=_server_loop, daemon=True).start()
    core.addListenerByName("DownEvent", _handle_DownEvent)
    log.info("[ARP MONITOR] Ejecutá arp_monitor.py en otra terminal")
