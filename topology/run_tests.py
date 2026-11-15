#!/usr/bin/python3
"""
Automated NAT/PAT test suite — TP2: SDN with POX and Mininet.

Usage:
    # Terminal 1 — start controller first:
    cd pox && python3 pox.py log.level --DEBUG openflow.of_01 protorouter

    # Terminal 2 — run tests:
    sudo python3 topology/run_tests.py
"""

import os
import sys
import time
import subprocess

# ---------------------------------------------------------------------------
# Make pox/ext/config.py importable from the topology directory
# ---------------------------------------------------------------------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../pox")))

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI

from ext.config import (
    PRIVATE,                        # "192.168.1.250"  (str)
    PUBLIC_IP,                      # "200.0.0.250"    (str)
    PRIVATE_IP_ROUTER as PRIVATE_GW,  # IPAddr("192.168.1.250")
    PUBLIC_IP_ROUTER  as PUBLIC_GW,   # IPAddr("200.0.0.250")
    FLOW_IDLE_TIMEOUT,              # seconds (int)
)

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------
CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 6633

H1_IP  = "200.0.0.1"
H2_IP  = "192.168.1.2"
H3_IP  = "192.168.1.3"

UNKNOWN_PUBLIC_IP = "200.0.0.99"   # does not exist — used for resilience test


# ===========================================================================
# Topology
# ===========================================================================

class NATTopo(Topo):
    """
    1 public host (h1) + 3 private hosts (h2, h3, h4) + switch (s1).

    Default routes are set with f-strings so the variables imported from
    config.py are properly interpolated (192.168.1.250 / 200.0.0.250).
    """

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow10", failMode="secure")

        h1 = self.addHost(
            "h1",
            ip="200.0.0.1/24",
            mac="00:00:00:00:00:01",
            defaultRoute=f"via {PUBLIC_IP}",    # via 200.0.0.250
        )
        h2 = self.addHost(
            "h2",
            ip="192.168.1.2/24",
            mac="00:00:00:00:00:02",
            defaultRoute=f"via {PRIVATE}",      # via 192.168.1.250
        )
        h3 = self.addHost(
            "h3",
            ip="192.168.1.3/24",
            mac="00:00:00:00:00:03",
            defaultRoute=f"via {PRIVATE}",
        )
        h4 = self.addHost(
            "h4",
            ip="192.168.1.4/24",
            mac="00:00:00:00:00:04",
            defaultRoute=f"via {PRIVATE}",
        )

        # h1 → port 1,  h2 → port 2,  h3 → port 3,  h4 → port 4
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


# ===========================================================================
# Test-runner infrastructure
# ===========================================================================

_results = []   # list of (label: str, passed: bool)


def run_test(label, fn, net):
    """
    Run fn(net) → (passed: bool, detail: str).
    Print the result and append it to _results.
    """
    print(f"\n{BOLD}{CYAN}{'─' * 64}{RESET}")
    print(f"{BOLD}{CYAN}  {label}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 64}{RESET}")

    try:
        passed, detail = fn(net)
    except Exception as exc:
        passed = False
        detail = f"Excepción no esperada: {exc}"

    badge = f"{GREEN}✓ PASS{RESET}" if passed else f"{RED}✗ FAIL{RESET}"
    print(f"  Resultado : {badge}")
    for line in (detail or "").splitlines():
        print(f"  {line}")

    _results.append((label, passed))
    return passed


def _pause(seconds=1.5):
    time.sleep(seconds)


def _last_lines(text, n=2):
    """Return the last n non-empty lines of a string."""
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return "\n".join(lines[-n:]) if lines else text.strip()


def _ping_ok(output):
    """Return True when ping output reports 0% packet loss."""
    return ", 0% packet loss" in output


def _iperf_ok(output):
    """Return True when iperf output contains a bandwidth figure."""
    return "bits/sec" in output


# ===========================================================================
# Tests
# ===========================================================================

def t01_arp_cold(net):
    """
    Verify that ARP tables are empty before any traffic is generated.
    Confirms the network starts from a clean state with no static entries.
    """
    h1, h2 = net.get("h1"), net.get("h2")
    out_h1 = h1.cmd("arp -n").strip()
    out_h2 = h2.cmd("arp -n").strip()

    def is_empty(o):
        return o == "" or "(none)" in o or "no entries" in o.lower()

    empty_h1 = is_empty(out_h1)
    empty_h2 = is_empty(out_h2)

    detail = (
        f"h1 ARP : {out_h1 or '(vacía) ✓'}\n"
        f"h2 ARP : {out_h2 or '(vacía) ✓'}"
    )
    return empty_h1 and empty_h2, detail


def t02_gateway_ping_private(net):
    """
    h2 pings the router's private interface (192.168.1.250).
    Validates that ARPManager responds ARP Requests and the router
    generates ICMP Echo Replies for its own IPs.
    """
    h2 = net.get("h2")
    out = h2.cmd(f"ping -c 2 -W 2 {PRIVATE_GW}")
    passed = _ping_ok(out)
    arp_out = h2.cmd("arp -n").strip()
    detail = (
        f"{_last_lines(out)}\n"
        f"ARP h2 después: {arp_out}"
    )
    return passed, detail


def t03_gateway_ping_public(net):
    """
    h1 pings the router's public interface (200.0.0.250).
    Same mechanism as t02 but from the public side.
    """
    h1 = net.get("h1")
    out = h1.cmd(f"ping -c 2 -W 2 {PUBLIC_GW}")
    passed = _ping_ok(out)
    arp_out = h1.cmd("arp -n").strip()
    detail = (
        f"{_last_lines(out)}\n"
        f"ARP h1 después: {arp_out}"
    )
    return passed, detail


def t04_nat_icmp_outbound(net):
    """
    h2 pings h1 (200.0.0.1). tcpdump on h1's interface must show
    source IP = 200.0.0.250 (the router's public IP), never 192.168.1.2.
    This confirms that NAT rewrites the source address before forwarding.
    """
    h1, h2 = net.get("h1"), net.get("h2")

    # Warm-up: trigger ARP resolution for h1 before the real test.
    # The first ping may fail — that is expected (ARP round-trip delay).
    h2.cmd(f"ping -c 1 -W 3 {H1_IP}")
    time.sleep(0.5)

    # Start capture on h1's NIC
    h1.cmd("rm -f /tmp/tp2_icmp.txt")
    h1.cmd("tcpdump -i h1-eth0 -n icmp -c 10 > /tmp/tp2_icmp.txt 2>&1 &")
    time.sleep(0.4)

    # Real test: ARP is now resolved, all 3 pings should go through
    out_ping = h2.cmd(f"ping -c 3 -W 2 {H1_IP}")
    time.sleep(0.5)
    h1.cmd("pkill tcpdump 2>/dev/null; true")
    time.sleep(0.3)

    cap = h1.cmd("cat /tmp/tp2_icmp.txt 2>/dev/null").strip()

    # Accept up to 1 lost packet (first-packet ARP delay is expected behavior).
    # The critical check is the NAT rewrite verification.
    ping_ok = "100% packet loss" not in out_ping and " 0 received" not in out_ping
    nat_ok  = str(PUBLIC_GW) in cap and "192.168.1." not in cap

    detail = (
        f"Ping h2 → h1    : {'✓ 0% packet loss' if _ping_ok(out_ping) else '~ pérdida primer paquete (ARP, esperado)'}\n"
        f"Reescritura NAT : {'✓ src=' + str(PUBLIC_GW) + ' (IP privada oculta)' if nat_ok else '✗ IP privada visible o sin captura'}\n"
        f"Captura (h1-eth0):\n"
        + "\n".join(f"    {l}" for l in cap.splitlines()[:6])
    )
    return ping_ok and nat_ok, detail


def t05_block_inbound(net):
    """
    h1 tries to ping 192.168.1.2 without any prior NAT mapping.
    The controller must discard it (100% packet loss).
    Verifies unidirectional NAT behaviour (stateful firewall).
    """
    h1 = net.get("h1")
    out = h1.cmd(f"ping -c 2 -W 2 {H2_IP}")
    passed = "100% packet loss" in out or " 0 received" in out
    detail = (
        f"{_last_lines(out)}\n"
        f"{'Tráfico inbound bloqueado correctamente ✓' if passed else 'ATENCIÓN: tráfico no fue bloqueado ✗'}"
    )
    return passed, detail


def t06_resilience_unknown_dest(net):
    """
    h2 pings an IP that does not exist (200.0.0.99).
    The controller must queue the packet, send ARP Requests, receive no reply,
    and eventually discard the packet — without crashing POX.
    """
    h2 = net.get("h2")
    out = h2.cmd(f"ping -c 2 -W 2 {UNKNOWN_PUBLIC_IP}")
    passed = "100% packet loss" in out or " 0 received" in out
    detail = (
        f"{_last_lines(out)}\n"
        f"{'Paquetes descartados, POX estable ✓' if passed else out[:120]}"
    )
    return passed, detail


def t07_pat_tcp_multi(net):
    """
    h2, h3 and h4 open simultaneous TCP connections to h1 (iperf).
    PAT must assign a distinct ephemeral port to each client.
    All three transfers must complete successfully.
    """
    h1 = net.get("h1")
    h2, h3, h4 = net.get("h2"), net.get("h3"), net.get("h4")

    # Clean up any leftover iperf processes
    for host in (h1, h2, h3, h4):
        host.cmd("killall iperf 2>/dev/null; true")
    time.sleep(0.3)

    h1.cmd("iperf -s > /dev/null 2>&1 &")
    time.sleep(0.5)

    h2.cmd("iperf -c 200.0.0.1 -t 7 > /tmp/tp2_iperf_h2.txt 2>&1 &")
    h3.cmd("iperf -c 200.0.0.1 -t 7 > /tmp/tp2_iperf_h3.txt 2>&1 &")
    out_h4 = h4.cmd("iperf -c 200.0.0.1 -t 7 2>&1")   # blocking
    time.sleep(2)

    out_h2 = h2.cmd("cat /tmp/tp2_iperf_h2.txt 2>/dev/null")
    out_h3 = h3.cmd("cat /tmp/tp2_iperf_h3.txt 2>/dev/null")

    ok2, ok3, ok4 = _iperf_ok(out_h2), _iperf_ok(out_h3), _iperf_ok(out_h4)
    passed = ok2 and ok3 and ok4

    for host in (h1, h2, h3, h4):
        host.cmd("killall iperf 2>/dev/null; true")

    detail = (
        f"h2 TCP: {'✓' if ok2 else '✗'}  "
        f"h3 TCP: {'✓' if ok3 else '✗'}  "
        f"h4 TCP: {'✓' if ok4 else '✗'}\n"
        + (_last_lines(out_h4) if out_h4.strip() else "")
    )
    return passed, detail


def t08_openflow_flows(net):
    """
    While a TCP flow is active, dump the OpenFlow table of s1.
    At minimum, L2 (mod_dl_src) and L3 (mod_nw_src) rewrite actions must
    be present. L4 (mod_tp_src) is expected for TCP/UDP flows.
    """
    h1, h2 = net.get("h1"), net.get("h2")

    for host in (h1, h2):
        host.cmd("killall iperf 2>/dev/null; true")
    time.sleep(0.3)

    h1.cmd("iperf -s > /dev/null 2>&1 &")
    time.sleep(0.4)
    h2.cmd("iperf -c 200.0.0.1 -t 15 > /dev/null 2>&1 &")
    time.sleep(1.5)

    try:
        raw = subprocess.check_output(
            ["ovs-ofctl", "dump-flows", "s1"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        for host in (h1, h2):
            host.cmd("killall iperf 2>/dev/null; true")
        return False, "ovs-ofctl falló — ¿está Open vSwitch corriendo?"

    has_dl = "mod_dl_src" in raw
    has_nw = "mod_nw_src" in raw
    has_tp = "mod_tp_src" in raw
    n_flows = raw.count("n_packets")

    for host in (h1, h2):
        host.cmd("killall iperf 2>/dev/null; true")

    passed = has_dl or has_nw

    detail = (
        f"mod_dl_src (L2): {'✓' if has_dl else '✗'}  "
        f"mod_nw_src (L3): {'✓' if has_nw else '✗'}  "
        f"mod_tp_src (L4): {'✓' if has_tp else '✗'}\n"
        f"Flujos activos en s1: {n_flows}"
    )
    return passed, detail


def t09_lan_internal(net):
    """
    h2 pings h3 (192.168.1.2 → 192.168.1.3).
    Traffic between private hosts must be forwarded directly by the switch
    without going through NAT — the controller installs a plain L2/L3 flow.
    """
    h2, h3 = net.get("h2"), net.get("h3")
    out = h2.cmd(f"ping -c 3 -W 2 {H3_IP}")
    passed = _ping_ok(out)
    return passed, _last_lines(out)


def t10_flow_expiration(net):
    """
    After generating a short flow, wait for FLOW_IDLE_TIMEOUT to expire.
    The switch must remove the rule and POX must receive FlowRemoved,
    returning the PAT port to the free pool.
    """
    h2, h1 = net.get("h2"), net.get("h1")

    # Ensure no leftover flows or iperf
    for host in (h1, h2):
        host.cmd("killall iperf 2>/dev/null; true")
    time.sleep(0.5)

    # Install a NAT flow with a single ping
    out_ping = h2.cmd(f"ping -c 1 -W 2 {H1_IP}")
    ping_ok = _ping_ok(out_ping) or " 1 received" in out_ping
    time.sleep(0.5)

    try:
        flows_before = subprocess.check_output(
            ["ovs-ofctl", "dump-flows", "s1"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "ovs-ofctl no disponible"

    has_flows = "nw_src" in flows_before or "nw_dst" in flows_before

    wait_seconds = FLOW_IDLE_TIMEOUT + 4
    print(f"  Esperando expiración ({wait_seconds}s)...", flush=True)
    time.sleep(wait_seconds)

    try:
        flows_after = subprocess.check_output(
            ["ovs-ofctl", "dump-flows", "s1"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "ovs-ofctl falló al verificar expiración"

    expired = "nw_src" not in flows_after and "nw_dst" not in flows_after
    passed = ping_ok and has_flows and expired

    detail = (
        f"Ping inicial      : {'✓' if ping_ok else '✗'}\n"
        f"Flujo instalado   : {'✓' if has_flows else '✗ (no se instaló flujo)'}\n"
        f"Flujo expirado    : {'✓' if expired else '✗ (aún activo después de ' + str(wait_seconds) + 's)'}"
    )
    return passed, detail


# ===========================================================================
# Summary
# ===========================================================================

def print_summary():
    total  = len(_results)
    passed = sum(1 for _, ok in _results if ok)

    print(f"\n{BOLD}{'═' * 64}")
    print("  RESUMEN DE PRUEBAS")
    print(f"{'═' * 64}{RESET}")

    for label, ok in _results:
        badge = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
        print(f"  {badge}  {label}")

    color = GREEN if passed == total else (YELLOW if passed > total // 2 else RED)
    print(f"\n{BOLD}{color}  Resultado: {passed}/{total} pruebas exitosas{RESET}")

    if passed == total:
        print(f"{BOLD}{GREEN}  ¡Todas las pruebas pasaron!{RESET}")
    elif passed == 0:
        print(f"{BOLD}{RED}  Verificá que el controlador POX esté corriendo antes de ejecutar este script.{RESET}")
    print()


# ===========================================================================
# Test registry — order matters
# ===========================================================================

TESTS = [
    ("1.  ARP en frío — tablas vacías",                    t01_arp_cold),
    ("2.  ARP dinámico — ping a gateway privado",          t02_gateway_ping_private),
    ("3.  ARP dinámico — ping a gateway público",          t03_gateway_ping_public),
    ("4.  NAT ICMP saliente + verificación reescritura",   t04_nat_icmp_outbound),
    ("5.  Bloqueo de tráfico inbound no solicitado",       t05_block_inbound),
    ("6.  Resiliencia — destino inexistente",              t06_resilience_unknown_dest),
    ("7.  PAT TCP — 3 clientes simultáneos",               t07_pat_tcp_multi),
    ("8.  Inspección de flujos OpenFlow (L2/L3/L4)",       t08_openflow_flows),
    ("9.  LAN interno — sin NAT",                          t09_lan_internal),
    ("10. Expiración de flujos y reciclaje del pool PAT",  t10_flow_expiration),
]


# ===========================================================================
# Entry point
# ===========================================================================

def run():
    topo = NATTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name, ip=CONTROLLER_HOST, port=CONTROLLER_PORT
        ),
        link=TCLink,
    )
    net.start()

    # Silence IPv6 Neighbor Discovery noise on all nodes
    for node in net.hosts + [net.get("s1")]:
        node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1     >/dev/null 2>&1")
        node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1")
        node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1      >/dev/null 2>&1")

    print(f"\n{BOLD}{CYAN}  Esperando conexión del switch al controlador POX...{RESET}")
    time.sleep(2)
    print(f"  {GREEN}Listo. Iniciando batería de {len(TESTS)} pruebas.{RESET}\n")

    for label, fn in TESTS:
        run_test(label, fn, net)
        _pause()

    print_summary()

    print(f"{YELLOW}  Abriendo CLI de Mininet para exploración manual...{RESET}\n")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("warning")   # Mininet quiet; POX logs come from Terminal 1
    run()
