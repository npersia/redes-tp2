from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
from pox.lib.recoco import Timer
from pox.lib.revent import Event, EventMixin
from collections import defaultdict
import time

log = core.getLogger()
# TODO explicar que significa cada color
# Estilos para Logs
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


# Configuración de Red Base
PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24
PRIVATE_IP = IPAddr("192.168.1.254")
PUBLIC_IP = IPAddr("200.0.0.254")
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT = 1

FLOW_IDLE_TIMEOUT = 30  # Timeout de inactividad para liberar flujos en segundos

ARP_TIMEOUT = 5  # Tiempo de vida de una entrada ARP sin actualizarse
ARP_CLEAN_INTERVAL = 3  # Intervalo de limpieza de la tabla ARP en segundos


class ARPEntry(object):
    """Entrada de la tabla ARP con su última actualización y puerto físico."""

    def __init__(self, mac, port):
        self.mac = mac
        self.port = port
        self.last_seen = time.time()

    def refresh(self, mac=None, port=None):
        if mac is not None:
            self.mac = mac
        if port is not None:
            self.port = port
        self.last_seen = time.time()

    @property
    def expired(self):
        return time.time() - self.last_seen > ARP_TIMEOUT


class ARPRemoved(Event):
    """Evento emitido cuando una entrada ARP expira."""

    def __init__(self, ip, mac, port):
        Event.__init__(self)
        self.ip = ip
        self.mac = mac
        self.port = port


class ARPManager(EventMixin):
    """Mantiene la tabla ARP dinámica, mapeo de puertos LAN, responde consultas al router y encola paquetes."""

    _eventMixin_events = {ARPRemoved}

    def __init__(self):
        EventMixin.__init__(self)
        self.arp_table = {}  # IPAddr -> ARPEntry
        self.pending_packets = defaultdict(list)  # IPAddr -> list(events)
        self._cleaner = Timer(ARP_CLEAN_INTERVAL, self._expire_entries, recurring=True)

    def _expire_entries(self):
        for ip, entry in list(self.arp_table.items()):
            if entry.expired:
                del self.arp_table[ip]
                self.pending_packets.pop(ip, None)
                self.raiseEvent(ARPRemoved, ip, entry.mac, entry.port)

    def shutdown(self):
        if self._cleaner:
            self._cleaner.cancel()
            self._cleaner = None

    def handle_arp(self, connection, event):
        packet = event.parsed
        arp_pkt = packet.find('arp')
        in_port = event.port

        if not arp_pkt:
            return None

        # Aprender dirección MAC y Puerto físico del emisor
        entry = self.arp_table.get(arp_pkt.protosrc)
        if entry is None:
            self.arp_table[arp_pkt.protosrc] = ARPEntry(arp_pkt.hwsrc, in_port)
        else:
            entry.refresh(arp_pkt.hwsrc, in_port)

        # 1. ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            if arp_pkt.protodst == PRIVATE_IP:
                log_color(CYAN, f"[ARP] Respondiendo a {arp_pkt.protosrc} por IP Privada {PRIVATE_IP}")
                self._send_arp_reply(connection, in_port, PRIVATE_MAC, PRIVATE_IP, arp_pkt.hwsrc, arp_pkt.protosrc)
            elif arp_pkt.protodst == PUBLIC_IP:
                log_color(CYAN, f"[ARP] Respondiendo a {arp_pkt.protosrc} por IP Pública {PUBLIC_IP}")
                self._send_arp_reply(connection, in_port, PUBLIC_MAC, PUBLIC_IP, arp_pkt.hwsrc, arp_pkt.protosrc)
            elif arp_pkt.protodst.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                # Consulta entre hosts locales (ej: h3 buscando a h2) -> Inundar a la LAN
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                connection.send(msg)

        # 2. ARP Reply
        elif arp_pkt.opcode == arp.REPLY:
            log_color(GREEN, f"[ARP] Aprendida MAC de {arp_pkt.protosrc} -> {arp_pkt.hwsrc} (Puerto {in_port})")

            # Reenviar respuesta ARP local si no era para las IPs del router
            if arp_pkt.protodst != PRIVATE_IP and arp_pkt.protodst != PUBLIC_IP:
                reply_entry = self.arp_table.get(arp_pkt.protodst)
                dst_port = reply_entry.port if reply_entry else of.OFPP_FLOOD
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=dst_port))
                connection.send(msg)

            if arp_pkt.protosrc in self.pending_packets:
                return self.pending_packets.pop(arp_pkt.protosrc)

        return None

    def request_mac(self, connection, out_port, src_mac, src_ip, dst_ip):
        """Envía un ARP Request para descubrir una MAC desconocida."""
        log_color(YELLOW, f"[ARP] Consultando MAC para IP {dst_ip}...")
        r = arp()
        r.opcode = arp.REQUEST
        r.hwsrc = src_mac
        r.hwdst = EthAddr("00:00:00:00:00:00")
        r.protosrc = src_ip
        r.protodst = dst_ip

        e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=EthAddr("ff:ff:ff:ff:ff:ff"))
        e.payload = r

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        connection.send(msg)

    def _send_arp_reply(self, connection, port, src_mac, src_ip, dst_mac, dst_ip):
        r = arp()
        r.opcode = arp.REPLY
        r.hwsrc = src_mac
        r.hwdst = dst_mac
        r.protosrc = src_ip
        r.protodst = dst_ip

        e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=dst_mac)
        e.payload = r

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=port))
        connection.send(msg)


class PATManager(object):
    """Administra el pool de puertos públicos efímeros y la tabla de traducción PAT."""

    def __init__(self, start_port=10000, end_port=65000):
        self.free_ports = set(range(start_port, end_port + 1))
        self.outbound_map = {}  # (src_ip, src_port, proto) -> nat_port
        self.inbound_map = {}  # (nat_port, proto) -> (src_ip, src_port)

    def get_or_assign(self, src_ip, src_port, proto):
        key = (src_ip, src_port, proto)
        if key in self.outbound_map:
            return self.outbound_map[key]

        if not self.free_ports:
            log_color(RED, "[PAT ERROR] Puertos agotados")
            return None

        nat_port = self.free_ports.pop()
        self.outbound_map[key] = nat_port
        self.inbound_map[(nat_port, proto)] = (src_ip, src_port)
        log_color(GREEN, f"[PAT MAP] {src_ip}:{src_port} <-> {PUBLIC_IP}:{nat_port} (Proto: {proto})")
        return nat_port

    def release_port(self, nat_port, proto):
        key = (nat_port, proto)
        if key in self.inbound_map:
            src_ip, src_port = self.inbound_map.pop(key)
            self.outbound_map.pop((src_ip, src_port, proto), None)
            self.free_ports.add(nat_port)
            log_color(YELLOW, f"[PAT RELEASE] Puerto {nat_port} devuelto al pool")


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.arp_mgr = ARPManager()
        self.pat_mgr = PATManager()
        self.arp_mgr.addListeners(self)

    def _handle_ARPRemoved(self, event):
        log_color(YELLOW, f"[ARP EXPIRE] {event.ip} -> {event.mac} (Puerto {event.port})")

    def _handle_ConnectionDown(self, event):
        self.arp_mgr.shutdown()

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            return

        packet = event.parsed

        # 1. Tráfico ARP
        if packet.type == ethernet.ARP_TYPE:
            pending_events = self.arp_mgr.handle_arp(self.connection, event)
            if pending_events:
                for pending_ev in pending_events:
                    self._handle_PacketIn(pending_ev)
            return

        # 2. Tráfico IP
        if packet.type == ethernet.IP_TYPE:
            self.process_ip(event)

    def process_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.find('ipv4')
        in_port = event.port

        if not ip_pkt:
            return

        proto = ip_pkt.protocol
        src_ip = ip_pkt.srcip
        dst_ip = ip_pkt.dstip

        # 0. Tráfico ICMP dirigido a las propias IPs del Router (Ping al Gateway)
        if dst_ip == PRIVATE_IP or dst_ip == PUBLIC_IP:
            icmp_pkt = packet.find('icmp')
            if icmp_pkt and icmp_pkt.type == 8:  # 8 = ICMP Echo Request
                log_color(CYAN, f"[ICMP Router] Respondiendo Ping a IP local {dst_ip} desde {src_ip}")

                reply_icmp = icmp()
                reply_icmp.type = 0  # 0 = ICMP Echo Reply
                reply_icmp.payload = icmp_pkt.payload

                reply_ip = ipv4()
                reply_ip.protocol = ipv4.ICMP_PROTOCOL
                reply_ip.srcip = dst_ip
                reply_ip.dstip = src_ip
                reply_ip.payload = reply_icmp

                router_mac = PRIVATE_MAC if dst_ip == PRIVATE_IP else PUBLIC_MAC
                reply_eth = ethernet()
                reply_eth.type = ethernet.IP_TYPE
                reply_eth.src = router_mac
                reply_eth.dst = packet.src
                reply_eth.payload = reply_ip

                msg = of.ofp_packet_out()
                msg.data = reply_eth.pack()
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
                self.connection.send(msg)
            return

        # 0.5. Tráfico LAN Local sin NAT (Privado -> Privado, ej: h3 -> h2)
        if src_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK) and dst_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            dst_entry = self.arp_mgr.arp_table.get(dst_ip)
            dst_port = dst_entry.port if dst_entry else None
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = in_port

            if dst_port:
                msg.actions.append(of.ofp_action_output(port=dst_port))
                # Instalar flujo directo L2/L3 en el switch para conmutación local rápida
                fm = of.ofp_flow_mod()
                fm.idle_timeout = FLOW_IDLE_TIMEOUT
                fm.match.in_port = in_port
                fm.match.dl_type = 0x0800
                fm.match.nw_src = src_ip
                fm.match.nw_dst = dst_ip
                fm.actions.append(of.ofp_action_output(port=dst_port))
                self.connection.send(fm)
            else:
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

            self.connection.send(msg)
            return

        # 1. Tráfico Saliente (Red Privada -> Red Pública con NAT/PAT)
        if src_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            # Obtener/Resolver MAC de Destino
            dst_entry = self.arp_mgr.arp_table.get(dst_ip)
            dst_mac = dst_entry.mac if dst_entry else None
            if not dst_mac:
                self.arp_mgr.pending_packets[dst_ip].append(event)
                self.arp_mgr.request_mac(self.connection, PUBLIC_PORT, PUBLIC_MAC, PUBLIC_IP, dst_ip)
                return

            l4_pkt = packet.find('tcp') or packet.find('udp')

            # Caso TCP / UDP (Con PAT)
            if l4_pkt:
                src_port = l4_pkt.srcport
                dst_port = l4_pkt.dstport

                nat_port = self.pat_mgr.get_or_assign(src_ip, src_port, proto)
                if not nat_port:
                    return

                # Flujo Saliente
                fm_out = of.ofp_flow_mod()
                fm_out.idle_timeout = FLOW_IDLE_TIMEOUT
                fm_out.match.in_port = in_port
                fm_out.match.dl_type = 0x0800
                fm_out.match.nw_proto = proto
                fm_out.match.nw_src = src_ip
                fm_out.match.nw_dst = dst_ip
                fm_out.match.tp_src = src_port
                fm_out.match.tp_dst = dst_port

                fm_out.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
                fm_out.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                fm_out.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
                fm_out.actions.append(of.ofp_action_tp_port.set_src(nat_port))
                fm_out.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
                self.connection.send(fm_out)

                # Flujo Entrante
                fm_in = of.ofp_flow_mod()
                fm_in.idle_timeout = FLOW_IDLE_TIMEOUT
                fm_in.flags |= of.OFPFF_SEND_FLOW_REM
                fm_in.match.in_port = PUBLIC_PORT
                fm_in.match.dl_type = 0x0800
                fm_in.match.nw_proto = proto
                fm_in.match.nw_src = dst_ip
                fm_in.match.nw_dst = PUBLIC_IP
                fm_in.match.tp_src = dst_port
                fm_in.match.tp_dst = nat_port

                fm_in.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
                fm_in.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
                fm_in.actions.append(of.ofp_action_nw_addr.set_dst(src_ip))
                fm_in.actions.append(of.ofp_action_tp_port.set_dst(src_port))
                fm_in.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(fm_in)

                # Reenviar primer paquete (PacketOut)
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = fm_out.actions
                self.connection.send(msg)

            # Caso ICMP / Ping atravesando NAT
            elif packet.find('icmp'):
                fm_out = of.ofp_flow_mod()
                fm_out.idle_timeout = FLOW_IDLE_TIMEOUT
                fm_out.match.in_port = in_port
                fm_out.match.dl_type = 0x0800
                fm_out.match.nw_proto = proto
                fm_out.match.nw_src = src_ip
                fm_out.match.nw_dst = dst_ip

                fm_out.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
                fm_out.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
                fm_out.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
                fm_out.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
                self.connection.send(fm_out)

                fm_in = of.ofp_flow_mod()
                fm_in.idle_timeout = FLOW_IDLE_TIMEOUT
                fm_in.match.in_port = PUBLIC_PORT
                fm_in.match.dl_type = 0x0800
                fm_in.match.nw_proto = proto
                fm_in.match.nw_src = dst_ip
                fm_in.match.nw_dst = PUBLIC_IP

                fm_in.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
                fm_in.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
                fm_in.actions.append(of.ofp_action_nw_addr.set_dst(src_ip))
                fm_in.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(fm_in)

                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = fm_out.actions
                self.connection.send(msg)

    def _handle_FlowRemoved(self, event):
        """Libera los puertos PAT cuando expiran las reglas."""
        ofp = event.ofp
        if ofp.match.dl_type == 0x0800 and ofp.match.nw_dst == PUBLIC_IP:
            nat_port = ofp.match.tp_dst
            proto = ofp.match.nw_proto
            if nat_port and proto:
                self.pat_mgr.release_port(nat_port, proto)


def launch():
    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter NAT/PAT en Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)