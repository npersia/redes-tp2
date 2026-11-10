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
# [MONITOR ARP/NAT] Import exclusivo del monitor; no afecta el comportamiento del protorouter.
import threading
import time
# TODO: no cerrar el popup antes del protorouter
# TODO: agregar un env para variables de configuracion (timeouts)
log = core.getLogger()
# Estilos para Logs
#
# Leyenda de colores:
#   VERDE   -> Aprendizaje / alta exitosa: nueva MAC aprendida (tabla ARP),
#              entrada ARP actualizada, nuevo mapeo NAT/PAT.
#   AZUL    -> Regla de flujo instalada en el switch (flow_mod): flujos LAN y
#              flujos NAT saliente/entrante (TCP/UDP e ICMP).
#   CIAN    -> Tráfico / forwarding normal: reenvíos LAN, ARP request/reply,
#              ping al router, desencolado de paquetes, PAT HIT y reenvío del
#              primer paquete.
#   MAGENTA -> Ciclo de vida / configuración: inicio del router, tabla ARP,
#              pool PAT, conexión OpenFlow arriba/abajo y arranque del módulo.
#   AMARILLO-> Advertencia / evento esperable pero no ideal: entrada ARP
#              vencida, MAC desconocida (encolar/inundar), request no
#              gestionado, liberación de PAT, protocolo/opcode no soportado.
#   ROJO    -> Error real: puertos PAT agotados, paquete inválido/no parseable.
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
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

FLOW_IDLE_TIMEOUT = 5  # Timeout de inactividad para liberar flujos en segundos

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
        log_color(MAGENTA, f"[ARP] Tabla ARP iniciada (timeout={ARP_TIMEOUT}s, limpieza cada {ARP_CLEAN_INTERVAL}s)")

    def _expire_entries(self):
        if self.arp_table:
            log.debug(f"[ARP CLEAN] Revisando {len(self.arp_table)} entrada(s) ARP")
        for ip, entry in list(self.arp_table.items()):
            if entry.expired:
                del self.arp_table[ip]
                pending = self.pending_packets.pop(ip, [])
                log_color(YELLOW, f"[ARP CLEAN] Entrada vencida: {ip} -> {entry.mac} (Puerto {entry.port}), {len(pending)} paquete(s) pendiente(s) descartado(s)")
                self.raiseEvent(ARPRemoved, ip, entry.mac, entry.port)

    def shutdown(self):
        if self._cleaner:
            log_color(MAGENTA, "[ARP] Deteniendo limpieza periódica de la tabla ARP")
            self._cleaner.cancel()
            self._cleaner = None

    # [MONITOR ARP/NAT] Método exclusivo del monitor; no afecta el comportamiento del protorouter.
    def snapshot(self):
        """Devuelve una copia de la tabla ARP para monitoreo."""
        return [
            (ip, entry.mac, entry.port, entry.last_seen)
            for ip, entry in self.arp_table.copy().items()
        ]

    def handle_arp(self, connection, event):
        packet = event.parsed
        arp_pkt = packet.find('arp')
        in_port = event.port

        if not arp_pkt:
            log_color(RED, f"[ARP] Paquete ARP inválido o no parseable en puerto {in_port}")
            return None

        # Aprender dirección MAC y Puerto físico del emisor
        entry = self.arp_table.get(arp_pkt.protosrc)
        if entry is None:
            self.arp_table[arp_pkt.protosrc] = ARPEntry(arp_pkt.hwsrc, in_port)
            log_color(GREEN, f"[ARP] Nueva entrada: {arp_pkt.protosrc} -> {arp_pkt.hwsrc} (Puerto {in_port})")
        else:
            entry.refresh(arp_pkt.hwsrc, in_port)
            log_color(GREEN, f"[ARP] Entrada actualizada: {arp_pkt.protosrc} -> {arp_pkt.hwsrc} (Puerto {in_port})")

        # 1. ARP Request
        if arp_pkt.opcode == arp.REQUEST:
            log_color(CYAN, f"[ARP] Request de {arp_pkt.protosrc} ({arp_pkt.hwsrc}) preguntando por {arp_pkt.protodst}")
            if arp_pkt.protodst == PRIVATE_IP:
                log_color(CYAN, f"[ARP] Respondiendo a {arp_pkt.protosrc} por IP Privada {PRIVATE_IP}")
                self._send_arp_reply(connection, in_port, PRIVATE_MAC, PRIVATE_IP, arp_pkt.hwsrc, arp_pkt.protosrc)
            elif arp_pkt.protodst == PUBLIC_IP:
                log_color(CYAN, f"[ARP] Respondiendo a {arp_pkt.protosrc} por IP Pública {PUBLIC_IP}")
                self._send_arp_reply(connection, in_port, PUBLIC_MAC, PUBLIC_IP, arp_pkt.hwsrc, arp_pkt.protosrc)
            elif arp_pkt.protodst.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
                # Consulta entre hosts locales (ej: h3 buscando a h2) -> Inundar a la LAN
                log_color(CYAN, f"[ARP] Request local por {arp_pkt.protodst}; inundando la LAN")
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                connection.send(msg)
            else:
                log_color(YELLOW, f"[ARP] Request no gestionado para {arp_pkt.protodst}; ignorado")

        # 2. ARP Reply
        elif arp_pkt.opcode == arp.REPLY:
            log_color(CYAN, f"[ARP] Reply de {arp_pkt.protosrc} ({arp_pkt.hwsrc}) para {arp_pkt.protodst}")

            # Reenviar respuesta ARP local si no era para las IPs del router
            if arp_pkt.protodst != PRIVATE_IP and arp_pkt.protodst != PUBLIC_IP:
                reply_entry = self.arp_table.get(arp_pkt.protodst)
                dst_port = reply_entry.port if reply_entry else of.OFPP_FLOOD
                dst_desc = "FLOOD" if dst_port == of.OFPP_FLOOD else f"puerto {dst_port}"
                log_color(CYAN, f"[ARP] Reenviando Reply a {arp_pkt.protodst} por {dst_desc}")
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions.append(of.ofp_action_output(port=dst_port))
                connection.send(msg)

            if arp_pkt.protosrc in self.pending_packets:
                pending = self.pending_packets.pop(arp_pkt.protosrc)
                log_color(CYAN, f"[ARP] Desencolando {len(pending)} paquete(s) pendiente(s) para {arp_pkt.protosrc}")
                return pending
        else:
            log_color(YELLOW, f"[ARP] Opcode no soportado {arp_pkt.opcode}; ignorado")

        return None

    def request_mac(self, connection, out_port, src_mac, src_ip, dst_ip):
        """Envía un ARP Request para descubrir una MAC desconocida."""
        log_color(YELLOW, f"[ARP] Consultando MAC para IP {dst_ip} (src={src_ip}/{src_mac}, salida por puerto {out_port})")
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
        log_color(YELLOW, f"[ARP] Request enviado por {dst_ip} a través del puerto {out_port}")

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
        log_color(CYAN, f"[ARP] Reply enviado: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac}) por puerto {port}")


class PATManager(object):
    """Administra el pool de puertos públicos efímeros y la tabla de traducción PAT."""

    def __init__(self, start_port=10000, end_port=65000):
        self.free_ports = set(range(start_port, end_port + 1))
        self.outbound_map = {}  # (src_ip, src_port, proto) -> nat_port
        self.inbound_map = {}  # (nat_port, proto) -> (src_ip, src_port)
        # [MONITOR ARP/NAT] Dato adicional para mostrar el destino en la ventana; no afecta el mapeo PAT.
        self.destination_map = {}  # (src_ip, src_port, proto) -> (dst_ip, dst_port)


        # traducciones ICMP
        self.icmp_entries = {}
        self.icmp_outbound_map = {}
        self._next_icmp_id = 1

        log_color(MAGENTA, f"[PAT] Pool inicializado: {start_port}-{end_port} ({len(self.free_ports)} puertos libres)")

    def _allocate_icmp_id(self):
        """Busca un identificador ICMP público disponible."""

        for _ in range(65535):
            candidate = self._next_icmp_id

            self._next_icmp_id += 1
            if self._next_icmp_id > 65535:
                self._next_icmp_id = 1

            if candidate not in self.icmp_entries:
                return candidate

        return None

    def register_icmp(self, src_ip, dst_ip, original_id, src_mac, in_port):
        """Busca o crea una traducción ICMP."""


        key = (src_ip, dst_ip, original_id)

        # ¿Ya existe una traducción para este tráfico?
        translated_id = self.icmp_outbound_map.get(key)

        if translated_id is not None:
            entry = self.icmp_entries[translated_id]
            entry["last_seen"] = time.time()
            entry["src_mac"] = src_mac
            entry["in_port"] = in_port
            return translated_id

        # Crear una nueva traducción
        translated_id = self._allocate_icmp_id()

        if translated_id is None:
            log_color(RED, "[NAT ICMP] Identificadores agotados")
            return None

        self.icmp_entries[translated_id] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "original_id": original_id,
            "translated_id": translated_id,
            "src_mac": src_mac,
            "in_port": in_port,
            "last_seen": time.time()
        }

        self.icmp_outbound_map[key] = translated_id

        log_color(
            GREEN,
            f"[NAT ICMP MAP] {src_ip} -> {dst_ip} "
            f"ID {original_id} => {translated_id}"
        )

        return translated_id

    def get_icmp_by_translated_id(self, translated_id, remote_ip=None):
        """Busca la traducción correspondiente a una respuesta ICMP."""


        entry = self.icmp_entries.get(translated_id)

        if entry is None:
            return None

        # Verificar que responda el destino al que enviamos el ping
        if remote_ip is not None and entry["dst_ip"] != remote_ip:
            return None

        entry["last_seen"] = time.time()

        return entry

    def release_icmp(self, translated_id):
        """Elimina una traducción ICMP."""

        entry = self.icmp_entries.pop(translated_id, None)

        if entry is not None:
            key = (
                entry["src_ip"],
                entry["dst_ip"],
                entry["original_id"]
            )

            self.icmp_outbound_map.pop(key, None)

            log_color(
                YELLOW,
                f"[NAT ICMP RELEASE] ID {translated_id} liberado"
            )

        return entry


    # [MONITOR ARP/NAT] Método exclusivo del monitor; no afecta el comportamiento del protorouter.
    def snapshot(self):
        """Devuelve una copia de los mapeos NAT/PAT para monitoreo."""
        entries = []

        # entradas TCP y UDP
        for key, nat_port in self.outbound_map.copy().items():
            src_ip, src_port, proto = key
            dst_ip, dst_port = self.destination_map.get(key, (None, None))
            entries.append((src_ip, src_port, proto, nat_port, dst_ip, dst_port))

        # entradas ICMP
        for entry in self.icmp_entries.values():
            entries.append((
                entry["src_ip"],
                None,
                ipv4.ICMP_PROTOCOL,
                None,
                entry["dst_ip"],
                None
            ))
        return entries

    # [MONITOR ARP/NAT] Método exclusivo del monitor; no afecta el comportamiento del protorouter.
    def free_count(self):
        """Cantidad de puertos PAT disponibles."""
        return len(self.free_ports)

    def get_or_assign(self, src_ip, src_port, proto, dst_ip=None, dst_port=None):
        key = (src_ip, src_port, proto)

        if key in self.outbound_map:
            # [MONITOR ARP/NAT] Solo guarda el destino para la ventana; no altera el mapeo PAT.
            if dst_ip is not None or dst_port is not None:
                self.destination_map[key] = (dst_ip, dst_port)
            nat_port = self.outbound_map[key]
            log_color(CYAN, f"[PAT HIT] {src_ip}:{src_port} (Proto: {proto}) ya mapeado a {PUBLIC_IP}:{nat_port}")
            return nat_port

        if not self.free_ports:
            log_color(RED, "[PAT ERROR] Puertos agotados")
            return None

        nat_port = self.free_ports.pop()
        self.outbound_map[key] = nat_port
        self.inbound_map[(nat_port, proto)] = (src_ip, src_port)
        # [MONITOR ARP/NAT] Solo guarda el destino para la ventana; no altera el mapeo PAT.
        if dst_ip is not None or dst_port is not None:
            self.destination_map[key] = (dst_ip, dst_port)
        log_color(GREEN, f"[PAT MAP] {src_ip}:{src_port} <-> {PUBLIC_IP}:{nat_port} (Proto: {proto}) [libres: {len(self.free_ports)}]")
        return nat_port

    def release_port(self, nat_port, proto):
        key = (nat_port, proto)
        if key in self.inbound_map:
            src_ip, src_port = self.inbound_map.pop(key)
            self.outbound_map.pop((src_ip, src_port, proto), None)
            # [MONITOR ARP/NAT] Limpia el dato mostrado en la ventana; no afecta el mapeo PAT.
            self.destination_map.pop((src_ip, src_port, proto), None)
            self.free_ports.add(nat_port)
            log_color(YELLOW, f"[PAT RELEASE] Puerto {nat_port} ({src_ip}:{src_port}, Proto: {proto}) devuelto al pool [libres: {len(self.free_ports)}]")
        else:
            log.debug(f"[PAT RELEASE] Ignorado: no existe mapeo para puerto {nat_port} (Proto: {proto})")


# [MONITOR ARP/NAT] Clase exclusiva del monitor visual; no participa del ruteo ni del NAT.
class TablesPopupMonitor(object):
    """Ventana Tkinter con las tablas ARP y NAT/PAT del router."""

    REFRESH_INTERVAL_MS = 1000
    TABLES = ("ARP", "NAT/PAT")

    def __init__(self, arp_mgr, pat_mgr, dpid="?"):
        self.arp_mgr = arp_mgr
        self.pat_mgr = pat_mgr
        self.dpid = dpid
        self._root = None
        self._text = None
        self._table_var = None
        self._closed = False
        self._thread = threading.Thread(
            target=self._run,
            name=f"TablesPopupMonitor-{dpid}",
            daemon=True,
        )
        self._thread.start()

    def _run(self):
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as exc:
            log_color(YELLOW, f"[POPUP] Tkinter no disponible: {exc}")
            return

        try:
            root = tk.Tk()
            root.title(f"ProtoRouter - Tablas ARP / NAT (dpid={self.dpid})")
            root.geometry("720x420")
            root.minsize(560, 260)
            root.configure(background="#111111")
            root.protocol("WM_DELETE_WINDOW", self._on_close)

            controls = tk.Frame(root, background="#111111")
            controls.pack(fill="x", padx=8, pady=(8, 0))

            label = tk.Label(
                controls,
                text="Tabla:",
                background="#111111",
                foreground="#00ff88",
                font=("Courier", 10),
            )
            label.pack(side="left")

            self._table_var = tk.StringVar(master=root, value=self.TABLES[0])
            combo = ttk.Combobox(
                controls,
                textvariable=self._table_var,
                values=self.TABLES,
                state="readonly",
                width=12,
            )
            combo.pack(side="left", padx=6)
            combo.bind("<<ComboboxSelected>>", self._on_table_changed)

            text = tk.Text(
                root,
                font=("Courier", 10),
                background="#111111",
                foreground="#00ff88",
                insertbackground="#00ff88",
                borderwidth=0,
                highlightthickness=0,
            )
            text.pack(fill="both", expand=True, padx=8, pady=8)
            text.configure(state="disabled")

            self._root = root
            self._text = text
            self._refresh()
            self._schedule_refresh()
            log_color(MAGENTA, f"[POPUP] Ventana abierta (dpid={self.dpid})")
            root.mainloop()
        except Exception as exc:
            log_color(YELLOW, f"[POPUP] No se pudo abrir la ventana: {exc}")
        finally:
            self._destroy()

    def _on_table_changed(self, event=None):
        self._refresh()

    def _schedule_refresh(self):
        if self._closed or self._root is None:
            return
        self._root.after(self.REFRESH_INTERVAL_MS, self._tick)

    def _tick(self):
        if self._closed or self._root is None:
            self._destroy()
            return

        try:
            self._refresh()
            self._schedule_refresh()
        except Exception as exc:
            log_color(YELLOW, f"[POPUP] Ventana cerrada o error: {exc}")
            self._on_close()

    def _refresh(self):
        if self._text is None:
            return

        now = time.time()
        selected = self._table_var.get() if self._table_var is not None else self.TABLES[0]

        if selected == "NAT/PAT":
            lines = self._format_nat(now)
        else:
            lines = self._format_arp(now)

        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", "\n".join(lines))
        self._text.configure(state="disabled")

    def _format_arp(self, now):
        entries = self.arp_mgr.snapshot()
        stamp = time.strftime("%H:%M:%S", time.localtime(now))
        lines = [
            "ProtoRouter - Tabla ARP",
            f"dpid: {self.dpid}    entradas: {len(entries)}    hora: {stamp}",
            "",
            f"{'IP':<16} {'MAC':<18} {'PUERTO':<7} {'EDAD':>8}",
            "-" * 55,
        ]

        if not entries:
            lines.append("(sin entradas ARP)")
        else:
            for ip, mac, port, last_seen in sorted(entries, key=lambda item: str(item[0])):
                age = max(0.0, now - last_seen)
                lines.append(f"{str(ip):<16} {str(mac):<18} {str(port):<7} {age:>7.1f}s")

        return lines

    def _format_nat(self, now):
        entries = self.pat_mgr.snapshot()
        stamp = time.strftime("%H:%M:%S", time.localtime(now))
        lines = [
            "ProtoRouter - Tabla NAT/PAT",
            f"dpid: {self.dpid}    mapeos: {len(entries)}    puertos libres: {self.pat_mgr.free_count()}    hora: {stamp}",
            "",
            f"{'IP PRIVADA':<16} {'PUERTO':<8} {'PROTO':<6} {'IP DESTINO':<16} {'PUERTO DEST':>11} {'IP PUBLICA':<16} {'PUERTO PUB':>10}",
            "-" * 89,
        ]

        if not entries:
            lines.append("(sin mapeos NAT/PAT)")
        else:
            for src_ip, src_port, proto, nat_port, dst_ip, dst_port in sorted(
                    entries, key=lambda item: (str(item[0]), str(item[1]), str(item[2]))
            ):
                dst_ip_text = str(dst_ip) if dst_ip is not None else "-"
                dst_port_text = str(dst_port) if dst_port is not None else "-"
                src_port_text = str(src_port) if src_port is not None else "-"
                nat_port_text = str(nat_port) if nat_port is not None else "-"
                lines.append(
                    f"{str(src_ip):<16} {src_port_text:<8} {self._proto_name(proto):<6} "
                    f"{dst_ip_text:<16} {dst_port_text:>11} {str(PUBLIC_IP):<16} {nat_port_text:>10}"
                )

        return lines

    def _proto_name(self, proto):
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

    def _destroy(self):
        root = self._root
        self._root = None
        self._text = None

        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
            log_color(MAGENTA, f"[POPUP] Ventana cerrada (dpid={self.dpid})")

    def _on_close(self):
        self._closed = True
        self._destroy()

    def stop(self):
        self._closed = True


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.arp_mgr = ARPManager()
        self.pat_mgr = PATManager()
        self.arp_mgr.addListeners(self)
        # [MONITOR ARP/NAT] Abre la ventana del monitor; el router funciona igual si falla.
        self.tables_popup = TablesPopupMonitor(self.arp_mgr, self.pat_mgr, getattr(connection, "dpid", "?"))
        log_color(MAGENTA, f"[ROUTER] ProtoRouter inicializado (dpid={getattr(connection, 'dpid', '?')}, idle_timeout={FLOW_IDLE_TIMEOUT}s)")

    def _handle_ARPRemoved(self, event):
        log_color(YELLOW, f"[ARP EXPIRE] {event.ip} -> {event.mac} (Puerto {event.port})")

    def _handle_ConnectionDown(self, event):
        log_color(MAGENTA, "[ROUTER] Conexión OpenFlow cerrada; liberando recursos")
        # [MONITOR ARP/NAT] Detiene solo la ventana del monitor; no afecta la liberación del router.
        if getattr(self, "tables_popup", None) is not None:
            self.tables_popup.stop()
        self.arp_mgr.shutdown()
        log_color(MAGENTA, "[ROUTER] Recursos liberados")

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.debug(f"[PKT IN] Paquete no parseado en puerto {getattr(event, 'port', '?')}; ignorado")
            return

        packet = event.parsed
        log.debug(f"[PKT IN] dpid={getattr(self.connection, 'dpid', '?')} puerto={event.port} tipo=0x{packet.type:04x} src={packet.src} dst={packet.dst}")

        # 1. Tráfico ARP
        if packet.type == ethernet.ARP_TYPE:
            pending_events = self.arp_mgr.handle_arp(self.connection, event)
            if pending_events:
                log_color(CYAN, f"[ROUTER] Reprocesando {len(pending_events)} paquete(s) pendiente(s)")
                for pending_ev in pending_events:
                    self._handle_PacketIn(pending_ev)
            return

        # 2. Tráfico IP
        if packet.type == ethernet.IP_TYPE:
            self.process_ip(event)
            return

        log_color(YELLOW, f"[PKT IN] Ethertype no soportado 0x{packet.type:04x} desde {packet.src} hacia {packet.dst}; ignorado")

    def process_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.find('ipv4')
        in_port = event.port

        if not ip_pkt:
            log_color(RED, f"[IP] Paquete IP inválido o no parseable en puerto {in_port}; ignorado")
            return

        proto = ip_pkt.protocol
        src_ip = ip_pkt.srcip
        dst_ip = ip_pkt.dstip
        log.debug(f"[IP] {src_ip} -> {dst_ip} proto={proto} in_port={in_port}")

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
                log.debug(f"[ICMP Router] Reply enviado a {src_ip} por puerto {in_port}")
            elif icmp_pkt:
                log.debug(f"[ICMP Router] ICMP tipo {icmp_pkt.type} para {dst_ip}; no se responde")
            else:
                log.debug(f"[IP] Paquete no ICMP para IP del router {dst_ip} proto={proto}; no se procesa")
            return

        # 0.5. Tráfico LAN Local sin NAT (Privado -> Privado, ej: h3 -> h2)
        if src_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK) and dst_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            dst_entry = self.arp_mgr.arp_table.get(dst_ip)
            dst_port = dst_entry.port if dst_entry else None
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.in_port = in_port

            if dst_port:
                log_color(CYAN, f"[LAN] {src_ip} -> {dst_ip} por puerto {dst_port}")
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
                log_color(BLUE, f"[FLOW] LAN instalado: {src_ip} -> {dst_ip} (in={in_port}, out={dst_port}, idle={FLOW_IDLE_TIMEOUT}s)")
            else:
                log_color(YELLOW, f"[LAN] MAC desconocida para {dst_ip}; inundando la LAN")
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

            self.connection.send(msg)
            return

        # 1. Tráfico Saliente (Red Privada -> Red Pública con NAT/PAT)
        if src_ip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(CYAN, f"[NAT] Saliente {src_ip} -> {dst_ip} proto={proto} in_port={in_port}")
            # Obtener/Resolver MAC de Destino
            dst_entry = self.arp_mgr.arp_table.get(dst_ip)
            dst_mac = dst_entry.mac if dst_entry else None
            if not dst_mac:
                queued = len(self.arp_mgr.pending_packets[dst_ip]) + 1
                log_color(YELLOW, f"[NAT] MAC desconocida para {dst_ip}; encolando paquete ({queued} pendiente(s)) y solicitando ARP")
                self.arp_mgr.pending_packets[dst_ip].append(event)
                self.arp_mgr.request_mac(self.connection, PUBLIC_PORT, PUBLIC_MAC, PUBLIC_IP, dst_ip)
                return

            l4_pkt = packet.find('tcp') or packet.find('udp')

            # Caso TCP / UDP (Con PAT)
            if l4_pkt:
                src_port = l4_pkt.srcport
                dst_port = l4_pkt.dstport
                log_color(CYAN, f"[NAT] TCP/UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={proto}")

                # [MONITOR ARP/NAT] Envía IP/puerto destino solo para poder mostrarlos en la ventana.
                nat_port = self.pat_mgr.get_or_assign(src_ip, src_port, proto, dst_ip, dst_port)
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
                log_color(BLUE, f"[FLOW] NAT saliente instalado: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (out={PUBLIC_PORT}, idle={FLOW_IDLE_TIMEOUT}s)")

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
                log_color(BLUE, f"[FLOW] NAT entrante instalado: {dst_ip}:{dst_port} -> {PUBLIC_IP}:{nat_port} (out={in_port}, idle={FLOW_IDLE_TIMEOUT}s)")

                # Reenviar primer paquete (PacketOut)
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = fm_out.actions
                self.connection.send(msg)
                log_color(CYAN, f"[NAT] Primer paquete TCP/UDP reenviado a {dst_ip}")

            # Caso ICMP / Ping atravesando NAT
            elif packet.find('icmp'):
                log_color(CYAN, f"[NAT] ICMP {src_ip} -> {dst_ip} proto={proto}")
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
                log_color(BLUE, f"[FLOW] NAT ICMP saliente instalado: {src_ip} -> {dst_ip} (out={PUBLIC_PORT}, idle={FLOW_IDLE_TIMEOUT}s)")
                icmp_pkt = packet.find('icmp')
                echo_pkt = packet.find('echo')



                if icmp_pkt is None or icmp_pkt.type != 8 or echo_pkt is None:
                    log_color(YELLOW, "[NAT ICMP] Paquete no es un Echo Request válido")
                    return

                icmp_cookie = self.pat_mgr.register_icmp(
                    src_ip,
                    dst_ip,
                    echo_pkt.id,
                    packet.src,
                    in_port
                )

                if icmp_cookie is None:
                    return


                fm_in = of.ofp_flow_mod()
                fm_in.idle_timeout = FLOW_IDLE_TIMEOUT

                # asocia la regla openfow con la entrada ICMP del monitor
                fm_in.cookie = icmp_cookie
                fm_in.flags |= of.OFPFF_SEND_FLOW_REM

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
                log_color(BLUE, f"[FLOW] NAT ICMP entrante instalado: {dst_ip} -> {PUBLIC_IP} (out={in_port}, idle={FLOW_IDLE_TIMEOUT}s)")

                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.in_port = in_port
                msg.actions = fm_out.actions
                self.connection.send(msg)
                log_color(CYAN, f"[NAT] Primer paquete ICMP reenviado a {dst_ip}")

            else:
                log_color(YELLOW, f"[NAT] Protocolo {proto} no soportado para {src_ip} -> {dst_ip}; descartado")

        else:
            log_color(YELLOW, f"[IP] Tráfico no clasificado {src_ip} -> {dst_ip} proto={proto}; descartado")

    def _handle_FlowRemoved(self, event):
        """Libera los recursos NAT/PAT cuando expiran las reglas."""

        ofp = event.ofp
        match = getattr(ofp, 'match', None)

        log.debug(
            f"[FLOW REMOVED] reason={getattr(ofp, 'reason', '?')} "
            f"idle_timeout={getattr(ofp, 'idle_timeout', '?')} "
            f"hard_timeout={getattr(ofp, 'hard_timeout', '?')}"
        )

        if match and match.dl_type == 0x0800 and match.nw_dst == PUBLIC_IP:

            proto = match.nw_proto

            # Caso ICMP
            if proto == ipv4.ICMP_PROTOCOL:
                cookie = ofp.cookie
                removed = self.pat_mgr.release_icmp(cookie)

                if removed:
                    src_ip = removed["src_ip"]
                    dst_ip = removed["dst_ip"]

                    log_color(
                        YELLOW,
                        f"[NAT ICMP EXPIRE] {src_ip} -> {dst_ip} (cookie={cookie})"
                    )

            # Caso TCP / UDP
            else:
                nat_port = match.tp_dst

                log.debug(
                    f"[FLOW REMOVED] NAT: {match.nw_src}:"
                    f"{getattr(match, 'tp_src', '?')} -> "
                    f"{match.nw_dst}:{getattr(match, 'tp_dst', '?')} "
                    f"proto={proto}"
                )

                if nat_port and proto:
                    self.pat_mgr.release_port(nat_port, proto)

        else:
            log.debug("[FLOW REMOVED] Flujo sin traducción NAT asociada")


def launch():
    def start_switch(event):
        log_color(MAGENTA, f"Iniciando ProtoRouter NAT/PAT en Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    log_color(MAGENTA, "[ROUTER] Esperando conexiones OpenFlow...")
    core.openflow.addListenerByName("ConnectionUp", start_switch)