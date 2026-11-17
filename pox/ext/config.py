from pox.lib.addresses import EthAddr, IPAddr


FLOW_IDLE_TIMEOUT = 20  # Timeout de inactividad para liberar flujos en segundos
ARP_TIMEOUT = 5  # Tiempo de vida de una entrada ARP sin actualizarse
ARP_CLEAN_INTERVAL = 3  # Intervalo de limpieza de la tabla ARP en segundos


# Configuración de Red Base
PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK = 24
PRIVATE = "192.168.1.250" #IP privada del router
PRIVATE_IP_ROUTER = IPAddr(PRIVATE)

PUBLIC_IP = "200.0.0.250" #IP publica del rourter
PUBLIC_IP_ROUTER = IPAddr(PUBLIC_IP)

PUBLIC_MAC_ROUTER = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC_ROUTER = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT = 1
