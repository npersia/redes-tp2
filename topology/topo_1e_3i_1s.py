#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel


class NATTopo(Topo):
    def build(self):
        # Switch principal
        s1 = self.addSwitch('s1', protocols='OpenFlow10', failMode='secure')

        # Host público (Servidor)
        h1 = self.addHost('h1', ip='200.0.0.1/24',
                          mac='00:00:00:00:00:01', defaultRoute='via 200.0.0.254')

        # Hosts privados (Clientes)
        h2 = self.addHost('h2', ip='192.168.1.2/24', mac='00:00:00:00:00:02',
                          defaultRoute='via 192.168.1.254')
        h3 = self.addHost('h3', ip='192.168.1.3/24', mac='00:00:00:00:00:03',
                          defaultRoute='via 192.168.1.254')
        h4 = self.addHost('h4', ip='192.168.1.4/24', mac='00:00:00:00:00:04',
                          defaultRoute='via 192.168.1.254')

        # Conexiones: h1 conectará en puerto 1, h2 en puerto 2, h3 en puerto 3, h4 en puerto 4
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


def run():
    topo = NATTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        link=TCLink
    )
    net.start()

    # Deshabilitar IPv6 para evitar ruido de paquetes ND
    for node in net.hosts + [net.get('s1')]:
        node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    # NOTA: Se eliminaron los setARP(...) para exigir resolución ARP dinámica.

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
