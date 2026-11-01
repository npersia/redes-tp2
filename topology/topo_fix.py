from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def create_net():
    # Inicializamos Mininet indicando que usaremos un controlador remoto (POX)
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, autoSetMacs=False)

    info('*** Agregando controlador POX\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info('*** Agregando switch\n')
    s1 = net.addSwitch('s1',protocols='OpenFlow10')

    info('*** Agregando hosts (Servidor y Cliente)\n')
    # h1: Red pública (Servidor)
    h1 = net.addHost('h1', ip='200.0.0.1/24', mac='00:00:00:00:00:01', defaultRoute='via 200.0.0.254')
    
    # h2: Red privada (Cliente)
    h2 = net.addHost('h2', ip='192.168.1.2/24', mac='00:00:00:00:00:02', defaultRoute='via 192.168.1.254')

    info('*** Conectando hosts al switch\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info('*** Iniciando la red\n')
    net.start()

    info('*** Abriendo la consola de Mininet (CLI)\n')
    CLI(net)

    info('*** Deteniendo la red\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_net()

