# redes-tp2 — SDN: NAT con POX y Mininet

El controlador y la topología base vienen del repo de la cátedra: https://github.com/TA048/tp_sdn_nat

## Estructura

| Ruta | Contenido |
|------|-----------|
| `pox/` | Controlador POX (repo oficial) |
| `pox/ext/protorouter_template.py` | Nuestro controlador (parte del de la cátedra) |
| `topology/topo.py` | Topología de Mininet: h1 (pública) — s1 (NAT) — h2 (privada) |

## Topología

| Equipo | IP | MAC | Gateway |
|--------|----|-----|---------|
| h1 (red pública, servidor) | 200.0.0.1/24 | 00:00:00:00:00:01 | 200.0.0.254 |
| h2 (red privada, cliente) | 192.168.1.2/24 | 00:00:00:00:00:02 | 192.168.1.254 |
| s1, interfaz pública (puerto 1) | 200.0.0.254 | 00:00:00:aa:aa:aa | — |
| s1, interfaz privada (puerto 2) | 192.168.1.254 | 00:00:00:bb:bb:bb | — |

## Instalación

### 1. Python 3.9

```bash
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt update
sudo apt install python3.9 python3.9-venv -y
```

Crear el entorno virtual en la raíz del repo:

```bash
python3.9 -m venv venv
```

### 2. Mininet y Open vSwitch

```bash
sudo apt install mininet openvswitch-switch -y
sudo systemctl enable --now openvswitch-switch
```

## Ejecución

Hacen falta dos terminales. Primero se levanta el controlador y después la topología.

### Terminal 1: controlador POX

```bash
cd redes-tp2
source venv/bin/activate
cd pox
python pox.py log.level --DEBUG openflow.of_01 --port=6653 protorouter
```

> **Importante:** `openflow.of_01 --port=6653` es necesario. POX escucha por defecto en el puerto 6633, pero Mininet 2.3 busca al controlador en el 6653. Si los puertos no coinciden, el switch nunca se conecta y se descartan todos los paquetes.

Tiene que quedar en `Listening on 0.0.0.0:6653`.

### Terminal 2: topología de Mininet

```bash
cd redes-tp2
sudo python3 topology/topo.py
```

Cuando el switch se conecta, en la terminal de POX aparece:

```
Iniciando ProtoRouter para Switch 1
```

## Pruebas

Desde la CLI de Mininet (`mininet>`):

```
mininet> h2 ping -c 3 h1
```

Con el controlador base:

| Prueba | Resultado esperado |
|--------|--------------------|
| `h2 ping h1` (privada → pública) | Funciona. En POX se ven `RECIBIDO`, `MATCH` y `ENVIANDO` solo para el primer paquete; el resto lo resuelve el switch con los flujos instalados. |
| `h1 ping h2` (pública → privada) | Falla a propósito: el NAT es solo saliente. En POX aparece `NO MATCH`. |

Para ver qué IP le llega al host público:

```
mininet> h1 tcpdump -n -i h1-eth0 &
mininet> h2 ping -c 3 h1
```

Con el controlador base llega la IP privada (`192.168.1.2`), porque todavía no se traduce. Con el PAT implementado debería llegar `200.0.0.254`.

Para ver los flujos instalados en el switch (en otra terminal):

```bash
sudo ovs-ofctl dump-flows s1
```

Para cerrar y quitar todo lo del mininet

```bash
sudo mn -c
```