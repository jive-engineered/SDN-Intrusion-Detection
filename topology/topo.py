#!/usr/bin/env python3
"""
topo.py  -  Mininet topology for the SDN IDS project (runs on the SWITCH laptop).

  MODE "distributed"  (3 laptops - the real demo)
  ---------------------------------------------------------------------------
     Laptop A  (controller)        Laptop B  (this script)               Laptop C (attacker)
     Ryu IDS controller  <--OF1.3--  s1 (Open vSwitch)  <==VXLAN tunnel==>  attacker namespace
                                      |            |                         10.0.0.1
                                     h2 (server) h3 (legit client)
                                     10.0.0.2    10.0.0.3

  MODE "single"  (1 laptop - backup plan, everything virtual)
  ---------------------------------------------------------------------------
     s1 with h1 (attacker 10.0.0.1), h2 (server 10.0.0.2), h3 (legit 10.0.0.3)

Usage (always with sudo):
   sudo python3 topology/topo.py --mode distributed --controller-ip <A_IP> --attacker-ip <C_IP>
   sudo python3 topology/topo.py --mode single      --controller-ip <A_IP>
"""
import argparse
import os
import subprocess
import sys
import time

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.log import setLogLevel, info, error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PORTS = "22 80 443 5000"      # services running on h2 (the scan will discover these)


def parse():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["single", "distributed"], default="distributed")
    p.add_argument("--controller-ip", default="127.0.0.1", help="IP address of Laptop A (Ryu)")
    p.add_argument("--controller-port", type=int, default=6653)
    p.add_argument("--attacker-ip", help="IP address of Laptop C (needed in distributed mode)")
    p.add_argument("--vxlan-key", type=int, default=100)
    p.add_argument("--datapath", choices=["kernel", "user"], default="kernel", help=argparse.SUPPRESS)
    p.add_argument("--no-cli", action="store_true", help=argparse.SUPPRESS)
    return p.parse_args()


def main():
    args = parse()
    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo python3 topology/topo.py ...")
    if args.mode == "distributed" and not args.attacker_ip:
        sys.exit("--attacker-ip <Laptop C IP> is required in distributed mode")

    setLogLevel("info")
    cleanup()
    os.chdir(ROOT)
    os.makedirs("logs", exist_ok=True)

    net = Mininet(controller=None, switch=OVSSwitch, build=False, autoSetMacs=False)
    net.addController("c0", controller=RemoteController, ip=args.controller_ip, port=args.controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13", failMode="secure", datapath=args.datapath)

    hosts = {}
    if args.mode == "single":
        hosts["h1"] = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    hosts["h2"] = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    hosts["h3"] = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    for h in hosts.values():
        net.addLink(h, s1)

    net.build()
    net.start()

    if args.mode == "distributed":
        # VXLAN tunnel port: everything the attacker laptop sends enters this switch on port 10
        subprocess.check_call(
            ["ovs-vsctl", "--may-exist", "add-port", "s1", "vxlan0", "--", "set", "interface", "vxlan0",
             "type=vxlan", "options:remote_ip=%s" % args.attacker_ip, "options:key=%d" % args.vxlan_key,
             "ofport_request=10"])
        info("*** VXLAN tunnel  s1 <-> %s  (key %d) created\n" % (args.attacker_ip, args.vxlan_key))

    info("*** Waiting for the switch to connect to the Ryu controller at %s:%d ...\n"
         % (args.controller_ip, args.controller_port))
    try:
        net.waitConnected(timeout=20)
        info("*** Switch connected to controller\n")
    except Exception:
        pass
    if not s1.connected():
        error("!!! Switch NOT connected to the controller. Is ryu-manager running on %s and port 6653 open?\n"
              % args.controller_ip)

    h2 = hosts["h2"]
    h2.cmd("python3 apps/tcp_server.py --ports %s > logs/server.log 2>&1 &" % SERVER_PORTS)
    time.sleep(1)
    hosts["h3"].cmd("ping -c 2 -W 1 10.0.0.2 > /dev/null 2>&1")      # let the controller learn the MACs

    info("\n*** Servers started on h2 (ports %s)\n" % SERVER_PORTS)
    info("*** Handy commands inside the Mininet CLI:\n")
    info("      h3 python3 apps/tcp_client.py --server 10.0.0.2 --port 5000 --duration 60\n")
    if args.mode == "single":
        info("      h1 python3 apps/attack_port_scan.py --target 10.0.0.2\n")
        info("      h1 python3 apps/attack_conn_flood.py --target 10.0.0.2 --rate 60\n")
    else:
        info("      (attacks are started on Laptop C - see README)\n")
    info("      sh ovs-ofctl -O OpenFlow13 dump-flows s1     # show the DROP rule\n\n")

    if not args.no_cli:
        CLI(net)
        net.stop()
        cleanup()
    return net


if __name__ == "__main__":
    main()
