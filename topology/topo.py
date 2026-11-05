#!/usr/bin/env python3
"""
topo.py - Mininet topology for the SDN IDS + IPS project.

  MODE "single"  (1 laptop, recommended for the single-laptop demo)
  ---------------------------------------------------------------------------
                            s1 (Open vSwitch, OpenFlow 1.3)
                           /     |          \\
    h1 10.0.0.1 (attacker)       |           h2  10.0.0.2  (primary app server)
    h3  10.0.0.3  heartbeat      |           srv2 10.0.0.10 (file server)
    h4-h9 10.0.0.4-9 workstations             srv3 10.0.0.11 (database)
                                              srv4 10.0.0.12 (dns/mail)

  Twelve hosts in total: 1 attacker, 7 legit clients, 4 protected servers.
  The seven clients continuously chatter at every server (apps/background_traffic.py),
  so attacks happen inside a busy office LAN, not a quiet lab.

  MODE "distributed" (3 laptops - the original VXLAN deployment)
  ---------------------------------------------------------------------------
     Laptop A (controller) <-OF1.3-> Laptop B (s1 + h2/h3/...) <=VXLAN=> Laptop C (attacker)

Usage (always with sudo):
   sudo python3 topology/topo.py --mode single      --controller-ip <A_IP>
   sudo python3 topology/topo.py --mode distributed --controller-ip <A_IP> --attacker-ip <C_IP>
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

# ---------------------------------------------------------------------------
# "Realistic office LAN" host roster. Keep h1/h2/h3 identical to the original
# so all existing automation (run_attacker.sh, auto_demo.sh, telemetry panel,
# tests) continues to work without edits.
# ---------------------------------------------------------------------------
SERVERS = [
    # (name, ip, mac, ports)                                                        # role
    ("h2",   "10.0.0.2",  "00:00:00:00:00:02", "22 80 443 5000"),                   # primary web/app
    ("srv2", "10.0.0.10", "00:00:00:00:00:0A", "21 445 8080"),                      # file server
    ("srv3", "10.0.0.11", "00:00:00:00:00:0B", "3306 5432"),                        # database
    ("srv4", "10.0.0.12", "00:00:00:00:00:0C", "25 53 143"),                        # mail/dns
]
LEGIT_CLIENTS = [
    # (name, ip, mac)
    ("h3", "10.0.0.3", "00:00:00:00:00:03"),  # original heartbeat client
    ("h4", "10.0.0.4", "00:00:00:00:00:04"),
    ("h5", "10.0.0.5", "00:00:00:00:00:05"),
    ("h6", "10.0.0.6", "00:00:00:00:00:06"),
    ("h7", "10.0.0.7", "00:00:00:00:00:07"),
    ("h8", "10.0.0.8", "00:00:00:00:00:08"),
    ("h9", "10.0.0.9", "00:00:00:00:00:09"),
]
# Two attackers for the coordinated / distributed-attack demo. Neither is in
# protected_hosts, so both stay subject to IDS detection. h1 is created first
# (OpenFlow port eth1); h10 is created LAST (eth13) so every other host keeps
# its original port number.
ATTACKERS = [
    ("h1",  "10.0.0.1",  "00:00:00:00:00:01"),  # primary attacker
    ("h10", "10.0.0.13", "00:00:00:00:00:0D"),  # second attacker
]
ALL_SERVER_IPS = ",".join(s[1] for s in SERVERS)


def parse():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["single", "distributed"], default="single")
    p.add_argument("--controller-ip", default="127.0.0.1", help="IP address of the Ryu controller")
    p.add_argument("--controller-port", type=int, default=6653)
    p.add_argument("--attacker-ip", help="IP address of Laptop C (needed in distributed mode)")
    p.add_argument("--vxlan-key", type=int, default=100)
    p.add_argument("--datapath", choices=["kernel", "user"], default="kernel", help=argparse.SUPPRESS)
    p.add_argument("--no-cli", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--no-background", action="store_true", help="skip auto-start of background chatter traffic")
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
    # Primary attacker h1 first (OpenFlow port eth1), single-laptop mode only.
    if args.mode == "single":
        name, ip, mac = ATTACKERS[0]
        hosts[name] = net.addHost(name, ip="%s/24" % ip, mac=mac)

    # Servers
    for name, ip, mac, _ports in SERVERS:
        hosts[name] = net.addHost(name, ip="%s/24" % ip, mac=mac)

    # Legit clients
    for name, ip, mac in LEGIT_CLIENTS:
        hosts[name] = net.addHost(name, ip="%s/24" % ip, mac=mac)

    # Second attacker h10 LAST (eth13), so all other host ports are unchanged.
    if args.mode == "single":
        for name, ip, mac in ATTACKERS[1:]:
            hosts[name] = net.addHost(name, ip="%s/24" % ip, mac=mac)

    for h in hosts.values():
        net.addLink(h, s1)

    net.build()
    net.start()

    if args.mode == "distributed":
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

    # Start every server with its own service ports.
    for name, _ip, _mac, ports in SERVERS:
        log = "logs/server_%s.log" % name
        hosts[name].cmd("python3 apps/tcp_server.py --ports %s > %s 2>&1 &" % (ports, log))
    time.sleep(1)

    # Prime the L2 MAC learning table from every legit client to every server.
    for cname, _cip, _cmac in LEGIT_CLIENTS:
        for _sname, sip, _smac, _ports in SERVERS:
            hosts[cname].cmd("ping -c 1 -W 1 %s > /dev/null 2>&1 &" % sip)
    time.sleep(1.5)

    # Fan out the background chatter daemon across every legit client.
    if not args.no_background:
        for cname, _cip, _cmac in LEGIT_CLIENTS:
            cmd = (
                "nohup python3 apps/background_traffic.py "
                "--servers %s --client-tag %s --min-interval 0.3 --max-interval 2.5 "
                "> logs/bg_%s.log 2>&1 &"
            ) % (ALL_SERVER_IPS, cname, cname)
            hosts[cname].cmd(cmd)
        info("*** Background chatter daemons started on %d legit clients\n" % len(LEGIT_CLIENTS))

    n_hosts = len(SERVERS) + len(LEGIT_CLIENTS) + (len(ATTACKERS) if args.mode == "single" else 0)
    info("\n*** %d-host office LAN is live.\n" % n_hosts)
    if args.mode == "single":
        info("    Attackers : %s\n" % ", ".join("%s(%s)" % (n, ip) for n, ip, _ in ATTACKERS))
    info("    Servers   : %s\n" % ", ".join("%s(%s)" % (n, ip) for n, ip, _, _ in SERVERS))
    info("    Clients   : %s\n" % ", ".join("%s(%s)" % (n, ip) for n, ip, _ in LEGIT_CLIENTS))
    info("*** Handy commands at the mininet> prompt:\n")
    info("      h1 python3 apps/attack_conn_flood.py --target 10.0.0.2 --rate 80\n")
    info("      sh ovs-ofctl -O OpenFlow13 dump-flows s1     # show the DROP rules\n")
    info("    Dashboard: in another terminal run  sudo python3 tools/sdn_cli.py sdn-ui\n")
    info("              then open http://127.0.0.1:8080 in a browser.\n\n")

    if not args.no_cli:
        CLI(net)
        net.stop()
        cleanup()
    return net


if __name__ == "__main__":
    main()
