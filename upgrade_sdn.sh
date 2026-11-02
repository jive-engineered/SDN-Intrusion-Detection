#!/usr/bin/env bash
set -e

PROJECT_DIR="sdn-ids"

if [ ! -d "$PROJECT_DIR" ]; then
    echo "[ERROR] '$PROJECT_DIR' directory not found! Please unzip your existing sdn-ids.zip here first."
    exit 1
fi

echo ">>> [1/4] Updating controller/ids_rules.json with Tri-Factor & Sybil thresholds..."
cat << 'RULES_EOF' > "$PROJECT_DIR/controller/ids_rules.json"
{
  "window_seconds": 4,
  "max_packets_per_port": 30,
  "max_ips_per_mac": 2,
  "max_syn_per_port": 15,
  "hardware_meter_pktps": 50,
  "hardware_meter_burst": 10,
  "static_bindings": {
    "10.0.0.1": {"mac": "00:00:00:00:00:01", "port": 1},
    "10.0.0.2": {"mac": "00:00:00:00:00:02", "port": 2},
    "10.0.0.3": {"mac": "00:00:00:00:00:03", "port": 3}
  }
}
RULES_EOF

echo ">>> [2/4] Updating controller/ids_engine.py with Multi-Layer Inspection..."
cat << 'ENGINE_EOF' > "$PROJECT_DIR/controller/ids_engine.py"
import json
import os
import time

class IDSEngine:
    """
    Multi-Layer SDN Intrusion Detection Engine:
    1. Static IP-MAC-Port Anti-Spoofing Binding
    2. MAC-to-Multiple-IP (Sybil) Detection
    3. Physical Ingress Port Volumetric Thresholding
    4. L4 TCP Half-Open SYN Tracking
    """
    def __init__(self, rules_path=None):
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), "ids_rules.json")
        with open(rules_path, "r") as f:
            self.rules = json.load(f)

        self.window_seconds = self.rules.get("window_seconds", 4)
        self.max_packets_per_port = self.rules.get("max_packets_per_port", 30)
        self.max_ips_per_mac = self.rules.get("max_ips_per_mac", 2)
        self.max_syn_per_port = self.rules.get("max_syn_per_port", 15)
        self.static_bindings = self.rules.get("static_bindings", {})

        self.reset_window()

    def reset_window(self):
        self.window_start = time.time()
        self.port_packet_counts = {}
        self.mac_to_ips = {}
        self.port_syn_counts = {}

    def _check_window_expiry(self):
        if time.time() - self.window_start >= self.window_seconds:
            self.reset_window()

    def inspect_packet(self, in_port, src_mac, src_ip=None, tcp_bits=None):
        """
        Returns a tuple: (is_malicious: bool, action_type: str, reason: str)
        action_type can be 'ISOLATE_PORT' or 'BLOCK_MAC' or 'ALLOW'
        """
        self._check_window_expiry()

        if src_ip:
            # 1. Anti-Spoofing Tri-Factor Binding Check (IP <-> MAC <-> Port)
            binding = self.static_bindings.get(src_ip)
            if binding:
                expected_mac = binding["mac"].lower()
                expected_port = binding["port"]
                if src_mac.lower() != expected_mac or in_port != expected_port:
                    return (
                        True,
                        "ISOLATE_PORT",
                        f"Anti-Spoofing Violation: IP {src_ip} seen on Port {in_port} (MAC {src_mac}), expected Port {expected_port} ({expected_mac})"
                    )

            # 2. MAC-to-Multiple-IP (Sybil / Randomized IP Spoofing) Check
            self.mac_to_ips.setdefault(src_mac, set()).add(src_ip)
            if len(self.mac_to_ips[src_mac]) > self.max_ips_per_mac:
                ips_list = ", ".join(sorted(self.mac_to_ips[src_mac]))
                return (
                    True,
                    "ISOLATE_PORT",
                    f"Sybil Multi-IP Spoofing: MAC {src_mac} on Port {in_port} claimed {len(self.mac_to_ips[src_mac])} IPs ({ips_list})"
                )

        # 3. Physical Ingress Port Volumetric Rate Check
        self.port_packet_counts[in_port] = self.port_packet_counts.get(in_port, 0) + 1
        if self.port_packet_counts[in_port] > self.max_packets_per_port:
            return (
                True,
                "ISOLATE_PORT",
                f"Ingress Port Flood: Switch Port {in_port} exceeded {self.max_packets_per_port} packets/{self.window_seconds}s window"
            )

        # 4. L4 TCP SYN-without-ACK Exhaustion Check
        if tcp_bits is not None:
            is_syn = bool(tcp_bits & 0x02)
            is_ack = bool(tcp_bits & 0x10)
            if is_syn and not is_ack:
                self.port_syn_counts[in_port] = self.port_syn_counts.get(in_port, 0) + 1
                if self.port_syn_counts[in_port] > self.max_syn_per_port:
                    return (
                        True,
                        "ISOLATE_PORT",
                        f"TCP SYN Exhaustion: Switch Port {in_port} sent >{self.max_syn_per_port} half-open SYNs"
                    )

        return (False, "ALLOW", "Normal traffic")
ENGINE_EOF

echo ">>> [3/4] Updating controller/ids_controller.py with OpenFlow 1.3 Port Quarantine & Metering..."
cat << 'CONTROLLER_EOF' > "$PROJECT_DIR/controller/ids_controller.py"
import os
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
from ryu.lib import hub

from ids_engine import IDSEngine

class SDNIDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNIDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.quarantined_ports = set()
        self.engine = IDSEngine()
        self.monitor_thread = hub.spawn(self._telemetry_loop)
        self.logger.info(">>> [SDN-IDS] Controller Active on OpenFlow 1.3 (Port 6653) <<<")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # Configure OpenFlow 1.3 Hardware Meter Band (ID 1) for Control-Plane Protection
        rate = self.engine.rules.get("hardware_meter_pktps", 50)
        burst = self.engine.rules.get("hardware_meter_burst", 10)
        bands = [parser.OFPMeterBandDrop(rate=rate, burst_size=burst)]
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS,
            meter_id=1,
            bands=bands
        )
        datapath.send_msg(meter_mod)

        # Priority 0: Table-Miss Flow Entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info(f"[SWITCH CONNECTED] DPID {datapath.id} registered with Hardware Meter Band 1.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority,
                match=match, instructions=inst,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout
            )
        datapath.send_msg(mod)

    def quarantine_ingress_port(self, datapath, in_port, src_mac, reason):
        if (datapath.id, in_port) in self.quarantined_ports:
            return
        self.quarantined_ports.add((datapath.id, in_port))
        parser = datapath.ofproto_parser

        # Priority 200: Hardware Ingress Port Drop (Blocks all spoofed IPs on that port)
        port_match = parser.OFPMatch(in_port=in_port)
        self.add_flow(datapath, priority=200, match=port_match, actions=[])

        # Priority 150: Source MAC Drop backup rule
        mac_match = parser.OFPMatch(eth_src=src_mac)
        self.add_flow(datapath, priority=150, match=mac_match, actions=[])

        self.logger.warning("\n=======================================================")
        self.logger.warning("[!!! DYNAMIC SDN MITIGATION TRIGGERED !!!]")
        self.logger.warning(f"  Reason : {reason}")
        self.logger.warning(f"  Action : Quarantined Switch Port {in_port} (Priority 200 DROP) & MAC {src_mac} (Priority 150 DROP)")
        self.logger.warning("=======================================================\n")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src_mac = eth.src
        dst_mac = eth.dst
        dpid = datapath.id

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        src_ip = ip_pkt.src if ip_pkt else None
        tcp_bits = tcp_pkt.bits if tcp_pkt else None

        # Evaluate packet against multi-layer IDS Engine
        is_malicious, action, reason = self.engine.inspect_packet(
            in_port=in_port,
            src_mac=src_mac,
            src_ip=src_ip,
            tcp_bits=tcp_bits
        )

        if is_malicious:
            self.quarantine_ingress_port(datapath, in_port, src_mac, reason)
            return

        # Standard L2 Learning Switch Forwarding
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=30)

        data = None if msg.buffer_id == ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _telemetry_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        flows = [f for f in ev.msg.body if f.priority > 0]
        if not flows:
            return
        self.logger.info("--- [LIVE SWITCH FLOW TABLE] ---")
        for stat in sorted(flows, key=lambda x: x.priority, reverse=True):
            self.logger.info(
                f"Priority: {stat.priority:3d} | Pkts: {stat.packet_count:5d} | Bytes: {stat.byte_count:7d} | Match: {stat.match}"
            )
CONTROLLER_EOF

chmod +x "$PROJECT_DIR"/*.sh "$PROJECT_DIR"/tools/*.sh "$PROJECT_DIR"/topology/*.sh 2>/dev/null || true

echo ">>> [4/4] Packaging everything into sdn-ids-upgraded.zip..."
zip -r sdn-ids-upgraded.zip "$PROJECT_DIR"

echo ""
echo "✅ Done! Your updated archive is ready at: $(pwd)/sdn-ids-upgraded.zip"
