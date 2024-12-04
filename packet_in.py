import json
import time
import threading
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3
import logging
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from ryu.lib.packet import in_proto, ether_types
from collections import deque

# Data structure with limited size to store packet data
MAX_PACKET_HISTORY = 50
packet_in_data = deque(maxlen=MAX_PACKET_HISTORY)

# Function to periodically save packet_in data to a JSON file
def save_packet_in_data():
    while True:
        try:
            json_ready_data = list(packet_in_data)  # Convert deque to list for JSON serialization
            with open('packet_in_data.json', 'w') as outfile:
                json.dump(json_ready_data, outfile, indent=2)
        except Exception as e:
            print(f"packet_in error: {str(e)}")
        
        time.sleep(3)  # Save every 3 seconds

# Ryu App definition
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}  # MAC address to port mapping table
        # Initialize logger
        logging.basicConfig(level=logging.CRITICAL)

        # Start a thread to save packet_in data periodically
        self.save_thread = threading.Thread(target=save_packet_in_data)
        self.save_thread.daemon = True
        self.save_thread.start()

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.send_flow_miss_to_controller(datapath)
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                self.datapaths.pop(datapath.id)

    # Install a flow rule to send all unmatched packets to the controller
    def send_flow_miss_to_controller(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    # Helper function to add a flow rule
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
    
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
    
        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Ignore IPv6 packets
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
    
        src_mac = eth.src
        dst_mac = eth.dst
        eth_type = eth.ethertype
    
        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port  # Learn or update MAC address for current datapath

        # Determine out_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Initialize match parameters
        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]

        src_ip = 'N/A'
        dst_ip = 'N/A'
        src_port = 'N/A'
        dst_port = 'N/A'
        protocol = 'N/A'
        icmp_type = 'N/A'
        tcp_flags = []

        # Handle IPv4 packets
        if eth_type == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            protocol = ipv4_pkt.proto

            # Handle ICMP packets
            if protocol == in_proto.IPPROTO_ICMP:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt:
                    icmp_type = icmp_pkt.type

            # Handle UDP packets
            elif protocol == in_proto.IPPROTO_UDP:
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    src_port = udp_pkt.src_port
                    dst_port = udp_pkt.dst_port
                    match = parser.OFPMatch(eth_type=eth_type, ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            eth_src=src_mac, eth_dst=dst_mac, in_port=in_port,
                                            ip_proto=protocol, udp_src=src_port, udp_dst=dst_port)

            # Handle TCP packets
            elif protocol == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    src_port = tcp_pkt.src_port
                    dst_port = tcp_pkt.dst_port
                    flags = tcp_pkt.bits
                    if flags & 0x20:
                        tcp_flags.append('URG')
                    if flags & 0x10:
                        tcp_flags.append('ACK')
                    if flags & 0x08:
                        tcp_flags.append('PSH')
                    if flags & 0x04:
                        tcp_flags.append('RST')
                    if flags & 0x02:
                        tcp_flags.append('SYN')
                    if flags & 0x01:
                        tcp_flags.append('FIN')
                    match = parser.OFPMatch(eth_type=eth_type, ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            eth_src=src_mac, eth_dst=dst_mac, in_port=in_port,
                                            ip_proto=protocol, tcp_src=src_port, tcp_dst=dst_port)

        # Install a flow rule if necessary
        if out_port != ofproto.OFPP_FLOOD:
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id, idle_timeout=30, hard_timeout=180)
            else:
                self.add_flow(datapath, 10, match, actions, idle_timeout=30, hard_timeout=180)

        packet_info = {
            'dpid': dpid,
            'in_port': in_port,
            'src_mac': src_mac,
            'dst_mac': dst_mac,
            'eth_type': eth_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'icmp_type': icmp_type,
            'tcp_flags': tcp_flags
        }

        # Append the packet information to the global packet_in_data deque
        packet_in_data.append(packet_info)

        # Send packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

if __name__ == '__main__':
    app_manager.AppManager.run_apps(['ryu.app.ofctl_rest', '__main__'])

