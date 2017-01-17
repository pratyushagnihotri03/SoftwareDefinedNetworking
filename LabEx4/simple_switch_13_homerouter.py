# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import ipaddress
import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto.ofproto_v1_3_parser import OFPPort
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import dhcp
from ryu.controller.controller import Datapath
from ryu.lib import hub
import ryu.app.ofctl.api as api

### Group work of:
# Patrick Welzel (1478819)
# Manisha Luthra (2687667)
# Pratyush Agnihotri (2387187)


IDLE_TIMEOUT = 30
IDLE_TIMEOUT_NAT = 60 * 5
DHCP_PORT = 68
TABLEID_FILTER = 0
TABLEID_FORWARD = 1


class Switch(object):

    def __init__(self, name, main):
        #super(object, self).__init__()
        self.name = name
        self.mac_to_port = {}
        self.port_to_name = {}
        self.ports = []
        self.main = main

    def _flood_output_actions(self, parser, in_port):
        actions = []

        for port in self.ports:
            if port != in_port:
                if self.port_to_name[port] == 'wlan' and self.port_to_name[in_port] not in ('wlan', 'local_int'):
                    # allow flooding to wlan only from wlan and local_int
                    continue
                actions.append(parser.OFPActionOutput(port))

        return actions

    def init_ports(self, port_info, portlist):
        self.ports = portlist
        for port in portlist:
            for portinfo in port_info.itervalues():
                if portinfo["port_no"] == port:
                    self.port_to_name[port] = portinfo["semantic"]
        pass

    def packet_in(self, datapath, msg, in_port):
        # Type hint for PyCharm <3
        assert isinstance(datapath, Datapath)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        port_semantic = "unknown"
        if in_port in self.port_to_name.keys():
            port_semantic = self.port_to_name[in_port]

        self.main.logger.debug("%s packet in %s %s %s %s (%s)", self.name,
                               dpid, src, dst, in_port, port_semantic)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if port_semantic == 'wlan':
            out_port = self.main.port_info['local_int']['port_no']
            actions = [parser.OFPActionOutput(out_port)]
            flood = False

        elif dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            flood = False

        else:
            actions = self._flood_output_actions(parser, in_port)
            flood = True

        # install a flow to avoid packet_in next time
        if not flood:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.main.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id, idle_timeout=IDLE_TIMEOUT)
                return
            else:
                self.main.add_flow(datapath, 1, match, actions, idle_timeout=IDLE_TIMEOUT)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    NAT_SPORT_TCP_RANGE = (23000, 42000)
    NAT_SPORT_UDP_RANGE = NAT_SPORT_TCP_RANGE
    NAT_GUEST_ALLOWED = {'tcp': (80, 443)}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.int_swc = Switch("int_swc", self)
        self.ext_swc = Switch("ext_swc", self)

        self.knowledge = {'int': {'clients': {},
                                  'ip': '10.1.0.1'},
                          'ext': {}}
        self.nat_map = {'tcp': set(), 'udp': set()}

        # Port name to OpenFlow port number mappings
        self.port_info = {
            'external':  {'name': 'eth0.10',
                          'port_no': None,
                          'semantic': 'external',
                          'location': 'ext',
                          'description': 'Port to connect to the Internet access'},
            'local_ext': {'name': 'external',
                          'port_no': None,
                          'semantic': 'local_ext',
                          'location': 'ext',
                          'description': 'Local network port of router to connect to the Internet access network,'
                                         ' provides DHCP functionality and other services'},
            'local_int': {'name': 'internal',
                          'port_no': None,
                          'semantic': 'local_int',
                          'location': 'int',
                          'description': 'Local network port of router to connect to the local network,'
                                         ' provides DHCP functionality and other services'},
            'local_2':   {'name': 'eth0.33',
                          'port_no': None,
                          'semantic': 'local_2',
                          'location': 'int',
                          'description': 'Local network port 2 that provides connectivity for the local network,'
                                         ' connect your devices here.'},
            'local_3':   {'name': 'eth0.34',
                          'port_no': None,
                          'semantic': 'local_3',
                          'location': 'int',
                          'description': 'Local network port 3 that provides connectivity for the local network,'
                                         ' connect your devices here.'},
            'local_4':   {'name': 'eth0.35',
                          'port_no': None,
                          'semantic': 'local_4',
                          'location': 'int',
                          'description': 'Local network port 4 that provides connectivity for the local network,'
                                         ' connect your devices here.'},
            'wlan':       {'name': 'veth0',
                           'port_no': None,
                           'semantic': 'wlan',
                           'location': 'int',
                           'description': 'Local network port 4 that provides connectivity for the local network,'
                                          ' connect your devices here.'},
        }

    def _get_free_source_port(self, proto='tcp', auto_allocate=True):
        portrange = SimpleSwitch13.NAT_SPORT_TCP_RANGE if proto == 'tcp' else SimpleSwitch13.NAT_SPORT_UDP_RANGE
        while True:
            sport = random.randint(*portrange)
            if sport not in self.nat_map[proto]:
                if auto_allocate:
                    self.nat_map[proto].add(sport)
                return sport

    def _is_internal_ip(self, ip):
        if 'interface' not in self.knowledge['int']:
            return False
        ip_a = ipaddress.IPv4Address(u"%s" % ip)
        return ip_a in self.knowledge['int']['interface'].network

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0,
                 table_id=0, flags=0, cookie=0):
        self.logger.info("add flow: [T:{table}] {match} =({timeout})> {actions}".format(
            match=match, actions=actions, table=table_id, timeout=idle_timeout))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, cookie=cookie,
                                    priority=priority, match=match, flags=flags,
                                    instructions=inst, idle_timeout=idle_timeout, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, flags=flags, cookie=cookie,
                                    match=match, instructions=inst, idle_timeout=idle_timeout, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Tell the Switch to send the complete packet with packet_in messages
        req = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 2000)
        datapath.send_msg(req)
        # Request the Switch Configuration
        req = parser.OFPGetConfigRequest(datapath)
        datapath.send_msg(req)

        msg = parser.OFPPortDescStatsRequest(datapath=datapath)
        result = api.send_msg(self, msg,
                              reply_cls=parser.OFPPortDescStatsReply,
                              reply_multi=True)
        if len(result) > 0:
            hub.spawn(self._init_topology, result[0].body)
            hub.spawn(self.create_rules_monitor_dhcp, datapath)
        #print(result)
        # install table-miss flow entry

        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _init_topology(self, port_list):
        int_ports = []
        ext_ports = []

        for v in port_list:
            if isinstance(v, OFPPort):
                self.logger.debug("Port name=%s number=%s", v.name, v.port_no)
                for port in self.port_info.itervalues():
                    if v.name == port['name']:
                        port['port_no'] = v.port_no
                        self.logger.info("Found port semantic=%s number=%s", port['semantic'], v.port_no)

        for port in self.port_info.itervalues():
            if port['location'] == 'ext':
                ext_ports.append(port['port_no'])
            elif port['location'] == 'int':
                int_ports.append(port['port_no'])
            else:
                self.logger.error("Unknown port location: %s", port['port_no'])

        self.int_swc.init_ports(self.port_info, int_ports)
        self.ext_swc.init_ports(self.port_info, ext_ports)

        self.logger.info("Topology: external=%s internal=%s", self.ext_swc.ports, self.int_swc.ports)

    def create_rules_monitor_dhcp(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # internal DHCP traffic
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)] +\
            self.int_swc._flood_output_actions(parser, self.port_info['local_int']['port_no'])
        match = parser.OFPMatch(in_port=self.port_info['local_int']['port_no'], eth_type=ether.ETH_TYPE_IP,
                                ip_proto=inet.IPPROTO_UDP, udp_dst=DHCP_PORT)
        self.add_flow(datapath, datapath.ofproto.OFP_DEFAULT_PRIORITY+15, match, actions)

        # external DHCP traffic
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER),
                   parser.OFPActionOutput(self.port_info['local_ext']['port_no'])]
        match = parser.OFPMatch(in_port=self.port_info['external']['port_no'], eth_type=ether.ETH_TYPE_IP,
                                ip_proto=inet.IPPROTO_UDP, udp_dst=DHCP_PORT)
        self.add_flow(datapath, datapath.ofproto.OFP_DEFAULT_PRIORITY+15, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        else:
            self.logger.debug("full length packet in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        if in_port not in self.int_swc.ports and in_port not in self.ext_swc.ports:
            self.logger.info("packet in on unused port %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)
            return

        if eth.ethertype == ether.ETH_TYPE_IP:  # ignore non-IPv4 packets (eg IPv6, IPX)

            ip4 = pkt.get_protocol(ipv4.ipv4)
            udp_head = pkt.get_protocol(udp.udp)
            tcp_head = pkt.get_protocol(tcp.tcp)
            icmp_head = pkt.get_protocol(icmp.icmp)

            if SimpleSwitch13Utils.is_dhcp(pkt):
                dhcp_pkt, cls, rest_data = dhcp.dhcp.parser(pkt.protocols[-1])
                if SimpleSwitch13Utils.is_dhcp_ack(dhcp_pkt):
                    return self.dhcp_discover(msg, dhcp_pkt)

            elif in_port in self.int_swc.ports and (tcp_head is not None or udp_head is not None) and\
                    not self._is_internal_ip(ip4.dst):

                if 'gw' not in self.knowledge['ext']:
                    # we don't have an external network yet, so just DROP the packet for now
                    self.logger.info("no external network configured: drop NAT packet")
                    return

                l4_head = tcp_head if tcp_head is not None else udp_head
                l4_name = l4_head.__class__.__name__
                # guest clients (connected via wifi) are allowed to use HTTP and HTTPS traffic only
                if in_port is self.port_info['wlan']['port_no'] and not \
                        (l4_name in self.NAT_GUEST_ALLOWED and l4_head.dst_port in self.NAT_GUEST_ALLOWED[l4_name]):
                    self.logger.info("dropping {proto}-NAT request from wifi guest client:\
{ip4.src}:{l4.src_port} -> {ip4.dst}:{l4.dst_port}".format(ip4=ip4, l4=l4_head, proto=l4_name))
                    return

                return self.create_nat_forwarding(msg)

            elif icmp_head is not None and icmp_head.type == icmp.ICMP_ECHO_REQUEST:
                switch = 'ext' if in_port in self.ext_swc.ports else 'int'
                if 'ip' in self.knowledge[switch] and ip4.dst == self.knowledge[switch]['ip']:
                    return self.ping_reply(msg)

        if in_port in self.int_swc.ports:
            self.int_swc.packet_in(datapath, msg, in_port)
        else:
            self.ext_swc.packet_in(datapath, msg, in_port)
        return

    def dhcp_discover(self, msg, dhcp_header):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        eth = packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0]

        if in_port in self.ext_swc.ports:
            #discover external network
            self.knowledge['ext']['ip'] = dhcp_header.yiaddr
            self.knowledge['ext']['mac'] = dhcp_header.chaddr
            self.knowledge['ext']['gw'] = SimpleSwitch13Utils.decode_dhcp_option_ip(
                SimpleSwitch13Utils.get_dhcp_option_values(dhcp_header, dhcp.DHCP_GATEWAY_ADDR_OPT)[0])
            self.knowledge['ext']['gw_mac'] = eth.src
                # TODO: this assumption is WRONG if DHCP_SERVER != GW => need to do an ARP discover on GWs IP
            self.logger.info("updated external knowledge")
            self.logger.debug(self.knowledge['ext'])
            self.create_rules_intercept_icmp(datapath, self.knowledge['ext']['ip'])
        elif in_port in self.int_swc.ports:
            # discover internal network
            self.knowledge['int']['mac'] = eth.src
            self.knowledge['int']['ip'] = dhcp_header.siaddr
            self.knowledge['int']['netmask'] = SimpleSwitch13Utils.decode_dhcp_option_ip(
                SimpleSwitch13Utils.get_dhcp_option_values(dhcp_header, dhcp.DHCP_SUBNET_MASK_OPT)[0])
            self.knowledge['int']['interface'] = ipaddress.IPv4Interface(
                u"%s/%s" % (self.knowledge['int']['ip'], self.knowledge['int']['netmask']))
            self.knowledge['int']['clients'][dhcp_header.chaddr] = dhcp_header.yiaddr
            self.logger.info("updated internal knowledge")
            self.logger.debug(self.knowledge['int'])
            self.create_rules_intercept_icmp(datapath, self.knowledge['int']['ip'])
            self.create_rules_router_filter(datapath)

    def create_rules_intercept_icmp(self, datapath, ip):
        # Intercept ICMP Echo Requests to router external IP
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_ICMP,
                                icmpv4_type=icmp.ICMP_ECHO_REQUEST, ipv4_dst=ip)
        self.add_flow(datapath, datapath.ofproto.OFP_DEFAULT_PRIORITY+15, match, actions)

    def create_rules_router_filter(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(TABLEID_FORWARD)]
        for port_id in self.port_info:
            if self.port_info[port_id]['location'] != 'int' or self.port_info[port_id]['semantic'] == 'local_int':
                continue

            match = parser.OFPMatch(in_port=self.port_info[port_id]['port_no'], eth_dst=self.knowledge['int']['mac'])
            mod = parser.OFPFlowMod(datapath=datapath, priority=50,
                                    instructions=inst, match=match, table_id=TABLEID_FILTER)
            datapath.send_msg(mod)

        # traffic actually for the router
        actions = [parser.OFPActionOutput(self.port_info['local_int']['port_no'])]
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_IP,
                                ipv4_dst=self.knowledge['int']['ip'])
        self.add_flow(datapath, 10, match, actions, table_id=TABLEID_FORWARD)

        # traffic to THE INTERNET!!
        # basically everything that is left :D
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=TABLEID_FORWARD)

    def create_nat_forwarding(self, msg):

        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip4 = pkt.get_protocol(ipv4.ipv4)
        udp_head = pkt.get_protocol(udp.udp)
        tcp_head = pkt.get_protocol(tcp.tcp)

        l4_head = tcp_head if tcp_head is not None else udp_head
        l4 = l4_head.__class__.__name__
        is_tcp = l4 == 'tcp'
        sport = self._get_free_source_port(l4)

        self.logger.info("setting up %s-NAT for (%s:%s):%s -> %s:%s" %
                         (l4, ip4.src, l4_head.src_port, sport, ip4.dst, l4_head.dst_port))

        ## incoming rule
        l4_match = {'tcp_src': l4_head.dst_port, 'tcp_dst': sport} if is_tcp else \
            {'udp_src': l4_head.dst_port, 'udp_dst': sport}
        match = parser.OFPMatch(in_port=self.port_info['external']['port_no'],
                                eth_type=eth.ethertype, ip_proto=ip4.proto,
                                ipv4_dst=self.knowledge['ext']['ip'], ipv4_src=ip4.dst, **l4_match)
        actions = [
            parser.OFPActionSetField(eth_src=self.knowledge['int']['mac']),
            parser.OFPActionSetField(eth_dst=eth.src),
            parser.OFPActionSetField(ipv4_dst=ip4.src),
            parser.OFPActionSetField(tcp_dst=tcp_head.src_port) if is_tcp else
            parser.OFPActionSetField(udp_dst=udp_head.src_port),
            parser.OFPActionOutput(in_port),
        ]
        self.add_flow(datapath, 100, match, actions, idle_timeout=IDLE_TIMEOUT_NAT, flags=ofproto.OFPFF_SEND_FLOW_REM,
                      cookie=SimpleSwitch13Utils.create_cookie(sport, is_tcp))

        ## outgoing rule
        l4_match = {'tcp_src': l4_head.src_port, 'tcp_dst': l4_head.dst_port} if is_tcp else \
            {'udp_src': l4_head.src_port, 'udp_dst': l4_head.dst_port}
        match = parser.OFPMatch(
            in_port=in_port, eth_dst=eth.dst,
            eth_type=eth.ethertype, ip_proto=ip4.proto,
            ipv4_src=ip4.src, ipv4_dst=ip4.dst,
            **l4_match
        )
        actions = [
            parser.OFPActionSetField(eth_src=self.knowledge['ext']['mac']),
            parser.OFPActionSetField(eth_dst=self.knowledge['ext']['gw_mac']),
            parser.OFPActionSetField(ipv4_src=self.knowledge['ext']['ip']),
            parser.OFPActionSetField(tcp_src=sport) if is_tcp else
            parser.OFPActionSetField(udp_src=sport),
            parser.OFPActionOutput(self.port_info['external']['port_no']),
        ]
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 100, match, actions, msg.buffer_id, idle_timeout=IDLE_TIMEOUT_NAT)
        else:
            self.add_flow(datapath, 100, match, actions, idle_timeout=IDLE_TIMEOUT_NAT)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def handle_flow_removed(self, ev):
        is_nat_cookie, is_tcp, port = SimpleSwitch13Utils.extract_cookie(ev.msg.cookie)
        type_ = 'tcp' if is_tcp else 'udp'
        if is_nat_cookie:
            try:
                self.logger.info("release NAT source port {0}:{1}".format(type_, port))
                self.nat_map[type_].remove(port)
            except KeyError:
                self.logger.warn("tried to free port: {0}:{1} but is was not reserved".format(type_, port))
        else:
            self.logger.info("flow removed; unknown cookie: {0:x} ({0:b})".format(ev.msg.cookie))

    def ping_reply(self, msg):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        icmp_reply = SimpleSwitch13Utils.create_icmp_reply(packet.Packet(msg.data))
        self.logger.info("ICMP reply: {0}".format(icmp_reply))
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, data=icmp_reply.data,
            actions=[parser.OFPActionOutput(in_port)])
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        flags = []

        if msg.flags & ofp.OFPC_FRAG_NORMAL:
            flags.append('NORMAL')
        if msg.flags & ofp.OFPC_FRAG_DROP:
            flags.append('DROP')
        if msg.flags & ofp.OFPC_FRAG_REASM:
            flags.append('REASM')
        self.logger.info('OFPGetConfigReply received: '
                         'flags=%s miss_send_len=%d',
                         ','.join(flags), msg.miss_send_len)


class SimpleSwitch13Utils(object):

    @staticmethod
    def is_dhcp(pkt):
        udp_head = pkt.get_protocol(udp.udp)
        return udp_head is not None and udp_head.src_port in (67, 68) and udp_head.dst_port in (67, 68)

    @staticmethod
    def is_dhcp_ack(dhcp_header):
        return dhcp_header.op == dhcp.DHCP_BOOT_REPLY and \
            SimpleSwitch13Utils.get_dhcp_option_values(dhcp_header, dhcp.DHCP_MESSAGE_TYPE_OPT)[0] == chr(dhcp.DHCP_ACK)

    @staticmethod
    def get_dhcp_option_values(proto_header, tag):
        assert isinstance(proto_header, dhcp.dhcp)
        return [o.value for o in proto_header.options.option_list if o.tag == tag]

    @staticmethod
    def decode_dhcp_option_ip(ipstr):
        return "{:d}.{:d}.{:d}.{:d}".format(*map(lambda x: ord(x), ipstr))

    @staticmethod
    def create_icmp_reply(pkt):
        eth = pkt.get_protocol(ethernet.ethernet)
        ip4 = pkt.get_protocol(ipv4.ipv4)
        icmp_request = pkt.get_protocol(icmp.icmp)

        icmp_reply = packet.Packet()
        icmp_reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                                  dst=eth.src,
                                                  src=eth.dst))
        icmp_reply.add_protocol(ipv4.ipv4(dst=ip4.src,
                                          src=ip4.dst,
                                          proto=ip4.proto))
        icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                          code=icmp_request.code,
                                          data=icmp_request.data))
        icmp_reply.serialize()
        return icmp_reply

    @staticmethod
    def _get_bit(data, bit):
        return (data >> (bit - 1)) & 1

    @staticmethod
    def extract_cookie(cookie):
        is_nat_cookie = SimpleSwitch13Utils._get_bit(cookie, 34)
        is_tcp = SimpleSwitch13Utils._get_bit(cookie, 33)
        port = cookie & ((1 << 32) - 1)
        return is_nat_cookie, is_tcp, port

    @staticmethod
    def create_cookie(port, is_tcp=True):
        head = 2 + bool(is_tcp) << 32
        return head + port