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

### Group work of:
# Patrick Welzel (1478819)
# Manisha Luthra (2687667)
# Pratyush Agnihotri (2387187)

# We have implemented our code on OF1.3 and following code is used for creating topology:
# sudo mn --custom lab5-topo.py --topo lbtopo --mac --arp --switch=ovsk,protocols=OpenFlow13 --controller=remote,ip=127.0.0.1

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp

virtualIp = '192.168.0.0'
serverMacDest = {'srv1': {'eth': '00:00:00:00:00:07', 'ip': '10.0.0.7', 'port': 7},
                 'srv2': {'eth': '00:00:00:00:00:08', 'ip': '10.0.0.8', 'port': 8}}
s1 = 513
s2 = 514

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.create_rules_intercept_virtualip(self, datapath, virtualIp)
        self.create_rules_load_balancer(self, datapath, virtualIp)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=1):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_head = pkt.get_protocol(arp.arp)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

         # Handle ARP response for request to virtual IP
        if arp_head is not None and src not in serverMacDest and arp_head.dst_ip == virtualIp:
            if arp_head.opcode == arp.ARP_REQUEST and datapath.id == s1:
                arp_reply = self.create_arp_reply(pkt, arp_head.src_mac, virtualIp, arp_head.src_ip)
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                    data=arp_reply.data, actions=[parser.OFPActionOutput(in_port)])
                datapath.send_msg(out)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @staticmethod
    def create_rules_intercept_virtualip(self, datapath, ip):
        if datapath.id == s1:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_op=arp.ARP_REQUEST, arp_tpa=ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]

            self.add_flow(datapath, 1, match, actions)

    @staticmethod
    def create_rules_load_balancer(self, datapath, vip):
        if datapath.id == s1:

            # first from client to server
            parser = datapath.ofproto_parser
            #even traffic to srv1
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=vip, ipv4_src=('0.0.0.0', '0.0.0.1'))
            actions = [parser.OFPActionSetField(eth_dst=serverMacDest['srv1']['eth']),
                       parser.OFPActionSetField(ipv4_dst=serverMacDest['srv1']['ip']),
                       parser.OFPActionOutput(serverMacDest['srv1']['port'])]
            self.add_flow(datapath, 1, match, actions)

            #odd traffic to srv2
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=vip, ipv4_src=('0.0.0.1', '0.0.0.1'))
            actions = [parser.OFPActionSetField(eth_dst=serverMacDest['srv2']['eth']),
                       parser.OFPActionSetField(ipv4_dst=serverMacDest['srv2']['ip']),
                       parser.OFPActionOutput(serverMacDest['srv2']['port'])]
            self.add_flow(datapath, 1, match, actions)

            # now from server to client
            #even traffic from srv1
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=serverMacDest['srv1']['ip'])
            actions = [parser.OFPActionSetField(ipv4_src=vip),
                       parser.OFPActionOutput(3)]
            self.add_flow(datapath, 1, match, actions)

            #odd traffic from srv2
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                    ipv4_src=serverMacDest['srv2']['ip'])
            actions = [parser.OFPActionSetField(ipv4_src=vip),
                       parser.OFPActionOutput(3)]
            self.add_flow(datapath, 1, match, actions)

    @staticmethod
    def create_arp_reply(pkt, dest_mac, sourceip, destip):
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                                 dst=dest_mac))
        arp_reply.add_protocol(arp.arp(hwtype=arp.ARP_HW_TYPE_ETHERNET, opcode=arp.ARP_REPLY,
                                       src_ip=sourceip, dst_mac=dest_mac, dst_ip=destip))

        arp_reply.serialize()
        return arp_reply
