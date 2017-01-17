## Software Defined Networking WS2014/15
## Exercise 1

# Group members: Patrick Welzel (1478819), Mahshid Okhovatzadeh (2796600)

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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp, ipv4


class MirrorPortSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MirrorPortSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.hosts_for_omniping = [('10.0.0.1', '00:00:00:00:00:1', 1),
                                   ('10.0.0.2', '00:00:00:00:00:2', 2),
                                   ('10.0.0.3', '00:00:00:00:00:3', 3), ]

    @staticmethod
    def _duplicate_pingreq_to_host(pkg, target):
        eth = pkg.get_protocol(ethernet.ethernet)
        ipv4_frame = pkg.get_protocol(ipv4.ipv4)
        icmp_frame = pkg.get_protocol(icmp.icmp)

        new_packet = packet.Packet()
        new_packet.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                                  dst=target[1],
                                                  src=eth.src))
        new_packet.add_protocol(ipv4.ipv4(dst=target[0],
                                          src=ipv4_frame.src,
                                          proto=ipv4_frame.proto))
        new_packet.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST,
                                          code=icmp_frame.code,
                                          csum=icmp_frame.csum,
                                          data=icmp_frame.data))
        return new_packet

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def my_packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        icmp_frame = pkt.get_protocol(icmp.icmp)

        # in this case, only forward packet.. (but without learning)
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if icmp_frame is not None and icmp_frame.type == icmp.ICMP_ECHO_REQUEST:
            # we have a ping request, doing the nasty magic :3

            self.logger.info("ping request in %s %s %s %s", dpid, src, dst, msg.in_port)

            for target in [host for host in self.hosts_for_omniping if host[1] != src]:

                new_ping_packet = self._duplicate_pingreq_to_host(pkt, target)
                new_ping_packet.serialize()

                actions = [datapath.ofproto_parser.OFPActionOutput(target[2])]

                # never aks my why 0xffffffff; the assertion error said so!!! (ohh, fuck this shit :)
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=0xffffffff, in_port=msg.in_port,
                    actions=actions, data=new_ping_packet.data)
                datapath.send_msg(out)

        else:
            # so we have a normal packet, just deliver it, but do not add flow rules
            self.logger.info("normal packet in %s %s %s %s", dpid, src, dst, msg.in_port)

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
