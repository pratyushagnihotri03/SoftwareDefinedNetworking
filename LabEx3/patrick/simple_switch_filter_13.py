#COPYRIGHT AND LICENCE BLABLA FROM ORIGINAL FILE.

### Group work of:
# Manisha Luthra (2687667)
# Pratyush Agnihotri (2387187)
# Patrick Welzel (1478819)

from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

TABLEID_FILTER = 0
TABLEID_FORWARD = 1


class SimpleSwitchFilter13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchFilter13, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(lambda: {})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entrys, redirecting packets to controller, on both tables
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        for table_id in [TABLEID_FILTER, TABLEID_FORWARD]:
            mod = parser.OFPFlowMod(datapath=datapath, match=match, instructions=instructions,
                                    table_id=table_id, priority=ofproto.OFP_DEFAULT_PRIORITY,
                                    cookie=0xdead00 + table_id)
            datapath.send_msg(mod)

    def add_flow(self, datapath, in_port, src, dst, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.allow_mac_from_port(datapath, in_port, src)

        match = datapath.ofproto_parser.OFPMatch(eth_dst=dst)

        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=ofproto.OFP_DEFAULT_PRIORITY+5,
                                match=match, instructions=instructions, table_id=TABLEID_FORWARD)
        datapath.send_msg(mod)

    def allow_mac_from_port(self, datapath, port, mac=None):
        self.logger.info("allowing src=%s on port S%s.%s", '*' if mac is None else mac, datapath.id, port)
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=port, eth_src=mac)
        inst = [parser.OFPInstructionGotoTable(TABLEID_FORWARD)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=datapath.ofproto.OFP_DEFAULT_PRIORITY+10,
                                instructions=inst, match=match, table_id=TABLEID_FILTER)
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
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.logger.info("packet in s%s src=%s dst=%s in_port=%s (cookie=%x)", dpid, src, dst, in_port, msg.cookie)

        # learn a mac address to avoid FLOOD next time and enforce the one mac
        # address per port rule
        print("s%s: in_port=%s known ports=%s" % (dpid, in_port, self.mac_to_port[dpid].values()))
        if in_port >= 3:
            self.mac_to_port[dpid][src] = in_port
        else:
            if in_port in self.mac_to_port[dpid].values() and (src not in self.mac_to_port[dpid].keys() or in_port != self.mac_to_port[dpid][src]):
                self.logger.info("dropping spoofed packet on s%s src=%s dst=%s in_port=%s", dpid, src, dst, in_port)
                return
            else:
                self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, in_port, src, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

#Thanks for watching...