from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        #
        # if msg.buffer_id != ofp.OFP_NO_BUFFER:
        #     return
        # print("data path ****///: ",dp)
        # print("msg /: ", msg)
        # print("IN Port: ", in_port)
        # print(pkt)
        # print("ETH: ", eth)
        # print("DID: ", did)


        # print("THIS IS THE HT")
        # print(self.ht)
        # print(type(self.ht))


        # deterministically determining out port
        out_port = 1 if in_port == 2 else 2
        # switching out port
        # out_port = 1 if out_port == 2 else 2

        print("OUT Port: ", out_port)
        acts = [psr.OFPActionOutput(out_port)] # do I need this?

        # IPv4 has proto 2048
        # need to check if tcp
        if eth.ethertype == 2048:
            tcph = pkt.get_protocols(tcp.tcp)
            # print(tcph)

            if len(tcph) >= 1:
                iph = pkt.get_protocols(ipv4.ipv4)
                print("=-==-=-=-IP header=-==---=-=")
                print(iph)
                print("=-==-=-=-=-=-=-=-==-==---=-=")

                # parsing ip and tcp headers
                srcip   = iph[0].src
                dstip   = iph[0].dst
                ipproto = iph[0].proto
                srcport = tcph[0].src_port
                dstport = tcph[0].dst_port

                flow_key = (srcip, dstip, srcport, dstport)
                opp_flow_key = (dstip, srcip, dstport, srcport)

                # if packet comes from port 1
                if in_port == 1:
                    # add flow_key to hash table if not already in
                    if flow_key not in self.ht:
                        self.ht.add(flow_key)
                    # insert flow in switch
                    mtc = psr.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip, tcp_src=srcport, tcp_dst=dstport, ip_proto=ipproto)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return

                # if packet comes from port 2
                if in_port == 2:
                    # if opposite flow key not in the has table, drop the packet
                    if opp_flow_key not in self.ht:
                        acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
                    # otherwise
                    else:
                        # forward to port 1
                        # dp.send_msg(1)
                        # acts = [psr.OFPActionOutput(1)]
                        # add flow entry to switch again
                        mtc = psr.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip,
                                           tcp_src=srcport, tcp_dst=dstport, ip_proto=ipproto)
                        self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                        if msg.buffer_id != ofp.OFP_NO_BUFFER:
                            return









        #
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
