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

class L4Mirror14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Mirror14, self).__init__(*args, **kwargs)
        self.ht = {}

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
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)

        out_port = 2 if in_port == 1 else 1
        #

        acts = [psr.OFPActionOutput(out_port)]

        # IPv4 has proto 2048
        if eth.ethertype == 2048:
            tcph = pkt.get_protocols(tcp.tcp)
            # check if tcp
            if len(tcph) >= 1:
                iph = pkt.get_protocols(ipv4.ipv4)
                # print("=-==-=-=-TCP header=-==---=-=")
                # header = tcp.tcp(bits=(tcp.TCP_SYN | tcp.TCP_ACK))
                # print("header: ", header)
                # print("tcph: ", tcph[0])
                # print(in_port == 2 and tcph[0].has_flags(tcp.TCP_SYN) and not tcph[0].has_flags(tcp.TCP_ACK))
                # print("in port: ", in_port==2)
                # print("has syn: ", tcph[0].has_flags(tcp.TCP_SYN))
                # print("not has ack: ", not tcph[0].has_flags(tcp.TCP_ACK))
                # print("=-==-=-=-=-=--=-=-==-==---=-=")

                # parsing ip and tcp headers
                srcip = iph[0].src
                dstip = iph[0].dst
                ipproto = iph[0].proto
                srcport = tcph[0].src_port
                dstport = tcph[0].dst_port

                flow_key = (srcip, dstip, srcport, dstport)
                opp_flow_key = (dstip, srcip, dstport, srcport)

                if in_port == 2 and tcph[0].has_flags(tcp.TCP_SYN) and not tcph[0].has_flags(tcp.TCP_ACK):
                    print("port 2")
                    # if flow_key not in self.ht.keys():
                    print("FLOW INITIATED")
                    print("1 st packet")
                    self.ht[flow_key] = 1
                    acts.append(psr.OFPActionOutput(3))
                    # else:
                    #     if self.ht[flow_key] == 10:
                    #         print("tenth packet!")
                    #         del self.ht[flow_key]
                    #         mtc = psr.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip,
                    #                            tcp_src=srcport, tcp_dst=dstport, ip_proto=ipproto)
                    #         self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    #         if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    #             return
                    #     else:
                    #         self.ht[flow_key] += 1
                    #         print(self.ht[flow_key], "th packet")
                elif in_port == 2 and flow_key in self.ht.keys():
                    if self.ht[flow_key] == 9:
                        print("10th packet")
                        del self.ht[flow_key]
                        mtc = psr.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip,
                                           tcp_src=srcport, tcp_dst=dstport, ip_proto=ipproto)
                        self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                        if msg.buffer_id != ofp.OFP_NO_BUFFER:
                            return

                    else:
                        self.ht[flow_key] += 1
                        print(self.ht[flow_key], "th packet")
                        acts.append(psr.OFPActionOutput(3))
                if in_port == 1:

                    #
                    # if flow_key in self.ht.keys():
                    #     if self.ht[flow_key] == 10:
                    #         print("DEL")
                    #         del self.ht[flow_key]
                    #         mtc = psr.OFPMatch(eth_type=eth.ethertype, in_port=in_port, ipv4_src=srcip, ipv4_dst=dstip,
                    #                            tcp_src=srcport, tcp_dst=dstport, ip_proto=ipproto)
                    #         self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    #         if msg.buffer_id != ofp.OFP_NO_BUFFER:
                    #             return
                    #     else:
                    #         print("inc two")
                    #         self.ht[flow_key] += 1



                    print("port 1")
                    # acts.append(psr.OFPActionOutput(3))
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
