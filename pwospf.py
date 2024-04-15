from scapy.fields import ByteField, ShortField, XIntField, LongField, ConditionalField, IPField, FieldListField 
from scapy.all import Packet, IP
from scapy.packet import bind_layers
#from scapy.all import Packet, Ether, IP, ARP, Padding, IPv6 
import struct

TYPE_HELLO = 1 
TYPE_LSU = 4 
class LinkStateAdvertisement(Packet):
    fields_desc = [
        IPField("subnet", "0.0.0.0"),  # Default route subnet
        IPField("mask", "255.255.255.0"),  # Common subnet mask
        IPField("router_id", "0.0.0.0")  # ID of neighboring router, 0 if none
    ]
class Pwospf(Packet): 
    name = "Pwospf" 
    fields_desc = [
            ByteField("version", 2), 
            ByteField("type", None),
            ShortField("packet_len", None), 
            XIntField("router_id", None), 
            XIntField("area_id", None), 
            ShortField("checksum", None), 
            ShortField("autype", 0),
            LongField("authentication",0), 
            ConditionalField(
                IPField("mask", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("helloint", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("padding", None), 
                lambda pkt: pkt.type == TYPE_HELLO
                ),
            ConditionalField(
                ShortField("seq", None), 
                lambda pkt: pkt.type == TYPE_LSU 
                ),
            ConditionalField(
                ShortField("ttl", None), 
                lambda pkt: pkt.type == TYPE_LSU 
                ),
            ConditionalField(
                XIntField("num_ads", None), 
                lambda pkt: pkt.type == TYPE_LSU
                ),
            ConditionalField(
                FieldListField("advertisements", [], LinkStateAdvertisement, count_from=lambda pkt: pkt.num_advertisements),
                lambda pkt: pkt.type == TYPE_LSU
                ),
            ]
    def post_build(self,p,pay): 
        if self.packet_len is None: 
            length = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", length) + p[4:] 
        return p + pay 

bind_layers(IP,Pwospf, proto=89) 



