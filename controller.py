from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, Padding, IPv6 
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time
from ipaddress  import ip_network, ip_address

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

class P4Controller(Thread):
    def __init__(self, sw,ips, macs,subnets, intfs_mappings,start_wait=0.3):
        super(P4Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {} #MAC --> PORT 
        self.arp = {} # IP --> MAC 
        self.route_table = {} #IP --> IP(dist)  
        self.stop_event = Event()
        self.ips = ips
        self.macs = macs 
        self.intfs_mappings = intfs_mappings #Subnet --> (mac,IP) 
        self.subnets = subnets
        print(str(self.sw) + f" IP: {self.ips} \n Sub: {self.subnets}") 
        self.pktcache = [] 
    
    def addArpEntry(self, ip, mac): 
        if ip in self.arp.keys(): 
            return 
        mask = 0xFFFFFFFF
        for s in self.subnets: 
            if ip_address(ip) in ip_network(s): 
                print("Adding arp entry " + f"{ip} --> {mac}") 
                self.arp[ip] = mac 
                self.sw.insertTableEntry(table_name='MyIngress.arp',
                        match_fields={'global_next_hop': [ip,mask]},
                        action_name='MyIngress.set_mac',
                        action_params={'dst_mac': mac },
                        priority = 1 
                        )
    def addMacAddr(self, mac, port):
        if mac in self.port_for_mac: return
        print("Adding port entry " + f"{mac} --> {port}") 
        self.port_for_mac[mac] = port
        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})

    def req_to_reply(self, pkt): 
        subnet = None 
        dst_ip = pkt[ARP].pdst
        for s in self.subnets: 
            if ip_address(dst_ip) in ip_network(s): 
                subnet = s
        pkt[ARP].op = 2
        pkt[ARP].hwdst = pkt[ARP].hwsrc 
        pkt[ARP].pdst = pkt[ARP].psrc
        pkt[ARP].hwsrc = self.intfs_mappings[subnet][0]
        pkt[ARP].psrc = self.intfs_mappings[subnet][1]
        #This is the mess up line
        pkt[Ether].dst = pkt[Ether].src
        pkt[Ether].src = pkt[ARP].hwsrc 

    def handleArpReply(self, pkt):
        dst_ip = pkt[ARP].pdst 
        src_ip = pkt[ARP].psrc 
        send_packet = pkt
        if src_ip not in self.arp.keys(): 
            self.addArpEntry(src_ip,pkt[ARP].hwsrc) 
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        if dst_ip in self.ips: 
            send_packet = self.pktcache.pop(0) 
            send_packet[Ether].dst = pkt[Ether].dst 
        self.sw.printTableEntries()
        send_packet.show2()
        self.send(send_packet)

    def handleArpRequest(self, pkt):
        dst_ip = pkt[ARP].pdst 
        src_ip = pkt[ARP].psrc 
        if src_ip not in self.arp.keys(): 
            self.addArpEntry(src_ip,pkt[ARP].hwsrc) 
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        if dst_ip in self.ips: 
            self.req_to_reply(pkt) 
        #Only send it forward if dst_ip is in the subnets 
        for s in self.subnets: 
            if ip_address(dst_ip) in ip_network(s): 
                self.send(pkt) 
                return 

    def send_ARP_Req(self,pkt,ip):
        cpu_metadata = pkt[CPUMetadata] 
        cpu_metadata.origEthertype = 0x806
        src_ip = None
        src_mac = None
        for s in self.subnets: 
            if ip_address(ip) in ip_network(s): 
                src_mac = self.intfs_mappings[s][0] 
                src_ip = self.intfs_mappings[s][1]
        copy_srcPort = cpu_metadata.srcPort
        ether = Ether(src= src_mac, dst="ff:ff:ff:ff:ff:ff") 
        cpu_layer =  CPUMetadata(srcPort = copy_srcPort)
        arp_layer = ARP(op =1, pdst = ip, hwlen = 6, plen = 4, psrc = src_ip, hwsrc = src_mac, hwtype = 0x1, ptype = 0x800) 
        arp_request = ether / cpu_layer / arp_layer 
        self.pktcache.append(pkt) 
        #arp_request.show2() 
        self.send(arp_request)


    def mask(self,addr): 
        first_three_chunks = ".".join(addr.split(".")[:3])
        first_three_chunks += ".0" 
        return first_three_chunks 

    def handleIPNetwork(self,pkt): 
       # if pkt[IP].dst == "10.0.0.2": 
       #     return
#        print("Switch: " + str(self.sw)) 
#        print("Route Table: " + str(self.route_table))
#        print("Arp Table: " + str(self.arp)) 
#        print("Ports: " + str(self.port_for_mac)) 
        next_hop = self.route_table[pkt[IP].dst] 
#        print("Next Hop IP: " + str(next_hop)) 
        if next_hop in self.arp.keys(): 
            dstMac = self.arp[next_hop] #arp lookup  
            outPort = self.port_for_mac[dstMac] #port lookup 
           # self.send(pkt) 
        else: 
            self.send_ARP_Req(pkt,next_hop) 

    def handleIP(self,pkt): 
        #Check which subnet the dst address is in 
        srcPort = pkt[CPUMetadata].srcPort 
        dstIP = pkt[IP].dst  
        self.handleIPNetwork(pkt) 
        
    def handlePkt(self, pkt):
        if CPUMetadata not in pkt: return 
        if pkt[CPUMetadata].fromCpu == 1: return
        #pkt.show2() 
        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                print("ARP Req from: " + str(pkt[ARP].psrc) + "  On Switch: " + str(self.sw)) 
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                print("ARP RESP from: " + str(pkt[ARP].psrc) + "    On Switch: " + str(self.sw)) 
                self.handleArpReply(pkt)
        if IP in pkt: 
            print("ip PACKET RECIEVED on" + str(self.sw))
            self.handleIP(pkt) 


    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        #pkt.show2()
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(P4Controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(P4Controller, self).join(*args, **kwargs)
