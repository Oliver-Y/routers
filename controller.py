from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, Padding, IPv6 
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import Pwospf
import time, threading 
from ipaddress  import ip_network, ip_address, IPv4Address

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
ALLSPFRouters = "224.0.0.5"
HELLO_INT = 5
TYPE_HELLO = 1 
TYPE_LSU = 4 

class OSPF_intfs(): 
    def __init__(self,ip,subnet,helloint,router_id,area_id): 
        self.ip = ip 
        network = ip_network(subnet) 
        self.subnet = network 
        self.mask = network.netmask 
        self.helloint = helloint 
        self.router_id = router_id 
        self.area_id = area_id
        self.timers = {}  
        self.flag = False  #Flag indicates if a change has been made
        #Need to index this by Neighbor_ip? 
    def __str__(self):
        return (f"OSPF Interface:\n"
                f"  IP Address: {self.ip}\n"
                f"  Subnet: {self.subnet}\n"
                f"  Subnet Mask: {self.mask}\n"
                f"  Hello Interval: {self.helloint} seconds\n"
                f" OSPF Timers: {self.timers}\n") 
    def update_status(self,neighbor_id, neighbor_ip): 
        if neighbor_ip in self.timers.keys(): 
            timer,nid = self.timers[neighbor_ip] 
            timer.cancel() 
            timer = threading.Timer(3*self.helloint, self.timer_cb, args = [neighbor_ip]) 
            self.timers[neighbor_ip] = (timer,nid)  
            timer.start()
        else: 
            timer = threading.Timer(3*self.helloint,self.timer_cb, args = [neighbor_ip]) 
            self.timers[neighbor_ip] = (timer,neighbor_id) 
            self.timers[neighbor_ip][0].start() 
            self.flag = True 
        print(f"Intfs {self.subnet} --> {self.timers}") 

    def timer_cb(self, neighbor_ip): 
        print(f"Timeout on {neighbor_ip}") 
        del self.timers[neighbor_ip] 
        self.flag = True 

    def lsu_needed(self): 
        ret = self.flag 
        self.flag = False 
        return ret 

    def build_packet(self,src_mac): 
        l2_ether = Ether(src =src_mac, dst ="ff:ff:ff:ff:ff:ff") 
        l2_cpumetadata = CPUMetadata(origEtherType=0x0800, srcPort = 1)
        l3_ipv4 = IP(src=self.ip, dst=ALLSPFRouters) 
        l3_ospf = Pwospf(type = TYPE_HELLO, router_id = self.router_id, area_id = self.area_id, mask = self.mask, helloint = self.helloint) 
        hello_pkt = l2_ether / l2_cpumetadata/ l3_ipv4 / l3_ospf
        #hello_pkt.show2() 
        return hello_pkt 

class RouteTable(): 
    def __init__(self,sw): 
        self.sw = sw 
        self.route_table = {} 
    def addEntry(self,ip,mask):
        ip_int = int(ip_address(ip)) 
        mask_int = int(ip_address(mask)) 
        #TODO: assumption that we only work with /24 addresses 
        priority = 1 if mask_int == 0xFFFFFF00 else 2
        subnet = IPv4Address(ip_int & mask_int)
        self.route_table[subnet] = ip 
        print(f"{self.sw}: {subnet},{mask} --> {ip}") 
        self.sw.insertTableEntry(
            table_name="MyIngress.fwd_l3",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_dst_ip",
            action_params={"next_hop":ip},
            priority = priority,
        )
    def delEntry(self,subnet,mask): 
        ip_int = int(ip_address(ip)) 
        mask_int = int(ip_address(mask)) 
        #TODO: assumption that we only work with /24 addresses 
        priority = 1 if mask_int == 0xFFFFFF00 else 2
        subnet = IPv4Address(ip_int & mask_int)
        del self.route_table[subnet] 
        print(f"{self.sw}: {subnet},{mask} --> {ip}") 
        self.sw.removeTableEntry(
            table_name="MyIngress.fwd_l3",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_dst_ip",
            action_params={"next_hop":ip},
            priority = priority,
        )
    def nextHop(self,ip): 
        if ip in self.route_table.keys(): 
            return ip 
        for k,v in self.route_table.items(): 
            if ip_address(ip) in ip_network(k): 
                return v
        return None


class P4Controller(Thread):
    def __init__(self,sw,ips,macs,subnets,intfs_mappings,router_id,area_id,lsuint=10,start_wait=0.3):
        super(P4Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        #Data-plane tables 
        self.port_for_mac = {} #MAC --> PORT 
        self.arp = {} # IP --> MAC 
        #self.route_table = {} #IP/Mask --> IP(dist)  
        self.routes = RouteTable(sw) 
        self.stop_event = Event()
        #Control-plane datastructures
        self.macs = macs 
        self.ips = ips
        self.intfs_mappings = intfs_mappings #Subnet --> (mac,IP) 
        self.subnets = subnets
        print(str(self.sw) + f" IP: {self.ips} \n Sub: {self.subnets}") 
        self.pktcache = [] 
        #OSPF Router Vars
        self.router_id = router_id 
        self.area_id = area_id 
        self.lsuint = lsuint #LinkState floods 
        self.ospf_intfs = [] 
        #OSPF interface variables --> for each interface mapping 
        for k,v in self.intfs_mappings.items(): 
            intfs = OSPF_intfs(v[1],k,HELLO_INT,self.router_id, self.area_id) 
            self.ospf_intfs.append(intfs) 
            #self.ospf_hello_cb(HELLO_INT,intfs) 
        #TEST: DEMOING SECOND INTERFACE 
        self.ospf_hello_cb(HELLO_INT,self.ospf_intfs[1],1) 
        #self.ospf_lsu_cb(lsuint) 

    #TODO: LSU FLOODS + HELLO 
    def lsu_flood(self): 
        pass 
    def hello_send(self): 
        #Construct Hello Packet 
        pass 
    def ospf_lsu_cb(self,interval): 
        threading.Timer(interval,self.ospf_lsu_cb, args=[interval]).start() 
        self.lsu_flood() 
        print("OSPF Lsu\n") 
    def ospf_hello_cb(self,interval,interface,interface_index): 
        print(f"Hello_cb {self.sw}") 
        threading.Timer(interval,self.ospf_hello_cb,args =[interval, interface, interface_index]).start() 
        src_mac = self.macs[interface_index] 
        pkt = interface.build_packet(src_mac) 
        #print(f"OSPF Hello on {interface}\n") 
        self.send(pkt) 
    
    
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
        #send_packet.show2()
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
        next_hop = self.routes.nextHop(pkt[IP].dst) 
        if next_hop == None: 
            return
        if next_hop in self.arp.keys(): 
            dstMac = self.arp[next_hop] #arp lookup  
            outPort = self.port_for_mac[dstMac] #port lookup 
           # self.send(pkt) 
        else: 
            #It'll always go here, should never go above? 
            self.send_ARP_Req(pkt,next_hop) 

    def handleIP(self,pkt): 
        #Check which subnet the dst address is in 
        srcPort = pkt[CPUMetadata].srcPort 
        dstIP = pkt[IP].dst  
        self.handleIPNetwork(pkt) 

    def pwospf_drop(self,pkt): 
        #Drop packets not in the right area and that are also not ourselves (this should never happen tho) 
        return pkt[Pwospf].area_id != self.area_id or pkt[Pwospf].router_id == self.router_id 
    def pwospf_lsu_flood(self): 
        print("Lsu Flood") 
        pass 

    def handlePwospf_hello(self,pkt): 
        if not self.pwospf_drop(pkt): 
            incoming_ip = pkt[IP].src #Find the equivalent subnet 
            nid = pkt[Pwospf].router_id
            #print(f"Inncoming IP: {incoming_ip} \t Nid: {nid}")
            for intfs in self.ospf_intfs: 
                if ip_address(incoming_ip) in ip_network(intfs.subnet): 
                    intfs.update_status(nid,incoming_ip) 
                if intfs.lsu_needed(): 
                    self.pwospf_lsu_flood() 
        else: 
            print("PWOSPF packet dropped") 


        
    def handlePwospf(self,pkt): 
        if pkt[Pwospf].type == TYPE_HELLO: 
            self.handlePwospf_hello(pkt) 
        elif pkt[Pwospf].type == TYPE_LSU: 
            self.handlePwospf_hello(pkt) 
        else: 
            print("Faulty PWOSPF Packet") 

    def handlePkt(self, pkt):
        if CPUMetadata not in pkt: 
            return 
        if pkt[CPUMetadata].fromCpu == 1: return
        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                print("ARP Req from: " + str(pkt[ARP].psrc) + "  On Switch: " + str(self.sw)) 
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                print("ARP RESP from: " + str(pkt[ARP].psrc) + "    On Switch: " + str(self.sw)) 
                self.handleArpReply(pkt)
        if Pwospf in pkt: 
            print("Pwospf on " + str(self.sw)) 
            #pkt.show2()
            self.handlePwospf(pkt) 
        elif IP in pkt: 
            print("IP on" + str(self.sw))
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
