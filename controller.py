from threading import Thread, Event
from collections import deque
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, Padding, IPv6 
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import Pwospf, LinkStateAdvertisement
import time, threading 
from ipaddress  import ip_network, ip_address, IPv4Address

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
ALLSPFRouters = "224.0.0.5"
HELLO_INT = 5
TYPE_HELLO = 1 
TYPE_LSU = 4 
TTL_DEFAULT = 30 

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
        #print(f"Intfs {self.subnet} --> {self.timers}") 

    def timer_cb(self, neighbor_ip): 
        print(f"Timeout on {neighbor_ip}") 
        del self.timers[neighbor_ip] 
        self.flag = True 

    #Clears the flag
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

class RouteTopology(): 
    def __init__(self,sw,router_id,area_id,subnet_masks, intfs_ips ): 
        self.sw = sw 
        self.ips = intfs_ips #Your own interface IPs 
        self.id_to_ip = {} #Tracks the interface for the RID. 
        self.subnet_masks = subnet_masks #These are the subnets that I own  
        self.router_id = router_id
        self.area_id = area_id 
        self.adj = {router_id: []} #Maps RID --> list of RID. updated on Hello Packet 
        self.lsa = {router_id: self.subnet_masks} #Maps RID --> (subnet,mask) updated on LSU. If the subnet is on your own put a mask of /32 
        self.routes = {} #Maps Subnet+Mask --> Next Hop IP. Keep track of state of Dataplane table 
        self.seq_num = {} #Maps Adjacent Host(RID) --> Sequence number of LSU 


    def check_seq(self,pkt): 
        rid = pkt[Pwospf].router_id 
        if rid not in self.seq_num.keys(): 
            self.seq_num[rid] = pkt[Pwospf].seq 
            return False 
        if pkt[Pwospf].seq <= self.seq_num[rid]: 
            return True 
        self.seq_num[rid] = pkt[Pwospf].seq 
        return False 


    #TODO: if change is detected in LSU, send LSU flood?
    def lsu_update(self,pkt): 
        rid = pkt[Pwospf].router_id 
        if self.check_seq(pkt): 
            return 
        lsu_ads = pkt[Pwospf].advertisements
        lsu_ad = pkt[Pwospf].advertisements[0]
        lsu_num = pkt[Pwospf].num_ads 
        for i in range(0,lsu_num): 
            subnet = lsu_ad.subnet 
            mask = lsu_ad.mask 
            #Only append if not redundant. 
            if (subnet,mask) not in self.lsa[lsu_ad.router_id]: 
                self.lsa[lsu_ad.router_id].append((subnet,mask)) 
            path = self.next_hop(subnet,mask) 
            #print(f"{self.sw} --> Path: {path} to {subnet}/{mask}") 
            #print(f"{self.sw} --> IPS: {self.ips}") 
            if len(path) > 1: 
                next_hop =self.id_to_ip[path[1]] 
                mask = 0xFFFFFF00
                self.routes[(subnet,mask)] = next_hop 
                self.addRoute(next_hop,subnet,mask) 
            lsu_ad = lsu_ad.payload 

        #print(f"{self.sw}: {self.lsa}") 
    def discover_node(self,rid,ip): 
        self.id_to_ip[rid] = ip 
        self.add_adj(rid) 
        self.lsa[rid] = [] 
        mask = 0xFFFFFFFF 
        if (ip,mask) not in self.routes.keys(): 
            self.routes[(ip,mask)] = ip 
            subnet = str(ip_network(int(ip_address(ip)) & mask).network_address) 
            self.addRoute(ip,subnet,mask) 

    def drop_node(self,rid): 
        self.del_adj(rid) 
        del self.seq_num[rid] 
        del self.lsa[rid] 
        del self.id_to_ip[rid] 

    def add_adj(self,rid): 
        if rid not in self.adj.keys(): 
            self.adj[rid] = [] 
        if rid not in self.adj[self.router_id]: 
            self.adj[self.router_id].append(rid) 
        if self.router_id not in self.adj[rid]: 
            self.adj[rid].append(self.router_id)
    def del_adj(self,rid): 
        for i in self.adj[rid]: 
            if i in self.adj.keys():
                self.adj[i].remove(rid) 
        del self.adj[rid] 

    def addRoute(self,ip,subnet,mask):
        priority = 1 if mask == 0xFFFFFF00 else 2
       # print(f"{self.sw}: {subnet},{mask} --> {ip}") 
        self.sw.insertTableEntry(
            table_name="MyIngress.fwd_l3",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_dst_ip",
            action_params={"next_hop":ip},
            priority = priority,
        )
    def delRoute(self,ip,subnet,mask): 
        priority = 1 if mask == 0xFFFFFF00 else 2
        print(f"del {self.sw}: {subnet},{mask} --> {ip}") 
        self.sw.removeTableEntry(
            table_name="MyIngress.fwd_l3",
            match_fields={"hdr.ipv4.dstAddr": [subnet,mask]},
            action_name="MyIngress.set_dst_ip",
            action_params={"next_hop":ip},
            priority = priority,
        )
        self.subnet_masks = subnet_masks #These are the subnets that I own  
        for s in self.subnet_masks: 
            if ip_address(ip) in ip_network(s): 
                self.routes[(ip,0xFFFFFFFF)] = ip 
                self.addRoute(ip,ip,0xFFFFFFFF)
        q = self.adj 
    def next_hop(self,subnet,mask): 
        def bfs_shortest_path(): 
            visited = set()
            q = [(self.router_id,[self.router_id])] 
            while q: 
                (current,path) = q.pop(0) 
                if current not in visited: 
                    visited.add(current) 
                    if (subnet,mask) in self.lsa[current]: 
                        return path 
                    for neighbor in self.adj[current]: 
                        if neighbor not in visited: 
                            q.append((neighbor, path + [neighbor])) 
        return bfs_shortest_path()

class P4Controller(Thread):
    def __init__(self,sw,ips,macs,subnets,intfs_mappings,router_id,area_id,lsuint=10,start_wait=0.3):
        super(P4Controller, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.host_seq = 0 
        #Data-plane tables 
        self.port_for_mac = {} #MAC --> PORT 
        self.arp = {} # IP --> MAC 
        subnet_masks = [] 
        for s in subnets: 
            net = ip_network(s) 
            subnet_masks.append((str(net.network_address),str(net.netmask))) 
        self.routes = RouteTopology(sw,router_id,area_id,subnet_masks,ips) 
        self.stop_event = Event()
        #Control-plane datastructures
        self.macs = macs 
        self.ips = ips
        self.intfs_mappings = intfs_mappings #Subnet --> (mac,IP) 
        self.subnets = subnets
        print(str(self.sw) + f" IP: {self.ips} \n Sub: {self.subnets}") 
        self.pktcache = {}  #IP Req --> Packet 
        #OSPF Router Vars
        self.router_id = router_id 
        self.area_id = area_id 
        self.lsuint = lsuint #LinkState floods 
        self.ospf_intfs = [] 
        #OSPF interface variables --> for each interface mapping 
        for i,(k,v) in enumerate(self.intfs_mappings.items()): 
            intfs = OSPF_intfs(v[1],k,HELLO_INT,self.router_id, self.area_id) 
            self.ospf_intfs.append(intfs) 
            self.ospf_hello_cb(HELLO_INT,intfs,i) 

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
        threading.Timer(interval,self.ospf_hello_cb,args =[interval, interface, interface_index]).start() 
        src_mac = self.macs[interface_index] 
        pkt = interface.build_packet(src_mac) 
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
            if src_ip not in self.pktcache: #If the pkt has been popped already 
                if src_ip not in self.arp.keys(): 
                    print(f"Something went wrong {self.arp}") 
                return 
            send_packet = self.pktcache[src_ip] #the original request src_ip 
            del self.pktcache[src_ip] 
            send_packet[Ether].dst = pkt[Ether].dst #This gets moved the source by the dataplane  
        self.send(send_packet)

    def handleArpRequest(self, pkt):
        dst_ip = pkt[ARP].pdst 
        src_ip = pkt[ARP].psrc 
        if src_ip in self.ips: 
            return 
        if src_ip not in self.arp.keys(): 
            self.addArpEntry(src_ip,pkt[ARP].hwsrc) 
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        if dst_ip in self.ips: 
            self.req_to_reply(pkt) 
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
        self.pktcache[ip] = pkt 
        #arp_request.show2() 
        self.send(arp_request)

    def mask(self,addr): 
        first_three_chunks = ".".join(addr.split(".")[:3])
        first_three_chunks += ".0" 
        return first_three_chunks 

    def handleIPNetwork(self,pkt): 
        #should only get forwarded up if ARP Request is missing 
        dst_ip = pkt[IP].dst 
        self.send_ARP_Req(pkt,dst_ip) 

    def handleIP(self,pkt): 
        #Check which subnet the dst address is in 
        srcPort = pkt[CPUMetadata].srcPort 
        dstIP = pkt[IP].dst  
        self.handleIPNetwork(pkt) 

    def pwospf_drop(self,pkt): 
        #Drop packets not in the right area and that are also not ourselves (this should never happen tho) 
        return pkt[Pwospf].area_id != self.area_id or pkt[Pwospf].router_id == self.router_id 

    def pwospf_lsu_flood(self): 
        neighbor_routers = self.routes.adj[self.router_id] 
        #TODO: LSU_ads here needs to be the entire table not just your own
        lsu_ads = [] 
        for rid in self.routes.lsa: 
            for v in self.routes.lsa[rid]: 
                lsu_ads.append(v) 
        lsu_ads = self.routes.lsa[self.router_id] 
        lsu_ads_pkt = [LinkStateAdvertisement(subnet = s, mask = m, router_id = self.router_id) for s,m in lsu_ads] 
        for n in neighbor_routers: 
            src_ip = None
            dst_ip = self.routes.id_to_ip[n] 
            for k,v in self.intfs_mappings.items(): 
                if ip_address(dst_ip) in ip_network(k): 
                    src_ip = v[1] 
                    break
            l2 = Ether() 
            l2_cpumetadata = CPUMetadata(origEtherType=0x0800, srcPort = 1)
            l3 = IP(src = src_ip,dst = dst_ip,proto=89) 
            l3_pwospf_flood = Pwospf(type=TYPE_LSU,router_id = self.router_id, area_id = self.area_id, seq = self.host_seq, ttl = TTL_DEFAULT,num_ads = len(lsu_ads_pkt), advertisements = lsu_ads_pkt)
            lsu_pkt = l2 / l2_cpumetadata / l3 / l3_pwospf_flood 
            if dst_ip not in self.arp.keys(): 
                self.send_ARP_Req(lsu_pkt,dst_ip) 
            else: 
                self.send(lsu_pkt) 
        self.host_seq += 1

    def handlePwospf_lsu(self,pkt): 
        self.routes.lsu_update(pkt) 


    def handlePwospf_hello(self,pkt): 
        if not self.pwospf_drop(pkt): 
            incoming_ip = pkt[IP].src #Find the equivalent subnet 
            rid = pkt[Pwospf].router_id
            for intfs in self.ospf_intfs: 
                if ip_address(incoming_ip) in ip_network(intfs.subnet): 
                    intfs.update_status(rid,incoming_ip) 
                if intfs.lsu_needed(): 
                    self.routes.discover_node(rid,incoming_ip) #When we discover a node, if its not in our route table add a direct route  
                    self.pwospf_lsu_flood() 
        else: 
            print("PWOSPF packet dropped") 

        
    def handlePwospf(self,pkt): 
        if pkt[Pwospf].type == TYPE_HELLO: 
            self.handlePwospf_hello(pkt) 
        elif pkt[Pwospf].type == TYPE_LSU: 
            self.handlePwospf_lsu(pkt) 
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
           # print("PWOSPF on" + str(self.sw))
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
