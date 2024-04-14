from p4app import P4Mininet

from controller import P4Controller
from my_topo import SingleSwitchTopo
from mininet.cli import CLI 
import time 

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SingleSwitchTopo(N)
net = P4Mininet(program="l2switch.p4", topo=topo, auto_arp=False)
h2 = net.get("h2") 
h3 = net.get("h3") 
h5 = net.get("h5") 
h6 = net.get("h6") 
h8 = net.get("h8") 
h9 = net.get("h9") 
h2.cmd("route add default gw 10.0.0.4")  
h3.cmd("route add default gw 10.0.0.4")  
h5.cmd("route add default gw 10.0.1.4")  
h6.cmd("route add default gw 10.0.1.4")  
h8.cmd("route add default gw 10.0.2.4")  
h9.cmd("route add default gw 10.0.2.4")  
#for h,g in zip(topo.hosts(),topo.default_gw): 
#    host = net.get(h)
net.start()

subnets = {} 
bcast_mgid = 1
switch_names = ["s1","s2","s3"] 
switches = [] 
for s_num,s in enumerate(switch_names): 
    subnet = "10.0.%d"%s_num 
    sw = net.get(s) 
    sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 3))
    sw.insertTableEntry(
        table_name="MyIngress.fwd_l2",
        match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
        action_name="MyIngress.set_mgid",
        action_params={"mgid": bcast_mgid},
    )
    #Also add in all the entries for interface MAC addresses 
    for i in sw.intfs.values(): 
        mac_addr = str(sw.MAC(i))  
        if mac_addr != "None": 
            sw.insertTableEntry(
                table_name="MyIngress.fwd_l2",
                match_fields={"hdr.ethernet.dstAddr": [mac_addr]},
                action_name="MyIngress.send_to_cpu",
                action_params={},
            )
    switches.append(sw) 

s1 = net.get("s1") 
s2 = net.get("s2") 
s3 = net.get("s3") 

#cpu1_ips = ["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.3.0", "10.0.3.1"] 
#cpu2_ips = ["10.0.1.4","10.0.1.5", "10.0.1.6", "10.0.3.2", "10.0.3.3"] 
#cpu3_ips = ["10.0.2.4", "10.0.2.5", "10.0.2.6", "10.0.3.4", "10.0.3.5"] 
cpu1_ips = ["10.0.0.4","10.0.3.0"]
cpu2_ips = ["10.0.1.4", "10.0.3.1"] 
cpu3_ips = ["10.0.2.4", "10.0.3.2"] 
cpu1_macs = ["00:00:00:00:00:10","00:00:00:00:00:11"] 
cpu2_macs = ["00:00:00:00:00:20","00:00:00:00:00:21"] 
cpu3_macs = ["00:00:00:00:00:30","00:00:00:00:00:31"] 
cpu1_subnets = ["10.0.0.0/24", "10.0.3.0/24"] 
cpu2_subnets = ["10.0.1.0/24", "10.0.3.0/24"] 
cpu3_subnets = ["10.0.2.0/24", "10.0.3.0/24"] 
cpu1_intfs_mappings = {cpu1_subnets[0]:(cpu1_macs[0],cpu1_ips[0]), cpu1_subnets[1]: (cpu1_macs[1], cpu1_ips[1])} 
cpu2_intfs_mappings = {cpu2_subnets[0]:(cpu2_macs[0],cpu2_ips[0]), cpu2_subnets[1]: (cpu2_macs[1], cpu2_ips[1])} 
cpu3_intfs_mappings = {cpu3_subnets[0]:(cpu3_macs[0],cpu3_ips[0]), cpu3_subnets[1]: (cpu3_macs[1], cpu3_ips[1])} 
#Initialize them individually 
cpu1 = P4Controller(s1,cpu1_ips, cpu1_macs,cpu1_subnets,cpu1_intfs_mappings) 
cpu2 = P4Controller(s2,cpu2_ips, cpu2_macs, cpu2_subnets, cpu2_intfs_mappings)  
cpu3 = P4Controller(s3,cpu3_ips, cpu3_macs, cpu3_subnets, cpu3_intfs_mappings) 


cpu1.route_table["10.0.2.2"] = "10.0.3.2" 
cpu3.route_table["10.0.2.2"] = "10.0.2.2" 
cpu3.route_table["10.0.0.2"] = "10.0.3.0" 
cpu1.route_table["10.0.0.2"] = "10.0.0.2" 
mask1 = 0xFFFFFF00 
mask2 = 0xFFFFFFFF
s1.insertTableEntry(
    table_name="MyIngress.fwd_l3",
    match_fields={"hdr.ipv4.dstAddr": ["10.0.2.0",mask1]},
    action_name="MyIngress.set_dst_ip",
    action_params={"next_hop":"10.0.3.2"},
    priority = 1,
)
s1.insertTableEntry(
    table_name="MyIngress.fwd_l3",
    match_fields={"hdr.ipv4.dstAddr": ["10.0.0.2",mask2]},
    action_name="MyIngress.set_dst_ip",
    action_params={"next_hop":"10.0.0.2"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.fwd_l3",
    match_fields={"hdr.ipv4.dstAddr": ["10.0.2.2",mask2]},
    action_name="MyIngress.set_dst_ip",
    action_params={"next_hop":"10.0.2.2"},
    priority = 1,
)

s3.insertTableEntry(
    table_name="MyIngress.fwd_l3",
    match_fields={"hdr.ipv4.dstAddr": ["10.0.0.0",mask1]},
    action_name="MyIngress.set_dst_ip",
    action_params={"next_hop":"10.0.3.0"},
    priority = 1,
)
#s3.insertTableEntry(
#    table_name="MyIngress.fwd_l3",
#    match_fields={"hdr.ipv4.dstAddr": ["10.0.0.2",mask2]},
#    action_name="MyIngress.send_to_cpu",
#    action_params={},
#    priority = 2,
#)


#cpu1.route_table["10.0.1.2"] = "10.0.1.50"
#cpu1.route_table["10.0.2.2"] = "10.0.2.50"
#cpu1.route_table["10.0.1.3"] = "10.0.1.50"
#cpu1.route_table["10.0.2.3"] = "10.0.2.50"
#cpu1.route_table["10.0.0.2"] = "10.0.0.2"
#cpu1.route_table["10.0.0.3"] = "10.0.0.3"
#
#cpu2.route_table["10.0.0.3"] = "10.0.0.50"
#cpu2.route_table["10.0.2.3"] = "10.0.2.50"
#cpu2.route_table["10.0.0.2"] = "10.0.0.50"
#cpu2.route_table["10.0.2.2"] = "10.0.2.50"
#cpu2.route_table["10.0.1.2"] = "10.0.1.2"
#cpu2.route_table["10.0.1.3"] = "10.0.1.3"
#
#
#cpu3.route_table["10.0.2.2"] = "10.0.2.2"
#cpu3.route_table["10.0.2.3"] = "10.0.2.3"
#cpu3.route_table["10.0.0.2"] = "10.0.0.50"
#cpu3.route_table["10.0.1.2"] = "10.0.1.50"
#cpu3.route_table["10.0.0.3"] = "10.0.0.50"
#cpu3.route_table["10.0.1.3"] = "10.0.1.50"

cpu1.start() 
#cpu2.start()
cpu3.start()

h2 = net.get("h2") 
#print(h2.cmd("ping -c1 10.0.2.2"))  
CLI(net) 
net.stop()
