from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)
        self.default_gw = [] 
        s1 = self.addSwitch("s1") 
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3") 
        switches = [s1,s2,s3] 
        for num,s in enumerate(switches):
            subnet = "10.0.%d"%num 
            for i in range(1,n+1): 
                host_num = 3*num + i  
                host_ip = subnet + ".%d/24"%i
                default_ip = (subnet + ".50")
                print("Default Gateway: " + default_ip) 
                print("Host: " + str(host_ip)) 
                print("Port: " + str(i)) 
                h = self.addHost(
                    "h%d" % host_num, ip=host_ip, mac="00:00:00:00:00:%02x" % host_num 
                )
                self.default_gw.append(default_ip) 
                self.addLink(h,s,port2=i)  
            print("\n") 

        self.addLink(s2,s1) 
        self.addLink(s2,s3) 
        self.addLink(s3,s1)
