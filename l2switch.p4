/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4           = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<8> PWOSPF_VERSION = 0x2; 
const bit<8> PWOSPF_HELLO = 0x1; 
const bit<8> PWOSPF_LSU = 0X4; 
const bit<8> PWOSPF_PROTO = 0d89; 

const bit<32> ALLSPFRouters = 0xe0000005; 


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header pwospf_head_t{
    bit<8> version; 
    bit<8> type; 
    bit<16> packet_len; 
    bit<32> router_id; 
    bit<32> area_id;  
    bit<16> checksum;
    bit<16> autype; 
    bit<64> auth;  
}

header pwospf_hello_t{
    bit<32> mask; 
    bit<16> helloint; 
    bit<16> padding; 
}

header pwospf_lsu_head_t{
    bit<16> seq; 
    bit<16> ttl; 
    bit<32> num_ads; 
}


header pwospf_lsu_ads_t{
    varbit<960> ads; 
}


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t{
    bit<8> type; 
    bit<8> code; 
    bit<16> checksum; 
    bit<32> data; 
}


struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    pwospf_head_t     pwospf_head; 
    pwospf_lsu_head_t  pwospf_lsu_head; 
    pwospf_lsu_ads_t   pwospf_lsu_ads; 
    pwospf_hello_t    pwospf_hello; 
    ipv4_t            ipv4; 
    icmp_t            icmp; 
}


error {PWOSPF_Invalid} 
struct metadata { }

parser MyParser(packet_in packet,
        out headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
        TYPE_IPV4: parse_ip; 
        TYPE_ARP: parse_arp;
        TYPE_CPU_METADATA: parse_cpu_metadata;
                    default: accept;
                }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
        TYPE_ARP: parse_arp;
        TYPE_IPV4: parse_ip; 
        default: accept;
                }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ip{
        packet.extract(hdr.ipv4); 
        transition select(hdr.ipv4.protocol){
            PWOSPF_PROTO: parse_pwospf_header; 
            default: accept; 
        }
    }   
    
    state parse_pwospf_header{
        packet.extract(hdr.pwospf_head); 
        transition select(hdr.pwospf_head.type){
            PWOSPF_HELLO: parse_pwospf_hello; 
            PWOSPF_LSU: parse_pwospf_lsu;  
            default: accept;
        }   
    }


   state parse_pwospf_hello{
        packet.extract(hdr.pwospf_hello); 
        transition accept; 
   }
   

   state parse_pwospf_lsu{
        packet.extract(hdr.pwospf_lsu_head); 
        verify(hdr.pwospf_lsu_head.num_ads >= 1, error.PWOSPF_Invalid); 
        transition parse_pwospf_ads; 
   }   

   state parse_pwospf_ads{
    packet.extract(hdr.pwospf_lsu_ads,(bit<32>)(hdr.pwospf_lsu_head.num_ads * 32));
    transition accept; 
   }   


}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {

        verify_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);

 }
}

control MyIngress(inout headers hdr,
        inout metadata meta,
        inout standard_metadata_t standard_metadata) {
    ip4Addr_t global_next_hop; 
    register<bit<32>>(size = 1) ip_counter;
    register<bit<32>>(size = 1) arp_counter;
    register<bit<32>>(size = 1) cpu_counter;


    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap(){
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ip_forward(macAddr_t dstAddr, port_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_dst_ip(ip4Addr_t next_hop){
        global_next_hop = next_hop;
    }

    action set_mac(macAddr_t dst_mac) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac; 
    }
    table fwd_l3{
        key = {
            hdr.ipv4.dstAddr: ternary; 
        }
        actions = {
            set_dst_ip; 
            send_to_cpu;
            drop; 
        }
        size = 1024; 
        default_action = drop; 
    }

    table arp{
        key = {
            global_next_hop: ternary; 
        }
        actions = {
            send_to_cpu;  
            set_mac;  
            NoAction; 
        }
        size = 1024;
        default_action = send_to_cpu; 
    }    
    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
            send_to_cpu; 
        }
        size = 1024;
        default_action = drop;
    }


    apply {
        if (standard_metadata.ingress_port == CPU_PORT){
            cpu_meta_decap();
            bit<32> temp;  
            cpu_counter.read(temp,0); 
            log_msg("Cpu Counter {}",{temp}); 
        }
        if(hdr.pwospf_hello.isValid()){
            if(standard_metadata.ingress_port == CPU_PORT){
                log_msg("send hello");  
                fwd_l2.apply();  
            }
            else{
                log_msg("got hello");  
                bit<32> temp;  
                cpu_counter.read(temp,0); 
                cpu_counter.write(0, temp + 1); 
                send_to_cpu(); 
            }
        }   
        else if(hdr.pwospf_lsu_head.isValid() && standard_metadata.ingress_port != CPU_PORT){
            //Always send LSU up to the CPU. If the CPU sends it back that just means 
            log_msg("got lsu");  
            bit<32> temp;  
            cpu_counter.read(temp,0); 
            cpu_counter.write(0, temp + 1); 
            send_to_cpu(); 
        }
        else if(hdr.ipv4.isValid()){
            bit<32> ip_temp;  
            ip_counter.read(ip_temp,0); 
            ip_counter.write(0, ip_temp + 1); 
            log_msg("ip detected"); 
            //First check to see if its a valid subnet. If not valid drop, otherwise, replace mac addresses based off of next hop IP 
            if(fwd_l3.apply().hit){
                if(arp.apply().hit){
                    log_msg("ether on IP");
                    //Decrement TTL 
                    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                    fwd_l2.apply(); 
                }
                else{
                    bit<32> temp;  
                    cpu_counter.read(temp,0); 
                    cpu_counter.write(0, temp + 1); 
                }
            }
        }
        else if(hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT){
            bit<32> temp;  
            cpu_counter.read(temp,0); 
            cpu_counter.write(0, temp + 1); 
            arp_counter.read(temp,0); 
            arp_counter.write(0, temp + 1); 
            log_msg("arp detected");  
            send_to_cpu(); 
        }
        else if (hdr.ethernet.isValid()) {
            if(hdr.arp.isValid() && standard_metadata.ingress_port == CPU_PORT){
                bit<32> temp; 
                arp_counter.read(temp,0); 
                arp_counter.write(0, temp + 1); 
                log_msg("Outgoing ARP"); 
                }
            fwd_l2.apply();
        }

        if(hdr.ipv4.isValid()){
            bit<32> ip_temp;  
            ip_counter.read(ip_temp,0); 
            log_msg("IP Counter {}",{ip_temp}); 
        }
        if(hdr.arp.isValid()){
                bit<32> temp; 
                arp_counter.read(temp,0); 
            log_msg("Arp Counter {}",{temp}); 
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);

 }




}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4); 
        packet.emit(hdr.pwospf_head); 
        packet.emit(hdr.pwospf_hello); 
        packet.emit(hdr.pwospf_lsu_head); 
        packet.emit(hdr.pwospf_lsu_ads); 
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
