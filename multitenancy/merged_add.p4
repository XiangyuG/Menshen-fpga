#include <core.p4>
#include <fpga.p4>

header ethernet_t {
    bit<48> eth_dst_addr;
    bit<48> eth_src_addr;
    bit<16> eth_ethertype;
}

header vlan_t {
    bit<16> vlan_id;
    bit<16> vlan_ethertype;
}

header ipv4_t {
    bit<32> ip_src_addr;
    bit<32> ip_dst_addr;
    bit<32> pkt_1;
    bit<32> pkt_2;
    bit<32> pkt_3;
}

header udp_t {
    bit<16> udp_src_port;
    bit<16> udp_dst_port;
    bit<16> hdr_length;
    bit<16> udp_checksum;
}

struct headers {
    ethernet_t ethernet;
    vlan_t     vlan;
    ipv4_t     ipv4;
    udp_t      udp;
}

struct metadata {
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition parse_vlan;
    }
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition parse_ip;
    }
    state parse_ip {
        packet.extract(hdr.ipv4);
        transition parse_udp;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action fwd() {
        hdr.ipv4.pkt_1 = hdr.ipv4.pkt_1 + 1;
    }
    table lb {
        key = {
            hdr.ipv4.pkt_2: exact;
        }
        actions = {
            fwd();
            @defaultonly NoAction();
        }
        const entries = {
                        13 : fwd();
        }

        default_action = NoAction();
    }
    action fwd_on_ip_dst() {
        standard_metadata.port = (bit<32>)32w4;
    }
    action fwd_on_ip_multicast() {
        standard_metadata.port = (bit<32>)32w85;
    }
    table sys_fwd_on_ip_dst {
        key = {
            hdr.ipv4.ip_dst_addr: exact;
        }
        actions = {
            fwd_on_ip_dst();
            fwd_on_ip_multicast();
        }
        const default_action = fwd_on_ip_dst();
        const entries = {
                        32w9 : fwd_on_ip_dst();
                        32w10 : fwd_on_ip_multicast();
        }

    }
    apply {
        lb.apply();
        // sys_fwd_on_ip_dst.apply();
    }
}

FpgaSwitch(MyParser(), MyIngress()) main;

