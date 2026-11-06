#include "dpi/parser.hpp"
#include <iostream>
#include <cassert>
#include <vector>

void test_ethernet_ipv4_tcp() {
    std::cout << "[Test] Running Ethernet + IPv4 + TCP parser test..." << std::endl;

    // Synthetic packet: Ethernet (14) + IPv4 (20) + TCP (20) + 4 bytes payload
    std::vector<uint8_t> raw = {
        // Ethernet: Dst MAC (00:11:22:33:44:55), Src MAC (66:77:88:99:aa:bb), EtherType (0x0800 IPv4)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,

        // IPv4: Ver/IHL (0x45 = IPv4, 20B hdr), DSCP 0, Total Len (44B = 0x002c), ID 0x1234, Flags/Frag 0x4000 (DF), TTL 64, Proto 6 (TCP), Cksum 0, Src (192.168.1.10), Dst (10.0.0.1)
        0x45, 0x00, 0x00, 0x2c,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 10,
        10, 0, 0, 1,

        // TCP: Src Port 54321 (0xd431), Dst Port 443 (0x01bb), Seq 0x00000001, Ack 0x00000000, DataOff 0x50 (20B), Flags 0x02 (SYN), Win 64240 (0xfaf0), Cksum 0, Urg 0
        0xd4, 0x31, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xfa, 0xf0,
        0x00, 0x00, 0x00, 0x00
    };

    dpi::ParsedPacket pkt;
    bool ok = dpi::PacketParser::parse(raw, 1000, pkt);
    if (!ok || !pkt.is_valid()) std::abort();
    assert(pkt.l3_proto == dpi::L3Protocol::IPV4);
    assert(pkt.ipv4 != nullptr);
    assert(pkt.ipv4->src_ip.to_string() == "192.168.1.10");
    assert(pkt.ipv4->dst_ip.to_string() == "10.0.0.1");

    assert(pkt.is_tcp());
    assert(pkt.tcp != nullptr);
    assert(pkt.src_port() == 54321);
    assert(pkt.dst_port() == 443);
    assert(pkt.tcp->syn());
    assert(!pkt.tcp->ack());

    std::cout << "  -> Passed." << std::endl;
}

void test_vlan_qinq() {
    std::cout << "[Test] Running 802.1ad QinQ double-tagged VLAN parser test..." << std::endl;

    // Ethernet (14) + Outer VLAN 802.1ad (4) + Inner VLAN 802.1Q (4) + IPv4 (20) + UDP (8)
    std::vector<uint8_t> raw = {
        // Ethernet: Dst, Src, EtherType 0x88a8 (QinQ)
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x01,
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x02,
        0x88, 0xa8,

        // Outer VLAN: TCI (VID = 100 -> 0x0064), Next EtherType 0x8100 (VLAN)
        0x00, 0x64, 0x81, 0x00,

        // Inner VLAN: TCI (VID = 200 -> 0x00c8), Next EtherType 0x0800 (IPv4)
        0x00, 0xc8, 0x08, 0x00,

        // IPv4 (Proto UDP = 17)
        0x45, 0x00, 0x00, 0x20,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        172, 16, 0, 1,
        172, 16, 0, 2,

        // UDP: Src 53 (DNS), Dst 12345, Len 8, Cksum 0
        0x00, 0x35, 0x30, 0x39,
        0x00, 0x08, 0x00, 0x00
    };

    dpi::ParsedPacket pkt;
    bool ok = dpi::PacketParser::parse(raw, 2000, pkt);
    if (!ok || !pkt.is_valid()) std::abort();
    assert(pkt.vlan != nullptr);
    assert(pkt.vlan->vlan_id() == 100);
    assert(pkt.inner_vlan != nullptr);
    assert(pkt.inner_vlan->vlan_id() == 200);

    assert(pkt.l3_proto == dpi::L3Protocol::IPV4);
    assert(pkt.is_udp());
    assert(pkt.src_port() == 53);
    assert(pkt.dst_port() == 12345);

    std::cout << "  -> Passed." << std::endl;
}

void test_truncated_packet() {
    std::cout << "[Test] Running malformed/truncated packet resilience test..." << std::endl;

    std::vector<uint8_t> broken = { 0x00, 0x11, 0x22 }; // Only 3 bytes (less than Ethernet)
    dpi::ParsedPacket pkt;
    assert(!dpi::PacketParser::parse(broken, 3000, pkt));

    // Valid ethernet but truncated IPv4
    std::vector<uint8_t> broken_ip = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00 // truncated IP
    };
    assert(!dpi::PacketParser::parse(broken_ip, 3001, pkt));

    std::cout << "  -> Passed." << std::endl;
}

void test_raw_ip_packet() {
    std::cout << "[Test] Running Raw IP (WinDivert/No-Ethernet) parser test..." << std::endl;

    // Raw IPv4 (20B) + TCP (20B) + 5 bytes payload
    std::vector<uint8_t> raw_ipv4 = {
        // IPv4: Ver/IHL (0x45), DSCP 0, Total Len (45B = 0x002d), ID 0x1234, Flags/Frag 0x4000, TTL 64, Proto 6 (TCP), Cksum 0, Src (192.168.1.50), Dst (104.154.127.110)
        0x45, 0x00, 0x00, 0x2d,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 50,
        104, 154, 127, 110,

        // TCP: Src Port 50000 (0xc350), Dst Port 443 (0x01bb), Seq 1, Ack 0, DataOff 0x50, Flags 0x02 (SYN), Win 64240, Cksum 0, Urg 0
        0xc3, 0x50, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xfa, 0xf0,
        0x00, 0x00, 0x00, 0x00,

        // 5 bytes payload
        'H', 'E', 'L', 'L', 'O'
    };

    dpi::ParsedPacket pkt;
    bool ok = dpi::PacketParser::parse(raw_ipv4, 4000, pkt);
    if (!ok || !pkt.is_valid()) std::abort();
    assert(pkt.eth == nullptr); // No Ethernet header
    assert(pkt.l3_offset == 0);
    assert(pkt.l3_proto == dpi::L3Protocol::IPV4);
    assert(pkt.ipv4 != nullptr);
    assert(pkt.ipv4->src_ip.to_string() == "192.168.1.50");
    assert(pkt.ipv4->dst_ip.to_string() == "104.154.127.110");

    assert(pkt.is_tcp());
    assert(pkt.src_port() == 50000);
    assert(pkt.dst_port() == 443);
    assert(pkt.payload.size() == 5);
    assert(pkt.payload[0] == 'H');

    // Raw IPv6 (40B) + UDP (8B)
    std::vector<uint8_t> raw_ipv6 = {
        // IPv6: Ver 6, TC 0, Flow 0, PayloadLen 8, NextHdr 17 (UDP), HopLimit 64
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x08, 0x11, 0x40,
        // Src IP (2001:db8::1)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dst IP (2001:db8::2)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        // UDP: Src 53, Dst 54321, Len 8, Cksum 0
        0x00, 0x35, 0xd4, 0x31,
        0x00, 0x08, 0x00, 0x00
    };

    dpi::ParsedPacket pkt6;
    bool ok6 = dpi::PacketParser::parse(raw_ipv6, 5000, pkt6);
    if (!ok6 || !pkt6.is_valid()) std::abort();
    assert(pkt6.eth == nullptr);
    assert(pkt6.l3_offset == 0);
    assert(pkt6.l3_proto == dpi::L3Protocol::IPV6);
    assert(pkt6.is_udp());
    assert(pkt6.src_port() == 53);
    assert(pkt6.dst_port() == 54321);

    std::cout << "  -> Passed." << std::endl;
}

int main() {
    test_ethernet_ipv4_tcp();
    test_vlan_qinq();
    test_truncated_packet();
    test_raw_ip_packet();
    std::cout << "[All Parser Tests Passed Cleanly]" << std::endl;
    return 0;
}
