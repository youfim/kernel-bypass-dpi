#include "dpi/parser.hpp"
#include <iostream>
#include <cassert>
#include <vector>

void test_ethernet_ipv4_tcp() {
    std::cout << "[Test] Running Ethernet + IPv4 + TCP parser test..." << std::endl;

    std::vector<uint8_t> raw = {

        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,

        0x45, 0x00, 0x00, 0x2c,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 10,
        10, 0, 0, 1,

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

    std::vector<uint8_t> raw = {

        0x00, 0x50, 0x56, 0xc0, 0x00, 0x01,
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x02,
        0x88, 0xa8,

        0x00, 0x64, 0x81, 0x00,

        0x00, 0xc8, 0x08, 0x00,

        0x45, 0x00, 0x00, 0x20,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        172, 16, 0, 1,
        172, 16, 0, 2,

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

    std::vector<uint8_t> broken = { 0x00, 0x11, 0x22 };
    dpi::ParsedPacket pkt;
    assert(!dpi::PacketParser::parse(broken, 3000, pkt));

    std::vector<uint8_t> broken_ip = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00
    };
    assert(!dpi::PacketParser::parse(broken_ip, 3001, pkt));

    std::cout << "  -> Passed." << std::endl;
}

void test_raw_ip_packet() {
    std::cout << "[Test] Running Raw IP (WinDivert/No-Ethernet) parser test..." << std::endl;

    std::vector<uint8_t> raw_ipv4 = {

        0x45, 0x00, 0x00, 0x2d,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 50,
        104, 154, 127, 110,

        0xc3, 0x50, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xfa, 0xf0,
        0x00, 0x00, 0x00, 0x00,

        'H', 'E', 'L', 'L', 'O'
    };

    dpi::ParsedPacket pkt;
    bool ok = dpi::PacketParser::parse(raw_ipv4, 4000, pkt);
    if (!ok || !pkt.is_valid()) std::abort();
    assert(pkt.eth == nullptr);
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

    std::vector<uint8_t> raw_ipv6 = {

        0x60, 0x00, 0x00, 0x00,
        0x00, 0x08, 0x11, 0x40,

        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,

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
