#include "dpi/flow_table.hpp"
#include "dpi/parser.hpp"
#include <iostream>
#include <cassert>
#include <vector>

void test_bidirectional_flow_matching() {
    std::cout << "[Test] Running bidirectional 5-tuple flow matching test..." << std::endl;
    dpi::FlowTable table(1024, 8);

    // Packet 1: Client -> Server
    std::vector<uint8_t> pkt1_bytes = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 50,
        1, 1, 1, 1,
        0xc3, 0x50, 0x01, 0xbb, // Src 50000, Dst 443
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00 // SYN
    };

    // Packet 2: Server -> Client
    std::vector<uint8_t> pkt2_bytes = {
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        1, 1, 1, 1,
        192, 168, 1, 50,
        0x01, 0xbb, 0xc3, 0x50, // Src 443, Dst 50000
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x50, 0x12, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00 // SYN-ACK
    };

    dpi::ParsedPacket p1, p2;
    bool ok1 = dpi::PacketParser::parse(pkt1_bytes, 1000, p1);
    bool ok2 = dpi::PacketParser::parse(pkt2_bytes, 2000, p2);
    if (!ok1 || !ok2) {
        std::cerr << "Failed to parse test packets!" << std::endl;
        std::abort();
    }

    dpi::FlowDirection dir1, dir2;
    auto rec1 = table.process_packet(p1, dir1);
    auto rec2 = table.process_packet(p2, dir2);

    if (!rec1 || !rec2 || rec1 != rec2) {
        std::cerr << "Flow table matching failed!" << std::endl;
        std::abort();
    }
    if (dir1 == dir2) {
        std::cerr << "Expected opposite directions!" << std::endl;
        std::abort();
    }

    if (rec1->fwd_packets.load() != 1 || rec1->rev_packets.load() != 1) {
        std::cerr << "Packet counter mismatch!" << std::endl;
        std::abort();
    }
    if (rec1->tcp_state.load() != dpi::TcpState::SYN_RECEIVED) {
        std::cerr << "TCP state mismatch!" << std::endl;
        std::abort();
    }

    std::cout << "  -> Passed. Flow record normalized: " << rec1->key.to_string() << std::endl;
}

void test_flow_eviction() {
    std::cout << "[Test] Running flow timeout eviction test..." << std::endl;
    dpi::FlowTable table(1024, 8);

    std::vector<uint8_t> udp_pkt = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        10, 0, 0, 1, 10, 0, 0, 2,
        0x10, 0x00, 0x20, 0x00, // Src 4096, Dst 8192
        0x00, 0x08, 0x00, 0x00
    };

    dpi::ParsedPacket p;
    bool ok = dpi::PacketParser::parse(udp_pkt, 10'000'000'000ULL, p);
    if (!ok) {
        std::cerr << "UDP packet parse failed!" << std::endl;
        std::abort();
    }

    dpi::FlowDirection dir;
    table.process_packet(p, dir);
    if (table.active_flows() != 1) {
        std::cerr << "Expected 1 active flow!" << std::endl;
        std::abort();
    }

    // Evict at 20s (elapsed 10s < 30s timeout) -> should not evict
    size_t evicted = table.evict_expired(20'000'000'000ULL, 300ULL * 1'000'000'000ULL, 30ULL * 1'000'000'000ULL);
    if (evicted != 0 || table.active_flows() != 1) {
        std::cerr << "Premature eviction!" << std::endl;
        std::abort();
    }

    // Evict at 50s (elapsed 40s > 30s timeout) -> should evict
    evicted = table.evict_expired(50'000'000'000ULL, 300ULL * 1'000'000'000ULL, 30ULL * 1'000'000'000ULL);
    if (evicted != 1 || table.active_flows() != 0) {
        std::cerr << "Eviction failed!" << std::endl;
        std::abort();
    }

    std::cout << "  -> Passed." << std::endl;
}

int main() {
    test_bidirectional_flow_matching();
    test_flow_eviction();
    std::cout << "[All Flow Table Tests Passed Cleanly]" << std::endl;
    return 0;
}
