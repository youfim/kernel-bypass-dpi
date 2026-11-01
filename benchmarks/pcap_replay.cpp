#include "dpi/parser.hpp"
#include "dpi/flow_table.hpp"
#include "dpi/ring_buffer.hpp"
#include "dpi/protocols/tls.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>

int main(int argc, char* argv[]) {
    size_t iterations = 5'000'000;
    if (argc > 1) {
        iterations = std::stoull(argv[1]);
    }

    std::cout << "==========================================================" << std::endl;
    std::cout << "  Kernel-Bypass DPI Engine — High-Throughput Replay Benchmark" << std::endl;
    std::cout << "  Iterations: " << iterations << " packets" << std::endl;
    std::cout << "==========================================================" << std::endl;

    // Pre-craft sample Ethernet II + IPv4 + TCP packet (64 bytes)
    std::vector<uint8_t> sample_packet = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x32, 0x10, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 100,
        1, 1, 1, 1,
        0xd4, 0x31, 0x01, 0xbb, // 54321 -> 443
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00,
        // 10 bytes payload
        0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00
    };

    dpi::FlowTable flow_table(65536, 64);
    dpi::ParsedPacket parsed{};

    uint64_t valid_packets = 0;
    uint64_t total_bytes = 0;

    auto start_time = std::chrono::steady_clock::now();

    for (size_t i = 0; i < iterations; ++i) {
        // Vary source port slightly to populate flow table
        uint16_t dynamic_port = static_cast<uint16_t>(1024 + (i & 0x3FFF));
        sample_packet[34] = static_cast<uint8_t>(dynamic_port >> 8);
        sample_packet[35] = static_cast<uint8_t>(dynamic_port & 0xFF);

        uint64_t fake_timestamp = static_cast<uint64_t>(i * 100);

        if (dpi::PacketParser::parse(sample_packet, fake_timestamp, parsed)) {
            dpi::FlowDirection dir;
            auto flow = flow_table.process_packet(parsed, dir);
            if (flow) {
                valid_packets++;
                total_bytes += sample_packet.size();
            }
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    double duration_sec = std::chrono::duration<double>(end_time - start_time).count();
    double mpps = (static_cast<double>(iterations) / duration_sec) / 1'000'000.0;
    double mbps = (static_cast<double>(total_bytes * 8) / duration_sec) / 1'000'000.0;
    double ns_per_pkt = (duration_sec * 1'000'000'000.0) / static_cast<double>(iterations);

    std::cout << "\nResults:" << std::endl;
    std::cout << "  Elapsed Time:     " << std::fixed << std::setprecision(4) << duration_sec << " s" << std::endl;
    std::cout << "  Throughput:       " << std::fixed << std::setprecision(2) << mpps << " Mpps" << std::endl;
    std::cout << "  Bandwidth Rate:   " << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::endl;
    std::cout << "  Latency:          " << std::fixed << std::setprecision(2) << ns_per_pkt << " ns / packet" << std::endl;
    std::cout << "  Active Flows:     " << flow_table.active_flows() << std::endl;
    std::cout << "==========================================================" << std::endl;

    return 0;
}
