#include "dpi/capture.hpp"
#include "dpi/parser.hpp"
#include "dpi/flow_table.hpp"
#include "dpi/process_resolver.hpp"
#include "dpi/process_filter.hpp"
#include "dpi/protocols/tls.hpp"
#include "dpi/protocols/dns.hpp"
#include "dpi/protocols/http.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <csignal>
#include <ctime>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace {

std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running.store(false);
}

std::string format_time(uint64_t ns) {
    auto secs = static_cast<time_t>(ns / 1'000'000'000ULL);
    uint32_t millis = static_cast<uint32_t>((ns % 1'000'000'000ULL) / 1'000'000ULL);

    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &secs);
#else
    localtime_r(&secs, &tm_buf);
#endif

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03u",
                  tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
    return buf;
}

void print_banner() {
    std::cout << "\033[1;36m"
              << "========================================================================================\n"
              << "   Kernel-Bypass DPI Streamer — Live Network & Application Request Monitor             \n"
              << "========================================================================================\033[0m\n";
    std::cout << std::left
              << "\033[1;37m"
              << std::setw(14) << "TIME"
              << std::setw(18) << "PROCESS [PID]"
              << std::setw(8)  << "PROTO"
              << std::setw(32) << "REMOTE TARGET"
              << std::setw(30) << "DOMAIN / SNI / QUERY"
              << "DETAILS"
              << "\033[0m\n"
              << "----------------------------------------------------------------------------------------\n";
}

} // namespace

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);

#if defined(_WIN32)
    // Enable ANSI virtual terminal processing on Windows console
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif

    dpi::ProcessFilter filter;
    std::string pcap_file;
    std::string custom_filter = "outbound && (tcp.DstPort == 80 || tcp.DstPort == 443 || udp.DstPort == 53)";

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--app" && i + 1 < argc) {
            filter.include_app(argv[++i]);
        } else if (arg == "--pid" && i + 1 < argc) {
            filter.include_pid(static_cast<uint32_t>(std::stoul(argv[++i])));
        } else if (arg == "--path" && i + 1 < argc) {
            filter.include_path_contains(argv[++i]);
        } else if (arg == "--exclude" && i + 1 < argc) {
            filter.exclude_app(argv[++i]);
        } else if (arg == "--pcap" && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (arg == "--filter" && i + 1 < argc) {
            custom_filter = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: dpi_monitor [options]\n"
                      << "  --app <name>       Filter traffic by executable name (e.g. chrome.exe, telegram.exe)\n"
                      << "  --pid <pid>        Filter traffic by Process ID\n"
                      << "  --path <substr>    Filter by substring in process path\n"
                      << "  --exclude <name>   Exclude process name\n"
                      << "  --filter <expr>    Custom WinDivert capture filter string\n"
                      << "  --pcap <file>      Replay from offline PCAP dump instead of live NIC\n";
            return 0;
        }
    }

    std::unique_ptr<dpi::ICaptureDevice> capture;
    if (!pcap_file.empty()) {
        std::cout << "[Monitor] Replaying offline PCAP dump: " << pcap_file << std::endl;
        capture = dpi::ICaptureDevice::create_pcap(pcap_file);
        if (!capture->open(pcap_file)) {
            std::cerr << "Failed to open PCAP file: " << pcap_file << std::endl;
            return 1;
        }
    } else {
#if defined(_WIN32)
        std::cout << "[Monitor] Opening WinDivert kernel filter: " << custom_filter << std::endl;
        capture = dpi::ICaptureDevice::create_windivert();
        if (!capture->open(custom_filter)) {
            std::cerr << "[Monitor] Failed to open WinDivert filter. Make sure to run as Administrator." << std::endl;
            return 1;
        }
#else
        capture = dpi::ICaptureDevice::create_afxdp();
        if (!capture->open("eth0")) {
            std::cerr << "[Monitor] Failed to open AF_XDP device." << std::endl;
            return 1;
        }
#endif
    }

    print_banner();

    dpi::FlowTable table(65536, 64);
    std::vector<dpi::PacketSlot> batch(64);

    while (g_running.load()) {
        size_t n = capture->receive_batch(batch);
        if (n == 0) {
            if (!pcap_file.empty()) {
                break; // Replay completed
            }
#if defined(_WIN32)
            Sleep(5);
#else
            usleep(5000);
#endif
            continue;
        }

        for (size_t i = 0; i < n; ++i) {
            const auto& slot = batch[i];
            dpi::ParsedPacket pkt;
            if (!dpi::PacketParser::parse(std::span<const uint8_t>(slot.data, slot.length), slot.timestamp_ns, pkt)) {
                continue;
            }

            dpi::FlowDirection dir;
            auto flow = table.process_packet(pkt, dir);
            if (!flow) continue;

            // Apply process filter
            if (filter.has_rules() && !filter.matches(flow->process)) {
                continue;
            }

            // Inspect L7 payload for TLS, DNS, HTTP
            if (!pkt.payload.empty()) {
                std::lock_guard<std::mutex> lock(flow->l7_mutex);

                std::string target_endpoint;
                if (pkt.l3_proto == dpi::L3Protocol::IPV4 && pkt.ipv4) {
                    target_endpoint = pkt.ipv4->dst_ip.to_string() + ":" + std::to_string(pkt.dst_port());
                } else if (pkt.l3_proto == dpi::L3Protocol::IPV6 && pkt.ipv6) {
                    target_endpoint = "[" + pkt.ipv6->dst_ip.to_string() + "]:" + std::to_string(pkt.dst_port());
                }

                std::string proc_str = flow->process.is_valid()
                    ? (flow->process.name + " [" + std::to_string(flow->process.pid) + "]")
                    : "Unknown";

                // 1. TLS ClientHello
                if (!flow->tls_meta.has_value() && pkt.is_tcp() && (pkt.dst_port() == 443 || pkt.src_port() == 443)) {
                    flow->tls_meta = dpi::protocols::parse_tls_client_hello(pkt.payload);
                    if (flow->tls_meta.has_value() && !flow->tls_meta->sni.empty()) {
                        std::cout << std::left
                                  << "\033[90m" << std::setw(14) << format_time(slot.timestamp_ns) << "\033[0m"
                                  << "\033[32m" << std::setw(18) << proc_str.substr(0, 17) << "\033[0m"
                                  << "\033[33m" << std::setw(8)  << "TLS" << "\033[0m"
                                  << std::setw(32) << target_endpoint
                                  << "\033[1;35m" << std::setw(30) << flow->tls_meta->sni.substr(0, 29) << "\033[0m"
                                  << "\033[90mJA3:" << flow->tls_meta->ja3_hash.substr(0, 10) << "...\033[0m\n";
                    }
                }

                // 2. DNS Query / Answer
                if (!flow->dns_meta.has_value() && pkt.is_udp() && (pkt.dst_port() == 53 || pkt.src_port() == 53)) {
                    auto dns = dpi::protocols::parse_dns_message(pkt.payload);
                    if (dns.has_value()) {
                        for (const auto& q : dns->questions) {
                            std::string ans_str;
                            if (!dns->answers.empty()) {
                                ans_str = "-> " + dns->answers[0].data;
                            }
                            std::cout << std::left
                                      << "\033[90m" << std::setw(14) << format_time(slot.timestamp_ns) << "\033[0m"
                                      << "\033[32m" << std::setw(18) << proc_str.substr(0, 17) << "\033[0m"
                                      << "\033[34m" << std::setw(8)  << "DNS" << "\033[0m"
                                      << std::setw(32) << target_endpoint
                                      << "\033[1;34m" << std::setw(30) << q.name.substr(0, 29) << "\033[0m"
                                      << "\033[36m" << ans_str << "\033[0m\n";
                        }
                        flow->dns_meta = std::move(dns);
                    }
                }

                // 3. HTTP Request
                if (flow->http_method.empty() && pkt.is_tcp()) {
                    auto req = dpi::protocols::parse_http_request(pkt.payload);
                    if (req.has_value()) {
                        flow->http_method = std::string(req->method_string());
                        flow->http_uri = std::string(req->uri);
                        flow->http_host = std::string(req->host);
                        flow->http_user_agent = std::string(req->user_agent);

                        std::cout << std::left
                                  << "\033[90m" << std::setw(14) << format_time(slot.timestamp_ns) << "\033[0m"
                                  << "\033[32m" << std::setw(18) << proc_str.substr(0, 17) << "\033[0m"
                                  << "\033[31m" << std::setw(8)  << "HTTP" << "\033[0m"
                                  << std::setw(32) << target_endpoint
                                  << "\033[1;33m" << std::setw(30) << flow->http_host.substr(0, 29) << "\033[0m"
                                  << flow->http_method << " " << flow->http_uri.substr(0, 40) << "\n";
                    }
                }
            }
        }
    }

    std::cout << "\n[Monitor] Stopping capture. Active tracked flows: " << table.active_flows() << std::endl;
    capture->close();
    return 0;
}
