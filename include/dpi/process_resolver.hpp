#pragma once

#include "protocols/endian.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <optional>
#include <algorithm>

namespace dpi {

struct ProcessInfo {
    uint32_t    pid{0};
    std::string name;       // e.g. "chrome.exe"
    std::string path;       // e.g. "C:\Program Files\Google\Chrome\Application\chrome.exe"

    [[nodiscard]] bool is_valid() const noexcept {
        return pid != 0 && !name.empty();
    }
};

class ProcessResolver {
public:
    static ProcessResolver& instance();

    // Resolves process for a given local socket endpoint (IPv4 / IPv6, local port, protocol TCP/UDP)
    [[nodiscard]] ProcessInfo resolve(uint16_t local_port, uint8_t protocol, bool is_ipv6 = false);

    // Explicit cache refresh
    void refresh_cache();

    // Resolves process name and full path from PID
    static ProcessInfo query_process_by_pid(uint32_t pid);

private:
    ProcessResolver();
    ~ProcessResolver() = default;

    ProcessResolver(const ProcessResolver&) = delete;
    ProcessResolver& operator=(const ProcessResolver&) = delete;

    void refresh_tables_windows();

    mutable std::shared_mutex mutex_;
    std::chrono::steady_clock::time_point last_refresh_;
    std::unordered_map<uint32_t, ProcessInfo> pid_cache_; // pid -> ProcessInfo

    // Endpoint maps: (port | (proto << 16)) -> pid
    std::unordered_map<uint32_t, uint32_t> endpoint_to_pid_tcp_;
    std::unordered_map<uint32_t, uint32_t> endpoint_to_pid_udp_;
};

} // namespace dpi
