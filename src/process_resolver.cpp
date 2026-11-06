#include "dpi/process_resolver.hpp"
#include <iostream>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

namespace dpi {

namespace {

std::string extract_filename(const std::string& full_path) {
    if (full_path.empty()) return {};
    size_t last_slash = full_path.find_last_of("\\/");
    if (last_slash != std::string::npos && last_slash + 1 < full_path.size()) {
        return full_path.substr(last_slash + 1);
    }
    return full_path;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), str.data(), size_needed, nullptr, nullptr);
    return str;
}

}

ProcessResolver& ProcessResolver::instance() {
    static ProcessResolver resolver;
    return resolver;
}

ProcessResolver::ProcessResolver() {
    refresh_cache();
}

ProcessInfo ProcessResolver::query_process_by_pid(uint32_t pid) {
    if (pid == 0) return {0, "System Idle", ""};
    if (pid == 4) return {4, "System", ""};

    ProcessInfo info;
    info.pid = pid;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t path_buf[MAX_PATH * 2] = {0};
        DWORD size = sizeof(path_buf) / sizeof(wchar_t);
        if (QueryFullProcessImageNameW(hProc, 0, path_buf, &size)) {
            info.path = wstring_to_utf8(path_buf);
            info.name = extract_filename(info.path);
        }
        CloseHandle(hProc);
    }

    if (info.name.empty()) {
        info.name = "PID:" + std::to_string(pid);
    }

    return info;
}

void ProcessResolver::refresh_tables_windows() {
    std::unordered_map<uint32_t, uint32_t> new_tcp;
    std::unordered_map<uint32_t, uint32_t> new_udp;

    ULONG table_size = 0;
    GetExtendedTcpTable(nullptr, &table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (table_size > 0) {
        std::vector<uint8_t> buffer(table_size);
        if (GetExtendedTcpTable(buffer.data(), &table_size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* pTable = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                new_tcp[port] = row.dwOwningPid;
            }
        }
    }

    table_size = 0;
    GetExtendedUdpTable(nullptr, &table_size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (table_size > 0) {
        std::vector<uint8_t> buffer(table_size);
        if (GetExtendedUdpTable(buffer.data(), &table_size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* pTable = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                new_udp[port] = row.dwOwningPid;
            }
        }
    }

    table_size = 0;
    GetExtendedTcpTable(nullptr, &table_size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (table_size > 0) {
        std::vector<uint8_t> buffer(table_size);
        if (GetExtendedTcpTable(buffer.data(), &table_size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* pTable = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                new_tcp[port] = row.dwOwningPid;
            }
        }
    }

    table_size = 0;
    GetExtendedUdpTable(nullptr, &table_size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (table_size > 0) {
        std::vector<uint8_t> buffer(table_size);
        if (GetExtendedUdpTable(buffer.data(), &table_size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* pTable = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
                new_udp[port] = row.dwOwningPid;
            }
        }
    }

    endpoint_to_pid_tcp_ = std::move(new_tcp);
    endpoint_to_pid_udp_ = std::move(new_udp);
    last_refresh_ = std::chrono::steady_clock::now();
}

void ProcessResolver::refresh_cache() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    refresh_tables_windows();
}

ProcessInfo ProcessResolver::resolve(uint16_t local_port, uint8_t protocol, bool ) {
    const auto now = std::chrono::steady_clock::now();

    {
        std::shared_lock<std::shared_mutex> read_lock(mutex_);
        if (now - last_refresh_ < std::chrono::milliseconds(1000)) {
            const auto& map = (protocol == 6) ? endpoint_to_pid_tcp_ : endpoint_to_pid_udp_;
            auto it = map.find(local_port);
            if (it != map.end()) {
                uint32_t pid = it->second;
                auto pit = pid_cache_.find(pid);
                if (pit != pid_cache_.end()) {
                    return pit->second;
                }
            }
        }
    }

    std::unique_lock<std::shared_mutex> write_lock(mutex_);
    if (now - last_refresh_ >= std::chrono::milliseconds(100)) {
        refresh_tables_windows();
    }

    const auto& map = (protocol == 6) ? endpoint_to_pid_tcp_ : endpoint_to_pid_udp_;
    auto it = map.find(local_port);
    if (it == map.end()) {
        return {0, "", ""};
    }

    uint32_t pid = it->second;
    auto pit = pid_cache_.find(pid);
    if (pit != pid_cache_.end()) {
        return pit->second;
    }

    ProcessInfo info = query_process_by_pid(pid);
    pid_cache_[pid] = info;
    return info;
}

}

#else

namespace dpi {

ProcessResolver& ProcessResolver::instance() {
    static ProcessResolver resolver;
    return resolver;
}

ProcessResolver::ProcessResolver() = default;

ProcessInfo ProcessResolver::query_process_by_pid(uint32_t pid) {
    return {pid, "proc_" + std::to_string(pid), ""};
}

void ProcessResolver::refresh_tables_windows() {}

void ProcessResolver::refresh_cache() {}

ProcessInfo ProcessResolver::resolve(uint16_t, uint8_t, bool) {
    return {0, "", ""};
}

}

#endif
