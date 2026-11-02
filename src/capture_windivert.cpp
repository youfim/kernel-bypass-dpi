#include "dpi/capture.hpp"
#include <chrono>
#include <iostream>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dpi {

#pragma pack(push, 1)
struct WINDIVERT_ADDRESS {
    int64_t Timestamp;
    uint32_t Layer : 8;
    uint32_t Event : 8;
    uint32_t Sniffed : 1;
    uint32_t Outbound : 1;
    uint32_t Loopback : 1;
    uint32_t Impostor : 1;
    uint32_t IPv6 : 1;
    uint32_t IPChecksum : 1;
    uint32_t TCPChecksum : 1;
    uint32_t UDPChecksum : 1;
    uint32_t Reserved1 : 8;
    uint32_t IfIdx;
    uint32_t SubIfIdx;
};
#pragma pack(pop)

using WinDivertOpen_t = HANDLE(WINAPI*)(const char* filter, int layer, int16_t priority, uint64_t flags);
using WinDivertClose_t = BOOL(WINAPI*)(HANDLE handle);
using WinDivertRecv_t = BOOL(WINAPI*)(HANDLE handle, void* pPacket, UINT packetLen, UINT* pRecvLen, WINDIVERT_ADDRESS* pAddr);
using WinDivertRecvEx_t = BOOL(WINAPI*)(HANDLE handle, void* pPacket, UINT packetLen, UINT* pRecvLen, uint64_t flags, WINDIVERT_ADDRESS* pAddr, UINT* pAddrLen, OVERLAPPED* lpOverlapped);

class WinDivertCaptureDevice : public ICaptureDevice {
public:
    WinDivertCaptureDevice() {
        // 1. Try standard DLL search path
        hDll_ = LoadLibraryW(L"WinDivert.dll");

        // 2. Try loading from the directory of the current module (.exe or .pyd)
        if (!hDll_) {
            HMODULE hMod = nullptr;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCWSTR>(&WinDivertCaptureDevice::create_windivert), &hMod) && hMod) {
                wchar_t modPath[MAX_PATH];
                if (GetModuleFileNameW(hMod, modPath, MAX_PATH)) {
                    wchar_t* lastSlash = wcsrchr(modPath, L'\\');
                    if (lastSlash) {
                        *(lastSlash + 1) = L'\0';
                        wcscat_s(modPath, L"WinDivert.dll");
                        hDll_ = LoadLibraryW(modPath);
                    }
                }
            }
        }

        // 3. Try known repository paths
        if (!hDll_) {
            const wchar_t* candidates[] = {
                L"d:\\projects\\github\\kernel-ethernet-dumper\\WinDivert.dll",
                L"d:\\projects\\github\\kernel-ethernet-dumper\\build\\Release\\WinDivert.dll",
                L"d:\\projects\\github\\kernel-ethernet-dumper\\python\\dpi_engine\\WinDivert.dll",
                L"d:\\projects\\github\\kernel-ethernet-dumper\\python\\dpi_engine\\Release\\WinDivert.dll"
            };
            for (const auto* cand : candidates) {
                hDll_ = LoadLibraryW(cand);
                if (hDll_) break;
            }
        }

        if (hDll_) {
            fnOpen_ = reinterpret_cast<WinDivertOpen_t>(GetProcAddress(hDll_, "WinDivertOpen"));
            fnClose_ = reinterpret_cast<WinDivertClose_t>(GetProcAddress(hDll_, "WinDivertClose"));
            fnRecv_ = reinterpret_cast<WinDivertRecv_t>(GetProcAddress(hDll_, "WinDivertRecv"));
            fnRecvEx_ = reinterpret_cast<WinDivertRecvEx_t>(GetProcAddress(hDll_, "WinDivertRecvEx"));
        }
    }

    ~WinDivertCaptureDevice() override {
        close();
        if (hDll_) {
            FreeLibrary(hDll_);
        }
    }

    bool open(const std::string& filter) override {
        if (!hDll_ || !fnOpen_) {
            std::cerr << "[WinDivert] WinDivert.dll not found or missing exports." << std::endl;
            return false;
        }

        const char* filter_str = filter.empty() ? "true" : filter.c_str();
        // Layer 0 = WINDIVERT_LAYER_NETWORK, Flags 1 = WINDIVERT_FLAG_SNIFF
        handle_ = fnOpen_(filter_str, 0, 0, 1);
        if (handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "[WinDivert] WinDivertOpen failed with error code: " << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    void close() override {
        if (handle_ != INVALID_HANDLE_VALUE && fnClose_) {
            fnClose_(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    size_t receive_batch(std::span<PacketSlot> out_slots) override {
        if (handle_ == INVALID_HANDLE_VALUE || out_slots.empty()) {
            return 0;
        }

        size_t count = 0;
        const size_t max_packets = out_slots.size();

        for (size_t i = 0; i < max_packets; ++i) {
            auto& slot = out_slots[i];
            UINT recv_len = 0;
            WINDIVERT_ADDRESS addr{};

            if (fnRecv_(handle_, slot.data, PACKET_BUFFER_SIZE, &recv_len, &addr)) {
                slot.length = recv_len;
                slot.interface_id = static_cast<uint16_t>(addr.IfIdx);
                const auto now = std::chrono::steady_clock::now().time_since_epoch();
                slot.timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
                stats_.packets_received++;
                stats_.bytes_received += recv_len;
                count++;
            } else {
                break; // No more packets immediately available
            }
        }

        return count;
    }

    [[nodiscard]] CaptureStats get_stats() const override {
        return stats_;
    }

private:
    HMODULE hDll_{nullptr};
    HANDLE handle_{INVALID_HANDLE_VALUE};
    WinDivertOpen_t fnOpen_{nullptr};
    WinDivertClose_t fnClose_{nullptr};
    WinDivertRecv_t fnRecv_{nullptr};
    WinDivertRecvEx_t fnRecvEx_{nullptr};
    CaptureStats stats_{};
};

std::unique_ptr<ICaptureDevice> ICaptureDevice::create_windivert() {
    return std::make_unique<WinDivertCaptureDevice>();
}

} // namespace dpi

#else

namespace dpi {

class NullWinDivertDevice : public ICaptureDevice {
public:
    bool open(const std::string&) override { return false; }
    void close() override {}
    size_t receive_batch(std::span<PacketSlot>) override { return 0; }
    CaptureStats get_stats() const override { return {}; }
};

std::unique_ptr<ICaptureDevice> ICaptureDevice::create_windivert() {
    return std::make_unique<NullWinDivertDevice>();
}

} // namespace dpi

#endif
