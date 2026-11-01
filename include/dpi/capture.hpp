#pragma once

#include "packet.hpp"
#include <string>
#include <span>
#include <memory>
#include <cstdint>

namespace dpi {

struct CaptureStats {
    uint64_t packets_received{0};
    uint64_t bytes_received{0};
    uint64_t packets_dropped{0};
};

class ICaptureDevice {
public:
    virtual ~ICaptureDevice() = default;

    // Opens interface or filter string (e.g. WinDivert filter "true" or Linux interface "eth0")
    virtual bool open(const std::string& target) = 0;

    // Closes device handle
    virtual void close() = 0;

    // Receives a batch of packets directly into preallocated PacketSlots
    virtual size_t receive_batch(std::span<PacketSlot> out_slots) = 0;

    // Capture statistics
    [[nodiscard]] virtual CaptureStats get_stats() const = 0;

    // Factory methods
    static std::unique_ptr<ICaptureDevice> create_windivert();
    static std::unique_ptr<ICaptureDevice> create_afxdp();
    static std::unique_ptr<ICaptureDevice> create_pcap(const std::string& pcap_path);
};

} // namespace dpi
