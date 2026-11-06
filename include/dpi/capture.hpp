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

    virtual bool open(const std::string& target) = 0;

    virtual void close() = 0;

    virtual size_t receive_batch(std::span<PacketSlot> out_slots) = 0;

    [[nodiscard]] virtual CaptureStats get_stats() const = 0;

    static std::unique_ptr<ICaptureDevice> create_windivert();
    static std::unique_ptr<ICaptureDevice> create_afxdp();
    static std::unique_ptr<ICaptureDevice> create_pcap(const std::string& pcap_path);
};

}
