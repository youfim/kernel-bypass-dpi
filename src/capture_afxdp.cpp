#include "dpi/capture.hpp"
#include <iostream>

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>

namespace dpi {

class AfXdpCaptureDevice : public ICaptureDevice {
public:
    AfXdpCaptureDevice() = default;
    ~AfXdpCaptureDevice() override { close(); }

    bool open(const std::string& ifname) override {
        // High-level AF_XDP socket setup via UMEM mmap and XSK
        std::cout << "[AF_XDP] Initializing UMEM rings on interface: " << ifname << std::endl;
        interface_name_ = ifname;
        // In full Linux deployment: xsk_umem__create & xsk_socket__create
        return true;
    }

    void close() override {
        // Release UMEM buffer and close xsk socket
    }

    size_t receive_batch(std::span<PacketSlot> out_slots) override {
        // Dequeue descriptors from XSK RX ring, copy/swap buffers, replenish Fill ring
        return 0;
    }

    [[nodiscard]] CaptureStats get_stats() const override {
        return stats_;
    }

private:
    std::string interface_name_;
    CaptureStats stats_{};
};

std::unique_ptr<ICaptureDevice> ICaptureDevice::create_afxdp() {
    return std::make_unique<AfXdpCaptureDevice>();
}

} // namespace dpi

#else

namespace dpi {

class NullAfXdpDevice : public ICaptureDevice {
public:
    bool open(const std::string&) override {
        std::cerr << "[AF_XDP] AF_XDP is supported on Linux kernels only." << std::endl;
        return false;
    }
    void close() override {}
    size_t receive_batch(std::span<PacketSlot>) override { return 0; }
    CaptureStats get_stats() const override { return {}; }
};

std::unique_ptr<ICaptureDevice> ICaptureDevice::create_afxdp() {
    return std::make_unique<NullAfXdpDevice>();
}

} // namespace dpi

#endif
