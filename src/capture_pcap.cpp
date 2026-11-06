#include "dpi/capture.hpp"
#include <fstream>
#include <iostream>
#include <cstring>

namespace dpi {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

class PcapCaptureDevice : public ICaptureDevice {
public:
    explicit PcapCaptureDevice(std::string path) : path_(std::move(path)) {}
    ~PcapCaptureDevice() override { close(); }

    bool open(const std::string& custom_path) override {
        if (!custom_path.empty()) {
            path_ = custom_path;
        }

        file_.open(path_, std::ios::binary);
        if (!file_.is_open()) {
            std::cerr << "[PCAP] Failed to open file: " << path_ << std::endl;
            return false;
        }

        PcapGlobalHeader gh{};
        if (!file_.read(reinterpret_cast<char*>(&gh), sizeof(gh))) {
            std::cerr << "[PCAP] Failed to read PCAP global header." << std::endl;
            return false;
        }

        if (gh.magic_number == 0xa1b2c3d4) {
            nano_ts_ = false;
            byte_swap_ = false;
        } else if (gh.magic_number == 0xd4c3b2a1) {
            nano_ts_ = false;
            byte_swap_ = true;
        } else if (gh.magic_number == 0xa1b23c4d) {
            nano_ts_ = true;
            byte_swap_ = false;
        } else {
            std::cerr << "[PCAP] Unrecognized magic number: 0x" << std::hex << gh.magic_number << std::endl;
            return false;
        }

        return true;
    }

    void close() override {
        if (file_.is_open()) {
            file_.close();
        }
    }

    size_t receive_batch(std::span<PacketSlot> out_slots) override {
        if (!file_.is_open() || out_slots.empty()) {
            return 0;
        }

        size_t count = 0;
        const size_t max_count = out_slots.size();

        while (count < max_count && file_) {
            PcapPacketHeader ph{};
            if (!file_.read(reinterpret_cast<char*>(&ph), sizeof(ph))) {
                break;
            }

            uint32_t cap_len = ph.incl_len;
            if (byte_swap_) {
                cap_len = protocols::bswap32(cap_len);
            }

            auto& slot = out_slots[count];
            const size_t read_bytes = std::min(static_cast<size_t>(cap_len), PACKET_BUFFER_SIZE);

            if (!file_.read(reinterpret_cast<char*>(slot.data), read_bytes)) {
                break;
            }

            if (cap_len > read_bytes) {
                file_.seekg(cap_len - read_bytes, std::ios::cur);
            }

            slot.length = static_cast<uint32_t>(read_bytes);
            slot.interface_id = 0;

            uint64_t sec = ph.ts_sec;
            uint64_t usec = ph.ts_usec;
            if (byte_swap_) {
                sec = protocols::bswap32(static_cast<uint32_t>(sec));
                usec = protocols::bswap32(static_cast<uint32_t>(usec));
            }

            if (nano_ts_) {
                slot.timestamp_ns = (sec * 1'000'000'000ULL) + usec;
            } else {
                slot.timestamp_ns = (sec * 1'000'000'000ULL) + (usec * 1'000ULL);
            }

            stats_.packets_received++;
            stats_.bytes_received += read_bytes;
            count++;
        }

        return count;
    }

    [[nodiscard]] CaptureStats get_stats() const override {
        return stats_;
    }

private:
    std::string path_;
    std::ifstream file_;
    bool byte_swap_{false};
    bool nano_ts_{false};
    CaptureStats stats_{};
};

std::unique_ptr<ICaptureDevice> ICaptureDevice::create_pcap(const std::string& pcap_path) {
    return std::make_unique<PcapCaptureDevice>(pcap_path);
}

} // namespace dpi
