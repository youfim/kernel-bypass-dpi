#pragma once

#include "endian.hpp"
#include <cstdint>
#include <span>
#include <optional>

namespace dpi::protocols {

#pragma pack(push, 1)

struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_off_res;
    uint8_t  flags;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urg_ptr;

    [[nodiscard]] uint16_t source_port() const noexcept {
        return ntoh16(src_port);
    }

    [[nodiscard]] uint16_t destination_port() const noexcept {
        return ntoh16(dst_port);
    }

    [[nodiscard]] uint32_t sequence_number() const noexcept {
        return ntoh32(seq_num);
    }

    [[nodiscard]] uint32_t ack_number() const noexcept {
        return ntoh32(ack_num);
    }

    [[nodiscard]] uint8_t data_offset() const noexcept {
        return data_off_res >> 4;
    }

    [[nodiscard]] uint16_t header_length() const noexcept {
        return static_cast<uint16_t>(data_offset() * 4);
    }

    [[nodiscard]] uint16_t window_size() const noexcept {
        return ntoh16(win_size);
    }

    [[nodiscard]] uint16_t raw_checksum() const noexcept {
        return ntoh16(checksum);
    }

    [[nodiscard]] uint16_t urgent_pointer() const noexcept {
        return ntoh16(urg_ptr);
    }

    [[nodiscard]] bool fin() const noexcept { return (flags & 0x01) != 0; }
    [[nodiscard]] bool syn() const noexcept { return (flags & 0x02) != 0; }
    [[nodiscard]] bool rst() const noexcept { return (flags & 0x04) != 0; }
    [[nodiscard]] bool psh() const noexcept { return (flags & 0x08) != 0; }
    [[nodiscard]] bool ack() const noexcept { return (flags & 0x10) != 0; }
    [[nodiscard]] bool urg() const noexcept { return (flags & 0x20) != 0; }
    [[nodiscard]] bool ece() const noexcept { return (flags & 0x40) != 0; }
    [[nodiscard]] bool cwr() const noexcept { return (flags & 0x80) != 0; }
};

#pragma pack(pop)

static_assert(sizeof(TcpHeader) == 20, "Base TcpHeader must be exactly 20 bytes");

struct TcpOptions {
    std::optional<uint16_t> mss;
    std::optional<uint8_t>  window_scale;
    bool                    sack_permitted{false};
    std::optional<uint32_t> timestamp_val;
    std::optional<uint32_t> timestamp_echo;

    static TcpOptions parse(std::span<const uint8_t> options_bytes) noexcept {
        TcpOptions opts;
        size_t idx = 0;
        const size_t len = options_bytes.size();

        while (idx < len) {
            const uint8_t kind = options_bytes[idx++];
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                continue;
            }
            if (idx >= len) {
                break;
            }
            const uint8_t opt_len = options_bytes[idx++];
            if (opt_len < 2 || idx + (opt_len - 2) > len) {
                break;
            }
            const size_t data_len = opt_len - 2;
            const uint8_t* data = &options_bytes[idx];

            switch (kind) {
                case 2:
                    if (data_len == 2) {
                        uint16_t raw_val;
                        std::memcpy(&raw_val, data, 2);
                        opts.mss = ntoh16(raw_val);
                    }
                    break;
                case 3:
                    if (data_len == 1) {
                        opts.window_scale = data[0];
                    }
                    break;
                case 4:
                    if (data_len == 0) {
                        opts.sack_permitted = true;
                    }
                    break;
                case 8:
                    if (data_len == 8) {
                        uint32_t ts_val, ts_ecr;
                        std::memcpy(&ts_val, data, 4);
                        std::memcpy(&ts_ecr, data + 4, 4);
                        opts.timestamp_val = ntoh32(ts_val);
                        opts.timestamp_echo = ntoh32(ts_ecr);
                    }
                    break;
                default:
                    break;
            }
            idx += data_len;
        }
        return opts;
    }
};

}
