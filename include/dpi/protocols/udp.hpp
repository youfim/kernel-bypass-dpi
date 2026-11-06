#pragma once

#include "endian.hpp"
#include <cstdint>

namespace dpi::protocols {

#pragma pack(push, 1)

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    [[nodiscard]] uint16_t source_port() const noexcept {
        return ntoh16(src_port);
    }

    [[nodiscard]] uint16_t destination_port() const noexcept {
        return ntoh16(dst_port);
    }

    [[nodiscard]] uint16_t total_length() const noexcept {
        return ntoh16(length);
    }

    [[nodiscard]] uint16_t raw_checksum() const noexcept {
        return ntoh16(checksum);
    }
};

#pragma pack(pop)

static_assert(sizeof(UdpHeader) == 8, "UdpHeader must be exactly 8 bytes");

}
