#pragma once

#include "endian.hpp"
#include <cstdint>
#include <string>
#include <cstdio>
#include <cstring>
#include <span>

namespace dpi::protocols {

#pragma pack(push, 1)

struct Ipv6Address {
    uint8_t bytes[16];

    [[nodiscard]] std::string to_string() const {
        char buf[40];
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      bytes[0], bytes[1], bytes[2], bytes[3],
                      bytes[4], bytes[5], bytes[6], bytes[7],
                      bytes[8], bytes[9], bytes[10], bytes[11],
                      bytes[12], bytes[13], bytes[14], bytes[15]);
        return std::string(buf);
    }

    [[nodiscard]] bool operator==(const Ipv6Address& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 16) == 0;
    }

    [[nodiscard]] bool operator!=(const Ipv6Address& other) const noexcept {
        return !(*this == other);
    }

    [[nodiscard]] bool operator<(const Ipv6Address& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 16) < 0;
    }
};

struct Ipv6Header {
    uint32_t    ver_tc_flow;
    uint16_t    payload_len;
    uint8_t     next_header;
    uint8_t     hop_limit;
    Ipv6Address src_ip;
    Ipv6Address dst_ip;

    [[nodiscard]] uint8_t version() const noexcept {
        return static_cast<uint8_t>((ntoh32(ver_tc_flow) >> 28) & 0x0F);
    }

    [[nodiscard]] uint8_t traffic_class() const noexcept {
        return static_cast<uint8_t>((ntoh32(ver_tc_flow) >> 20) & 0xFF);
    }

    [[nodiscard]] uint32_t flow_label() const noexcept {
        return ntoh32(ver_tc_flow) & 0x000FFFFF;
    }

    [[nodiscard]] uint16_t payload_length() const noexcept {
        return ntoh16(payload_len);
    }
};

#pragma pack(pop)

static_assert(sizeof(Ipv6Header) == 40, "Ipv6Header must be exactly 40 bytes");

namespace ipv6_extension {
    constexpr uint8_t HOP_BY_HOP  = 0;
    constexpr uint8_t ROUTING     = 43;
    constexpr uint8_t FRAGMENT    = 44;
    constexpr uint8_t ESP         = 50;
    constexpr uint8_t AH          = 51;
    constexpr uint8_t NONE        = 59;
    constexpr uint8_t DEST_OPTS   = 60;
}

}
