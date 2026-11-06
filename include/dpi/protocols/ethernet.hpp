#pragma once

#include "endian.hpp"
#include <cstdint>
#include <string>
#include <cstdio>
#include <cstring>

namespace dpi::protocols {

#pragma pack(push, 1)

struct MacAddress {
    uint8_t bytes[6];

    [[nodiscard]] std::string to_string() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return std::string(buf);
    }

    [[nodiscard]] bool operator==(const MacAddress& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 6) == 0;
    }

    [[nodiscard]] bool operator!=(const MacAddress& other) const noexcept {
        return !(*this == other);
    }
};

struct EthernetHeader {
    MacAddress dst_mac;
    MacAddress src_mac;
    uint16_t   ethertype;

    [[nodiscard]] uint16_t type() const noexcept {
        return ntoh16(ethertype);
    }
};

#pragma pack(pop)

static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be exactly 14 bytes");

namespace ethertype {
    constexpr uint16_t IPV4  = 0x0800;
    constexpr uint16_t ARP   = 0x0806;
    constexpr uint16_t VLAN  = 0x8100;
    constexpr uint16_t IPV6  = 0x86DD;
    constexpr uint16_t QINQ  = 0x88A8;
}

}
