#pragma once

#include "endian.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <cstdio>
#include <cstring>

namespace dpi::protocols {

#pragma pack(push, 1)

struct Ipv4Address {
    uint8_t bytes[4];

    [[nodiscard]] uint32_t to_u32() const noexcept {
        uint32_t val;
        std::memcpy(&val, bytes, 4);
        return val;
    }

    [[nodiscard]] std::string to_string() const {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return std::string(buf);
    }

    [[nodiscard]] bool operator==(const Ipv4Address& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 4) == 0;
    }

    [[nodiscard]] bool operator!=(const Ipv4Address& other) const noexcept {
        return !(*this == other);
    }

    [[nodiscard]] bool operator<(const Ipv4Address& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 4) < 0;
    }
};

struct Ipv4Header {
    uint8_t     ver_ihl;
    uint8_t     tos;
    uint16_t    total_len;
    uint16_t    id;
    uint16_t    flags_frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    checksum;
    Ipv4Address src_ip;
    Ipv4Address dst_ip;

    [[nodiscard]] uint8_t version() const noexcept {
        return ver_ihl >> 4;
    }

    [[nodiscard]] uint8_t ihl() const noexcept {
        return ver_ihl & 0x0F;
    }

    [[nodiscard]] uint16_t header_length() const noexcept {
        return static_cast<uint16_t>(ihl() * 4);
    }

    [[nodiscard]] uint16_t total_length() const noexcept {
        return ntoh16(total_len);
    }

    [[nodiscard]] uint16_t identification() const noexcept {
        return ntoh16(id);
    }

    [[nodiscard]] bool dont_fragment() const noexcept {
        return (ntoh16(flags_frag_off) & 0x4000) != 0;
    }

    [[nodiscard]] bool more_fragments() const noexcept {
        return (ntoh16(flags_frag_off) & 0x2000) != 0;
    }

    [[nodiscard]] uint16_t fragment_offset() const noexcept {
        return (ntoh16(flags_frag_off) & 0x1FFF) * 8;
    }

    [[nodiscard]] bool is_fragment() const noexcept {
        return more_fragments() || (fragment_offset() > 0);
    }

    [[nodiscard]] uint16_t raw_checksum() const noexcept {
        return ntoh16(checksum);
    }

    [[nodiscard]] uint16_t compute_checksum() const noexcept {
        const auto* words = reinterpret_cast<const uint16_t*>(this);
        const size_t word_count = header_length() / 2;
        uint32_t sum = 0;

        for (size_t i = 0; i < word_count; ++i) {
            if (i == 5) continue;
            sum += ntoh16(words[i]);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum & 0xFFFF);
    }

    [[nodiscard]] bool verify_checksum() const noexcept {
        return compute_checksum() == raw_checksum();
    }
};

#pragma pack(pop)

static_assert(sizeof(Ipv4Header) == 20, "Base Ipv4Header must be exactly 20 bytes");

namespace ip_protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP  = 6;
    constexpr uint8_t UDP  = 17;
}

}
