#pragma once

#include "endian.hpp"
#include <cstdint>

namespace dpi::protocols {

#pragma pack(push, 1)

struct VlanHeader {
    uint16_t tci;       // Priority (3 bits) | DEI (1 bit) | VID (12 bits)
    uint16_t ethertype; // Encapsulated EtherType

    [[nodiscard]] uint16_t raw_tci() const noexcept {
        return ntoh16(tci);
    }

    [[nodiscard]] uint8_t priority() const noexcept {
        return static_cast<uint8_t>((raw_tci() >> 13) & 0x07);
    }

    [[nodiscard]] bool dei() const noexcept {
        return (raw_tci() & 0x1000) != 0;
    }

    [[nodiscard]] uint16_t vlan_id() const noexcept {
        return raw_tci() & 0x0FFF;
    }

    [[nodiscard]] uint16_t type() const noexcept {
        return ntoh16(ethertype);
    }
};

#pragma pack(pop)

static_assert(sizeof(VlanHeader) == 4, "VlanHeader must be exactly 4 bytes");

} // namespace dpi::protocols
