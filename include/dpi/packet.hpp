#pragma once

#include "protocols/ethernet.hpp"
#include "protocols/vlan.hpp"
#include "protocols/ipv4.hpp"
#include "protocols/ipv6.hpp"
#include "protocols/tcp.hpp"
#include "protocols/udp.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <optional>

namespace dpi {

constexpr size_t PACKET_BUFFER_SIZE = 2048;

#pragma pack(push, 1)

struct alignas(64) PacketSlot {
    uint64_t timestamp_ns{0};
    uint32_t length{0};
    uint16_t interface_id{0};
    uint16_t flags{0};
    uint8_t  data[PACKET_BUFFER_SIZE];
};

#pragma pack(pop)

enum class L3Protocol : uint8_t {
    UNKNOWN = 0,
    IPV4,
    IPV6,
    ARP
};

enum class L4Protocol : uint8_t {
    UNKNOWN = 0,
    TCP,
    UDP,
    ICMP
};

struct ParsedPacket {
    uint64_t timestamp_ns{0};
    std::span<const uint8_t> raw_data;

    // L2 Layer
    const protocols::EthernetHeader* eth{nullptr};
    const protocols::VlanHeader*     vlan{nullptr};
    const protocols::VlanHeader*     inner_vlan{nullptr}; // For QinQ
    uint16_t                         l3_offset{0};

    // L3 Layer
    L3Protocol                       l3_proto{L3Protocol::UNKNOWN};
    const protocols::Ipv4Header*     ipv4{nullptr};
    const protocols::Ipv6Header*     ipv6{nullptr};
    uint16_t                         l4_offset{0};

    // L4 Layer
    L4Protocol                       l4_proto{L4Protocol::UNKNOWN};
    const protocols::TcpHeader*      tcp{nullptr};
    const protocols::UdpHeader*      udp{nullptr};
    std::optional<protocols::TcpOptions> tcp_options;
    uint16_t                         payload_offset{0};

    // L7 Payload
    std::span<const uint8_t>         payload;

    [[nodiscard]] bool is_valid() const noexcept {
        return l3_proto != L3Protocol::UNKNOWN;
    }

    [[nodiscard]] bool is_tcp() const noexcept {
        return l4_proto == L4Protocol::TCP;
    }

    [[nodiscard]] bool is_udp() const noexcept {
        return l4_proto == L4Protocol::UDP;
    }

    [[nodiscard]] uint16_t src_port() const noexcept {
        if (tcp) return tcp->source_port();
        if (udp) return udp->source_port();
        return 0;
    }

    [[nodiscard]] uint16_t dst_port() const noexcept {
        if (tcp) return tcp->destination_port();
        if (udp) return udp->destination_port();
        return 0;
    }
};

} // namespace dpi
