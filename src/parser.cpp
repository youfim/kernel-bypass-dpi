#include "dpi/parser.hpp"
#include <cstring>

namespace dpi {

bool PacketParser::parse(std::span<const uint8_t> raw_bytes,
                         uint64_t timestamp_ns,
                         ParsedPacket& out) noexcept {
    out = ParsedPacket{};
    out.timestamp_ns = timestamp_ns;
    out.raw_data = raw_bytes;

    const size_t total_len = raw_bytes.size();
    if (total_len < sizeof(protocols::EthernetHeader)) {
        return false;
    }

    // 1. L2 Layer: Ethernet II
    out.eth = reinterpret_cast<const protocols::EthernetHeader*>(raw_bytes.data());
    uint16_t next_type = out.eth->type();
    size_t offset = sizeof(protocols::EthernetHeader);

    // 2. 802.1Q / QinQ VLAN handling
    if (next_type == protocols::ethertype::VLAN || next_type == protocols::ethertype::QINQ) {
        if (offset + sizeof(protocols::VlanHeader) > total_len) {
            return false;
        }
        out.vlan = reinterpret_cast<const protocols::VlanHeader*>(raw_bytes.data() + offset);
        next_type = out.vlan->type();
        offset += sizeof(protocols::VlanHeader);

        // Check for double tag (QinQ inner tag)
        if (next_type == protocols::ethertype::VLAN) {
            if (offset + sizeof(protocols::VlanHeader) > total_len) {
                return false;
            }
            out.inner_vlan = reinterpret_cast<const protocols::VlanHeader*>(raw_bytes.data() + offset);
            next_type = out.inner_vlan->type();
            offset += sizeof(protocols::VlanHeader);
        }
    }
    out.l3_offset = static_cast<uint16_t>(offset);

    // 3. L3 Layer: IPv4 or IPv6
    uint8_t l4_protocol_id = 0;
    size_t l3_payload_len = 0;

    if (next_type == protocols::ethertype::IPV4) {
        if (offset + sizeof(protocols::Ipv4Header) > total_len) {
            return false;
        }
        const auto* ip = reinterpret_cast<const protocols::Ipv4Header*>(raw_bytes.data() + offset);
        if (ip->version() != 4 || ip->ihl() < 5) {
            return false;
        }
        const uint16_t ip_hdr_len = ip->header_length();
        if (offset + ip_hdr_len > total_len) {
            return false;
        }
        const uint16_t ip_total_len = ip->total_length();
        if (ip_total_len > 0 && offset + ip_total_len <= total_len) {
            l3_payload_len = ip_total_len - ip_hdr_len;
        } else {
            l3_payload_len = total_len - (offset + ip_hdr_len);
        }

        out.l3_proto = L3Protocol::IPV4;
        out.ipv4 = ip;
        l4_protocol_id = ip->protocol;
        offset += ip_hdr_len;
    } else if (next_type == protocols::ethertype::IPV6) {
        if (offset + sizeof(protocols::Ipv6Header) > total_len) {
            return false;
        }
        const auto* ip6 = reinterpret_cast<const protocols::Ipv6Header*>(raw_bytes.data() + offset);
        if (ip6->version() != 6) {
            return false;
        }
        out.l3_proto = L3Protocol::IPV6;
        out.ipv6 = ip6;
        uint8_t next_hdr = ip6->next_header;
        offset += sizeof(protocols::Ipv6Header);

        // IPv6 Extension Headers traversal
        while (next_hdr == protocols::ipv6_extension::HOP_BY_HOP ||
               next_hdr == protocols::ipv6_extension::ROUTING ||
               next_hdr == protocols::ipv6_extension::DEST_OPTS) {
            if (offset + 2 > total_len) {
                return false;
            }
            next_hdr = raw_bytes[offset];
            const size_t ext_len = (static_cast<size_t>(raw_bytes[offset + 1]) + 1) * 8;
            if (offset + ext_len > total_len) {
                return false;
            }
            offset += ext_len;
        }
        l4_protocol_id = next_hdr;
        l3_payload_len = total_len - offset;
    } else if (next_type == protocols::ethertype::ARP) {
        out.l3_proto = L3Protocol::ARP;
        return true;
    } else {
        return false;
    }

    out.l4_offset = static_cast<uint16_t>(offset);

    // 4. L4 Layer: TCP or UDP
    if (l4_protocol_id == protocols::ip_protocol::TCP) {
        if (offset + sizeof(protocols::TcpHeader) > total_len) {
            return false;
        }
        const auto* tcp = reinterpret_cast<const protocols::TcpHeader*>(raw_bytes.data() + offset);
        const uint16_t tcp_hdr_len = tcp->header_length();
        if (tcp_hdr_len < sizeof(protocols::TcpHeader) || offset + tcp_hdr_len > total_len) {
            return false;
        }

        out.l4_proto = L4Protocol::TCP;
        out.tcp = tcp;

        // Parse TCP options if present
        if (tcp_hdr_len > sizeof(protocols::TcpHeader)) {
            const size_t opt_len = tcp_hdr_len - sizeof(protocols::TcpHeader);
            std::span<const uint8_t> opt_span(raw_bytes.data() + offset + sizeof(protocols::TcpHeader), opt_len);
            out.tcp_options = protocols::TcpOptions::parse(opt_span);
        }

        offset += tcp_hdr_len;
        out.payload_offset = static_cast<uint16_t>(offset);

        // L7 Payload slice
        if (offset < total_len) {
            size_t payload_size = total_len - offset;
            if (l3_payload_len > tcp_hdr_len && (l3_payload_len - tcp_hdr_len) < payload_size) {
                payload_size = l3_payload_len - tcp_hdr_len;
            }
            out.payload = std::span<const uint8_t>(raw_bytes.data() + offset, payload_size);
        }
    } else if (l4_protocol_id == protocols::ip_protocol::UDP) {
        if (offset + sizeof(protocols::UdpHeader) > total_len) {
            return false;
        }
        const auto* udp = reinterpret_cast<const protocols::UdpHeader*>(raw_bytes.data() + offset);
        const uint16_t udp_len = udp->total_length();
        if (udp_len < sizeof(protocols::UdpHeader)) {
            return false;
        }

        out.l4_proto = L4Protocol::UDP;
        out.udp = udp;
        offset += sizeof(protocols::UdpHeader);
        out.payload_offset = static_cast<uint16_t>(offset);

        // L7 Payload slice
        size_t payload_size = (udp_len > sizeof(protocols::UdpHeader)) ? (udp_len - sizeof(protocols::UdpHeader)) : 0;
        if (offset + payload_size > total_len) {
            payload_size = total_len - offset;
        }
        if (payload_size > 0) {
            out.payload = std::span<const uint8_t>(raw_bytes.data() + offset, payload_size);
        }
    } else if (l4_protocol_id == protocols::ip_protocol::ICMP) {
        out.l4_proto = L4Protocol::ICMP;
    }

    return true;
}

} // namespace dpi
