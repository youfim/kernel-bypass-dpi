#pragma once

#include "endian.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <cstring>

namespace dpi::protocols {

#pragma pack(push, 1)

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    [[nodiscard]] uint16_t transaction_id() const noexcept { return ntoh16(id); }
    [[nodiscard]] uint16_t raw_flags() const noexcept { return ntoh16(flags); }
    [[nodiscard]] bool is_response() const noexcept { return (raw_flags() & 0x8000) != 0; }
    [[nodiscard]] uint8_t opcode() const noexcept { return static_cast<uint8_t>((raw_flags() >> 11) & 0x0F); }
    [[nodiscard]] bool authoritative() const noexcept { return (raw_flags() & 0x0400) != 0; }
    [[nodiscard]] bool truncated() const noexcept { return (raw_flags() & 0x0200) != 0; }
    [[nodiscard]] bool recursion_desired() const noexcept { return (raw_flags() & 0x0100) != 0; }
    [[nodiscard]] bool recursion_available() const noexcept { return (raw_flags() & 0x0080) != 0; }
    [[nodiscard]] uint8_t rcode() const noexcept { return static_cast<uint8_t>(raw_flags() & 0x0F); }

    [[nodiscard]] uint16_t question_count() const noexcept { return ntoh16(qdcount); }
    [[nodiscard]] uint16_t answer_count() const noexcept { return ntoh16(ancount); }
    [[nodiscard]] uint16_t authority_count() const noexcept { return ntoh16(nscount); }
    [[nodiscard]] uint16_t additional_count() const noexcept { return ntoh16(arcount); }
};

#pragma pack(pop)

static_assert(sizeof(DnsHeader) == 12, "DnsHeader must be exactly 12 bytes");

namespace dns_type {
    constexpr uint16_t A     = 1;
    constexpr uint16_t NS    = 2;
    constexpr uint16_t CNAME = 5;
    constexpr uint16_t SOA   = 6;
    constexpr uint16_t PTR   = 12;
    constexpr uint16_t MX    = 15;
    constexpr uint16_t TXT   = 16;
    constexpr uint16_t AAAA  = 28;
    constexpr uint16_t SRV   = 33;
    constexpr uint16_t HTTPS = 65;
}

struct DnsQuestion {
    std::string name;
    uint16_t    qtype{0};
    uint16_t    qclass{0};
};

struct DnsAnswer {
    std::string name;
    uint16_t    type{0};
    uint16_t    rr_class{0};
    uint32_t    ttl{0};
    std::string data;
};

struct DnsMessage {
    uint16_t                 transaction_id{0};
    bool                     is_response{false};
    uint8_t                  rcode{0};
    std::vector<DnsQuestion> questions;
    std::vector<DnsAnswer>   answers;
};

inline bool decode_dns_name(std::span<const uint8_t> packet_payload,
                            size_t& offset,
                            std::string& out_name,
                            int max_jumps = 10) {
    out_name.clear();
    const size_t total_size = packet_payload.size();
    size_t curr_pos = offset;
    bool jumped = false;
    size_t jump_back_pos = 0;
    int jumps = 0;

    while (curr_pos < total_size) {
        const uint8_t len = packet_payload[curr_pos];
        if (len == 0) {

            if (jumped) {
                offset = jump_back_pos;
            } else {
                offset = curr_pos + 1;
            }
            return true;
        }

        if ((len & 0xC0) == 0xC0) {
            if (curr_pos + 1 >= total_size) {
                return false;
            }
            if (jumps++ >= max_jumps) {
                return false;
            }
            if (!jumped) {
                jump_back_pos = curr_pos + 2;
                jumped = true;
            }
            const uint16_t ptr_offset = ((static_cast<uint16_t>(len & 0x3F) << 8) | packet_payload[curr_pos + 1]);
            if (ptr_offset >= total_size) {
                return false;
            }
            curr_pos = ptr_offset;
            continue;
        }

        curr_pos++;
        if (curr_pos + len > total_size) {
            return false;
        }
        if (!out_name.empty()) {
            out_name.push_back('.');
        }
        out_name.append(reinterpret_cast<const char*>(&packet_payload[curr_pos]), len);
        curr_pos += len;

        if (!jumped) {
            offset = curr_pos;
        }
    }

    if (jumped) {
        offset = jump_back_pos;
    }
    return true;
}

std::optional<DnsMessage> parse_dns_message(std::span<const uint8_t> payload);

}
