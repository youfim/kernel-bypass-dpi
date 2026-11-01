#include "dpi/protocols/dns.hpp"
#include <cstdio>

namespace dpi::protocols {

std::optional<DnsMessage> parse_dns_message(std::span<const uint8_t> payload) {
    if (payload.size() < sizeof(DnsHeader)) {
        return std::nullopt;
    }

    const auto* hdr = reinterpret_cast<const DnsHeader*>(payload.data());
    DnsMessage msg;
    msg.transaction_id = hdr->transaction_id();
    msg.is_response = hdr->is_response();
    msg.rcode = hdr->rcode();

    size_t offset = sizeof(DnsHeader);

    // 1. Questions section
    const uint16_t q_count = hdr->question_count();
    msg.questions.reserve(q_count);

    for (uint16_t i = 0; i < q_count; ++i) {
        DnsQuestion q;
        if (!decode_dns_name(payload, offset, q.name)) {
            return std::nullopt;
        }

        if (offset + 4 > payload.size()) {
            return std::nullopt;
        }

        uint16_t raw_qtype, raw_qclass;
        std::memcpy(&raw_qtype, payload.data() + offset, 2);
        std::memcpy(&raw_qclass, payload.data() + offset + 2, 2);
        q.qtype = ntoh16(raw_qtype);
        q.qclass = ntoh16(raw_qclass);
        offset += 4;

        msg.questions.push_back(std::move(q));
    }

    // 2. Answers section (if response)
    const uint16_t a_count = hdr->answer_count();
    msg.answers.reserve(a_count);

    for (uint16_t i = 0; i < a_count; ++i) {
        DnsAnswer ans;
        if (!decode_dns_name(payload, offset, ans.name)) {
            break;
        }

        if (offset + 10 > payload.size()) {
            break;
        }

        uint16_t raw_type, raw_class, raw_rdlen;
        uint32_t raw_ttl;
        std::memcpy(&raw_type, payload.data() + offset, 2);
        std::memcpy(&raw_class, payload.data() + offset + 2, 2);
        std::memcpy(&raw_ttl, payload.data() + offset + 4, 4);
        std::memcpy(&raw_rdlen, payload.data() + offset + 8, 2);

        ans.type = ntoh16(raw_type);
        ans.rr_class = ntoh16(raw_class);
        ans.ttl = ntoh32(raw_ttl);
        const uint16_t rdlen = ntoh16(raw_rdlen);
        offset += 10;

        if (offset + rdlen > payload.size()) {
            break;
        }

        // Format RDATA based on record type
        if (ans.type == dns_type::A && rdlen == 4) {
            char ip_buf[16];
            std::snprintf(ip_buf, sizeof(ip_buf), "%u.%u.%u.%u",
                          payload[offset], payload[offset + 1],
                          payload[offset + 2], payload[offset + 3]);
            ans.data = ip_buf;
            offset += 4;
        } else if (ans.type == dns_type::AAAA && rdlen == 16) {
            char ip6_buf[40];
            const auto* b = payload.data() + offset;
            std::snprintf(ip6_buf, sizeof(ip6_buf),
                          "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                          b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                          b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
            ans.data = ip6_buf;
            offset += 16;
        } else if ((ans.type == dns_type::CNAME || ans.type == dns_type::PTR)) {
            size_t cname_offset = offset;
            std::string cname_str;
            if (decode_dns_name(payload, cname_offset, cname_str)) {
                ans.data = std::move(cname_str);
            }
            offset += rdlen;
        } else {
            offset += rdlen;
        }

        msg.answers.push_back(std::move(ans));
    }

    return msg;
}

} // namespace dpi::protocols
