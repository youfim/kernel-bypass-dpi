#include "dpi/protocols/tls.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <array>

namespace dpi::protocols {

namespace {

struct MD5Context {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t  buffer[64];
};

inline void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    for (int i = 0; i < 16; ++i) {
        x[i] = static_cast<uint32_t>(block[i * 4]) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }

    #define ROTLEFT(num, amt) (((num) << (amt)) | ((num) >> (32 - (amt))))
    #define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
    #define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
    #define H(x, y, z) ((x) ^ (y) ^ (z))
    #define I(x, y, z) ((y) ^ ((x) | (~z)))

    #define STEP1(a, b, c, d, k, s, i) { a += F(b, c, d) + k + i; a = ROTLEFT(a, s) + b; }
    #define STEP2(a, b, c, d, k, s, i) { a += G(b, c, d) + k + i; a = ROTLEFT(a, s) + b; }
    #define STEP3(a, b, c, d, k, s, i) { a += H(b, c, d) + k + i; a = ROTLEFT(a, s) + b; }
    #define STEP4(a, b, c, d, k, s, i) { a += I(b, c, d) + k + i; a = ROTLEFT(a, s) + b; }

    STEP1(a, b, c, d, x[0], 7, 0xd76aa478);   STEP1(d, a, b, c, x[1], 12, 0xe8c7b756);
    STEP1(c, d, a, b, x[2], 17, 0x242070db);  STEP1(b, c, d, a, x[3], 22, 0xc1bdceee);
    STEP1(a, b, c, d, x[4], 7, 0xf57c0faf);   STEP1(d, a, b, c, x[5], 12, 0x4787c62a);
    STEP1(c, d, a, b, x[6], 17, 0xa8304613);  STEP1(b, c, d, a, x[7], 22, 0xfd469501);
    STEP1(a, b, c, d, x[8], 7, 0x698098d8);   STEP1(d, a, b, c, x[9], 12, 0x8b44f7af);
    STEP1(c, d, a, b, x[10], 17, 0xffff5bb1); STEP1(b, c, d, a, x[11], 22, 0x895cd7be);
    STEP1(a, b, c, d, x[12], 7, 0x6b901122);  STEP1(d, a, b, c, x[13], 12, 0xfd987193);
    STEP1(c, d, a, b, x[14], 17, 0xa679438e); STEP1(b, c, d, a, x[15], 22, 0x49b40821);

    STEP2(a, b, c, d, x[1], 5, 0xf61e2562);   STEP2(d, a, b, c, x[6], 9, 0xc040b340);
    STEP2(c, d, a, b, x[11], 14, 0x265e5a51); STEP2(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    STEP2(a, b, c, d, x[5], 5, 0xd62f105d);   STEP2(d, a, b, c, x[10], 9, 0x02441453);
    STEP2(c, d, a, b, x[15], 14, 0xd8a1e681); STEP2(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    STEP2(a, b, c, d, x[9], 5, 0x21e1cde6);   STEP2(d, a, b, c, x[14], 9, 0xc33707d6);
    STEP2(c, d, a, b, x[3], 14, 0xf4d50d87);  STEP2(b, c, d, a, x[8], 20, 0x455a14ed);
    STEP2(a, b, c, d, x[13], 5, 0xa9e3e905);  STEP2(d, a, b, c, x[2], 9, 0xfcefa3f8);
    STEP2(c, d, a, b, x[7], 14, 0x676f02d9);  STEP2(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    STEP3(a, b, c, d, x[5], 4, 0xfffa3942);   STEP3(d, a, b, c, x[8], 11, 0x8771f681);
    STEP3(c, d, a, b, x[11], 16, 0x6d9d6122); STEP3(b, c, d, a, x[14], 23, 0xfde5380c);
    STEP3(a, b, c, d, x[1], 4, 0xa4beea44);   STEP3(d, a, b, c, x[4], 11, 0x4bdecfa9);
    STEP3(c, d, a, b, x[7], 16, 0xf6bb4b60);  STEP3(b, c, d, a, x[10], 23, 0xbebfbc70);
    STEP3(a, b, c, d, x[13], 4, 0x289b7ec6);  STEP3(d, a, b, c, x[0], 11, 0xeaa127fa);
    STEP3(c, d, a, b, x[3], 16, 0xd4ef3085);  STEP3(b, c, d, a, x[6], 23, 0x04881d05);
    STEP3(a, b, c, d, x[9], 4, 0xd9d4d039);   STEP3(d, a, b, c, x[12], 11, 0xe6db99e5);
    STEP3(c, d, a, b, x[15], 16, 0x1fa27cf8); STEP3(b, c, d, a, x[2], 23, 0xc4ac5665);

    STEP4(a, b, c, d, x[0], 6, 0xf4292244);   STEP4(d, a, b, c, x[7], 10, 0x432aff97);
    STEP4(c, d, a, b, x[14], 15, 0xab9423a7); STEP4(b, c, d, a, x[5], 21, 0xfc93a039);
    STEP4(a, b, c, d, x[12], 6, 0x655b59c3);  STEP4(d, a, b, c, x[3], 10, 0x8f0ccc92);
    STEP4(c, d, a, b, x[10], 15, 0xffeff47d); STEP4(b, c, d, a, x[1], 21, 0x85845dd1);
    STEP4(a, b, c, d, x[8], 6, 0x6fa87e4f);   STEP4(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    STEP4(c, d, a, b, x[6], 15, 0xa3014314);  STEP4(b, c, d, a, x[13], 21, 0x4e0811a1);
    STEP4(a, b, c, d, x[4], 6, 0xf7537e82);   STEP4(d, a, b, c, x[11], 10, 0xbd3af235);
    STEP4(c, d, a, b, x[2], 15, 0x2ad7d2bb);  STEP4(b, c, d, a, x[9], 21, 0xeb86d391);

    #undef ROTLEFT
    #undef F
    #undef G
    #undef H
    #undef I
    #undef STEP1
    #undef STEP2
    #undef STEP3
    #undef STEP4

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

std::string compute_md5_hex(const std::string& input) {
    MD5Context ctx;
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.count[0] = ctx.count[1] = 0;

    const auto* data = reinterpret_cast<const uint8_t*>(input.data());
    size_t length = input.size();

    size_t index = (ctx.count[0] >> 3) & 63;
    uint32_t bits = static_cast<uint32_t>(length << 3);
    ctx.count[0] += bits;
    if (ctx.count[0] < bits) ctx.count[1]++;
    ctx.count[1] += static_cast<uint32_t>(length >> 29);

    size_t part_len = 64 - index;
    size_t i = 0;
    if (length >= part_len) {
        std::memcpy(&ctx.buffer[index], data, part_len);
        md5_transform(ctx.state, ctx.buffer);
        for (i = part_len; i + 63 < length; i += 64) {
            md5_transform(ctx.state, &data[i]);
        }
        index = 0;
    }
    std::memcpy(&ctx.buffer[index], &data[i], length - i);

    uint8_t padding[64] = { 0x80 };
    uint8_t bits_buf[8];
    for (int j = 0; j < 4; ++j) {
        bits_buf[j] = (ctx.count[0] >> (j * 8)) & 0xFF;
        bits_buf[j + 4] = (ctx.count[1] >> (j * 8)) & 0xFF;
    }

    size_t pad_index = (ctx.count[0] >> 3) & 63;
    size_t pad_len = (pad_index < 56) ? (56 - pad_index) : (120 - pad_index);

    size_t pindex = (ctx.count[0] >> 3) & 63;
    size_t ppart = 64 - pindex;
    if (pad_len >= ppart) {
        std::memcpy(&ctx.buffer[pindex], padding, ppart);
        md5_transform(ctx.state, ctx.buffer);
        for (i = ppart; i + 63 < pad_len; i += 64) {
            md5_transform(ctx.state, &padding[i]);
        }
        pindex = 0;
    } else {
        i = 0;
    }
    std::memcpy(&ctx.buffer[pindex], &padding[i], pad_len - i);

    for (int j = 0; j < 8; ++j) {
        ctx.buffer[56 + j] = bits_buf[j];
    }
    md5_transform(ctx.state, ctx.buffer);

    uint8_t digest[16];
    for (int j = 0; j < 4; ++j) {
        digest[j * 4] = ctx.state[j] & 0xFF;
        digest[j * 4 + 1] = (ctx.state[j] >> 8) & 0xFF;
        digest[j * 4 + 2] = (ctx.state[j] >> 16) & 0xFF;
        digest[j * 4 + 3] = (ctx.state[j] >> 24) & 0xFF;
    }

    std::ostringstream ss;
    for (int j = 0; j < 16; ++j) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[j]);
    }
    return ss.str();
}

inline bool is_grease(uint16_t val) noexcept {
    return (val & 0x0F0F) == 0x0A0A && ((val >> 8) == (val & 0xFF));
}

}

std::optional<TlsClientHello> parse_tls_client_hello(std::span<const uint8_t> payload) {
    if (payload.size() < sizeof(TlsRecordHeader) + sizeof(TlsHandshakeHeader)) {
        return std::nullopt;
    }

    const auto* rec = reinterpret_cast<const TlsRecordHeader*>(payload.data());
    if (!rec->is_handshake()) {
        return std::nullopt;
    }

    size_t offset = sizeof(TlsRecordHeader);
    const auto* hs = reinterpret_cast<const TlsHandshakeHeader*>(payload.data() + offset);
    if (!hs->is_client_hello()) {
        return std::nullopt;
    }
    offset += sizeof(TlsHandshakeHeader);

    if (offset + 2 + 32 > payload.size()) {
        return std::nullopt;
    }

    TlsClientHello hello;
    uint16_t client_ver;
    std::memcpy(&client_ver, payload.data() + offset, 2);
    hello.client_version = ntoh16(client_ver);
    offset += 2;

    std::memcpy(hello.random, payload.data() + offset, 32);
    offset += 32;

    if (offset >= payload.size()) return std::nullopt;
    const uint8_t session_id_len = payload[offset++];
    if (offset + session_id_len > payload.size()) return std::nullopt;
    if (session_id_len > 0) {
        hello.session_id.assign(payload.data() + offset, payload.data() + offset + session_id_len);
        offset += session_id_len;
    }

    if (offset + 2 > payload.size()) return std::nullopt;
    uint16_t cipher_len_raw;
    std::memcpy(&cipher_len_raw, payload.data() + offset, 2);
    const uint16_t cipher_len = ntoh16(cipher_len_raw);
    offset += 2;

    if (offset + cipher_len > payload.size()) return std::nullopt;
    for (size_t i = 0; i < cipher_len; i += 2) {
        uint16_t cipher;
        std::memcpy(&cipher, payload.data() + offset + i, 2);
        hello.cipher_suites.push_back(ntoh16(cipher));
    }
    offset += cipher_len;

    if (offset >= payload.size()) return std::nullopt;
    const uint8_t comp_len = payload[offset++];
    if (offset + comp_len > payload.size()) return std::nullopt;
    hello.compression_methods.assign(payload.data() + offset, payload.data() + offset + comp_len);
    offset += comp_len;

    if (offset + 2 <= payload.size()) {
        uint16_t ext_total_len_raw;
        std::memcpy(&ext_total_len_raw, payload.data() + offset, 2);
        const uint16_t ext_total_len = ntoh16(ext_total_len_raw);
        offset += 2;

        const size_t ext_end = std::min(payload.size(), offset + ext_total_len);

        while (offset + 4 <= ext_end) {
            uint16_t ext_type_raw, ext_data_len_raw;
            std::memcpy(&ext_type_raw, payload.data() + offset, 2);
            std::memcpy(&ext_data_len_raw, payload.data() + offset + 2, 2);
            const uint16_t ext_type = ntoh16(ext_type_raw);
            const uint16_t ext_data_len = ntoh16(ext_data_len_raw);
            offset += 4;

            if (offset + ext_data_len > ext_end) {
                break;
            }

            hello.extension_types.push_back(ext_type);
            const uint8_t* ext_ptr = payload.data() + offset;

            switch (ext_type) {
                case tls_extension::SERVER_NAME: {
                    if (ext_data_len >= 5) {
                        uint16_t name_list_len_raw;
                        std::memcpy(&name_list_len_raw, ext_ptr, 2);
                        const uint8_t name_type = ext_ptr[2];
                        if (name_type == 0) {
                            uint16_t name_len_raw;
                            std::memcpy(&name_len_raw, ext_ptr + 3, 2);
                            const uint16_t name_len = ntoh16(name_len_raw);
                            if (5 + name_len <= ext_data_len) {
                                hello.sni.assign(reinterpret_cast<const char*>(ext_ptr + 5), name_len);
                            }
                        }
                    }
                    break;
                }
                case tls_extension::ALPN: {
                    if (ext_data_len >= 2) {
                        uint16_t alpn_list_len_raw;
                        std::memcpy(&alpn_list_len_raw, ext_ptr, 2);
                        size_t a_idx = 2;
                        while (a_idx < ext_data_len) {
                            uint8_t proto_len = ext_ptr[a_idx++];
                            if (a_idx + proto_len <= ext_data_len) {
                                hello.alpn.emplace_back(reinterpret_cast<const char*>(ext_ptr + a_idx), proto_len);
                                a_idx += proto_len;
                            } else {
                                break;
                            }
                        }
                    }
                    break;
                }
                case tls_extension::SUPPORTED_GROUPS: {
                    if (ext_data_len >= 2) {
                        uint16_t groups_len_raw;
                        std::memcpy(&groups_len_raw, ext_ptr, 2);
                        const uint16_t groups_len = ntoh16(groups_len_raw);
                        for (size_t g = 0; g + 1 < groups_len && 2 + g + 1 < ext_data_len; g += 2) {
                            uint16_t group;
                            std::memcpy(&group, ext_ptr + 2 + g, 2);
                            hello.supported_groups.push_back(ntoh16(group));
                        }
                    }
                    break;
                }
                case tls_extension::EC_POINT_FORMATS: {
                    if (ext_data_len >= 1) {
                        uint8_t formats_len = ext_ptr[0];
                        for (size_t f = 0; f < formats_len && 1 + f < ext_data_len; ++f) {
                            hello.ec_point_formats.push_back(ext_ptr[1 + f]);
                        }
                    }
                    break;
                }
                case tls_extension::SIGNATURE_ALGORITHMS: {
                    if (ext_data_len >= 2) {
                        uint16_t sig_len_raw;
                        std::memcpy(&sig_len_raw, ext_ptr, 2);
                        const uint16_t sig_len = ntoh16(sig_len_raw);
                        for (size_t s = 0; s + 1 < sig_len && 2 + s + 1 < ext_data_len; s += 2) {
                            uint16_t sig;
                            std::memcpy(&sig, ext_ptr + 2 + s, 2);
                            hello.signature_algorithms.push_back(ntoh16(sig));
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            offset += ext_data_len;
        }
    }

    std::ostringstream ja3;
    ja3 << hello.client_version << ",";

    bool first = true;
    for (uint16_t c : hello.cipher_suites) {
        if (!is_grease(c)) {
            if (!first) ja3 << "-";
            ja3 << c;
            first = false;
        }
    }
    ja3 << ",";

    first = true;
    for (uint16_t e : hello.extension_types) {
        if (!is_grease(e)) {
            if (!first) ja3 << "-";
            ja3 << e;
            first = false;
        }
    }
    ja3 << ",";

    first = true;
    for (uint16_t g : hello.supported_groups) {
        if (!is_grease(g)) {
            if (!first) ja3 << "-";
            ja3 << g;
            first = false;
        }
    }
    ja3 << ",";

    first = true;
    for (uint8_t f : hello.ec_point_formats) {
        if (!first) ja3 << "-";
        ja3 << static_cast<unsigned>(f);
        first = false;
    }

    hello.ja3_string = ja3.str();
    hello.ja3_hash = compute_md5_hex(hello.ja3_string);

    return hello;
}

}
