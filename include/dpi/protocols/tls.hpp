#pragma once

#include "endian.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <span>
#include <optional>

namespace dpi::protocols {

#pragma pack(push, 1)

struct TlsRecordHeader {
    uint8_t  content_type; // 22 = Handshake, 20 = ChangeCipherSpec, 21 = Alert, 23 = ApplicationData
    uint16_t legacy_version;
    uint16_t length;

    [[nodiscard]] uint16_t version() const noexcept { return ntoh16(legacy_version); }
    [[nodiscard]] uint16_t payload_length() const noexcept { return ntoh16(length); }
    [[nodiscard]] bool is_handshake() const noexcept { return content_type == 22; }
};

struct TlsHandshakeHeader {
    uint8_t  msg_type; // 1 = ClientHello, 2 = ServerHello, etc.
    uint8_t  length_high;
    uint16_t length_low;

    [[nodiscard]] uint32_t length() const noexcept {
        return (static_cast<uint32_t>(length_high) << 16) | ntoh16(length_low);
    }
    [[nodiscard]] bool is_client_hello() const noexcept { return msg_type == 1; }
    [[nodiscard]] bool is_server_hello() const noexcept { return msg_type == 2; }
};

#pragma pack(pop)

static_assert(sizeof(TlsRecordHeader) == 5, "TlsRecordHeader must be exactly 5 bytes");
static_assert(sizeof(TlsHandshakeHeader) == 4, "TlsHandshakeHeader must be exactly 4 bytes");

struct TlsClientHello {
    uint16_t              client_version{0};
    uint8_t               random[32]{};
    std::vector<uint8_t>  session_id;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint8_t>  compression_methods;

    // Extracted Extensions
    std::string           sni;
    std::vector<std::string> alpn;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t>  ec_point_formats;
    std::vector<uint16_t> signature_algorithms;
    std::vector<uint16_t> extension_types;

    // Fingerprints
    std::string ja3_string;
    std::string ja3_hash; // MD5 digest
    std::string ja4_string;
};

namespace tls_extension {
    constexpr uint16_t SERVER_NAME            = 0x0000;
    constexpr uint16_t MAX_FRAGMENT_LENGTH    = 0x0001;
    constexpr uint16_t STATUS_REQUEST         = 0x0005;
    constexpr uint16_t SUPPORTED_GROUPS       = 0x000A;
    constexpr uint16_t EC_POINT_FORMATS       = 0x000B;
    constexpr uint16_t SIGNATURE_ALGORITHMS   = 0x000D;
    constexpr uint16_t ALPN                   = 0x0010;
    constexpr uint16_t SIGNED_CERT_TIMESTAMP  = 0x0012;
    constexpr uint16_t EXTENDED_MASTER_SECRET = 0x0017;
    constexpr uint16_t SESSION_TICKET         = 0x0023;
    constexpr uint16_t SUPPORTED_VERSIONS     = 0x002B;
    constexpr uint16_t KEY_SHARE              = 0x0033;
} // namespace tls_extension

std::optional<TlsClientHello> parse_tls_client_hello(std::span<const uint8_t> payload);

} // namespace dpi::protocols
