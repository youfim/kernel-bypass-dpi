#pragma once

#include "packet.hpp"
#include <span>

namespace dpi {

class PacketParser {
public:
    // Zero-copy parse function: overlays protocol structs on top of raw_bytes
    static bool parse(std::span<const uint8_t> raw_bytes,
                      uint64_t timestamp_ns,
                      ParsedPacket& out_packet) noexcept;
};

} // namespace dpi
