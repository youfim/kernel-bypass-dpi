#pragma once

#include "packet.hpp"
#include <span>

namespace dpi {

class PacketParser {
public:

    static bool parse(std::span<const uint8_t> raw_bytes,
                      uint64_t timestamp_ns,
                      ParsedPacket& out_packet) noexcept;
};

}
