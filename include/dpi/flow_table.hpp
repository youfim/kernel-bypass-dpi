#pragma once

#include "packet.hpp"
#include "protocols/tls.hpp"
#include "protocols/dns.hpp"
#include "protocols/http.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <vector>
#include <functional>
#include <optional>

namespace dpi {

enum class FlowDirection : uint8_t {
    FORWARD = 0,
    REVERSE = 1
};

enum class TcpState : uint8_t {
    NONE = 0,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED,
    RESET
};

#pragma pack(push, 1)
struct FlowKey {
    uint8_t  src_ip[16]{};
    uint8_t  dst_ip[16]{};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  protocol{0};
    uint8_t  is_ipv6{0};

    [[nodiscard]] bool operator==(const FlowKey& other) const noexcept {
        return std::memcmp(this, &other, sizeof(FlowKey)) == 0;
    }

    [[nodiscard]] uint64_t hash() const noexcept {
        uint64_t h = 14695981039346656037ULL;
        const auto* ptr = reinterpret_cast<const uint8_t*>(this);
        for (size_t i = 0; i < sizeof(FlowKey); ++i) {
            h ^= ptr[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    // Creates canonical representation and returns whether original was forward or reverse
    static std::pair<FlowKey, FlowDirection> from_packet(const ParsedPacket& pkt) noexcept;

    [[nodiscard]] std::string to_string() const;
};
#pragma pack(pop)
static_assert(sizeof(FlowKey) == 38, "FlowKey must be packed to 38 bytes");

struct FlowRecord {
    FlowKey key;
    uint64_t start_time_ns{0};
    std::atomic<uint64_t> last_seen_ns{0};

    // Counters
    std::atomic<uint64_t> fwd_packets{0};
    std::atomic<uint64_t> fwd_bytes{0};
    std::atomic<uint64_t> rev_packets{0};
    std::atomic<uint64_t> rev_bytes{0};

    // TCP State
    std::atomic<TcpState> tcp_state{TcpState::NONE};

    // L7 Metadata
    std::mutex l7_mutex;
    std::optional<protocols::TlsClientHello> tls_meta;
    std::optional<protocols::DnsMessage>    dns_meta;
    std::string                             http_host;
    std::string                             http_uri;
    std::string                             http_method;
    std::string                             http_user_agent;

    FlowRecord(const FlowKey& k, uint64_t ts)
        : key(k), start_time_ns(ts), last_seen_ns(ts) {}
};

class FlowTable {
public:
    explicit FlowTable(size_t bucket_count = 65536, size_t num_stripes = 64);
    ~FlowTable() = default;

    // Process a packet: lookup or insert flow, update counters, handle TCP state
    std::shared_ptr<FlowRecord> process_packet(const ParsedPacket& pkt, FlowDirection& out_dir);

    // Evict flows that exceeded idle timeouts
    size_t evict_expired(uint64_t current_time_ns,
                         uint64_t tcp_timeout_ns = 300ULL * 1'000'000'000ULL,
                         uint64_t udp_timeout_ns = 30ULL * 1'000'000'000ULL);

    [[nodiscard]] size_t active_flows() const noexcept;

    void for_each_flow(const std::function<void(const std::shared_ptr<FlowRecord>&)>& callback);

private:
    struct BucketEntry {
        FlowKey key;
        std::shared_ptr<FlowRecord> record;
    };

    struct Stripe {
        mutable std::mutex mutex;
        std::vector<BucketEntry> entries;
    };

    size_t num_stripes_;
    std::vector<Stripe> stripes_;
};

} // namespace dpi
