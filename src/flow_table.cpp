#include "dpi/flow_table.hpp"
#include <sstream>
#include <algorithm>

namespace dpi {

std::pair<FlowKey, FlowDirection> FlowKey::from_packet(const ParsedPacket& pkt) noexcept {
    FlowKey key{};

    if (pkt.l3_proto == L3Protocol::IPV4 && pkt.ipv4) {
        key.is_ipv6 = false;
        std::memcpy(key.src_ip, pkt.ipv4->src_ip.bytes, 4);
        std::memcpy(key.dst_ip, pkt.ipv4->dst_ip.bytes, 4);
        key.protocol = pkt.ipv4->protocol;
    } else if (pkt.l3_proto == L3Protocol::IPV6 && pkt.ipv6) {
        key.is_ipv6 = true;
        std::memcpy(key.src_ip, pkt.ipv6->src_ip.bytes, 16);
        std::memcpy(key.dst_ip, pkt.ipv6->dst_ip.bytes, 16);
        key.protocol = pkt.ipv6->next_header;
    } else {
        return {key, FlowDirection::FORWARD};
    }

    key.src_port = pkt.src_port();
    key.dst_port = pkt.dst_port();

    // Canonical ordering: min(src_endpoint, dst_endpoint)
    const size_t ip_len = key.is_ipv6 ? 16 : 4;
    int cmp = std::memcmp(key.src_ip, key.dst_ip, ip_len);
    if (cmp == 0) {
        if (key.src_port < key.dst_port) cmp = -1;
        else if (key.src_port > key.dst_port) cmp = 1;
    }

    if (cmp <= 0) {
        return {key, FlowDirection::FORWARD};
    } else {
        // Swap endpoints to normalize
        FlowKey canonical = key;
        std::swap_ranges(canonical.src_ip, canonical.src_ip + 16, canonical.dst_ip);
        std::swap(canonical.src_port, canonical.dst_port);
        return {canonical, FlowDirection::REVERSE};
    }
}

std::string FlowKey::to_string() const {
    std::ostringstream ss;
    if (is_ipv6) {
        protocols::Ipv6Address src{}, dst{};
        std::memcpy(src.bytes, src_ip, 16);
        std::memcpy(dst.bytes, dst_ip, 16);
        ss << "[" << src.to_string() << "]:" << src_port << " <-> [" << dst.to_string() << "]:" << dst_port;
    } else {
        protocols::Ipv4Address src{}, dst{};
        std::memcpy(src.bytes, src_ip, 4);
        std::memcpy(dst.bytes, dst_ip, 4);
        ss << src.to_string() << ":" << src_port << " <-> " << dst.to_string() << ":" << dst_port;
    }
    ss << " (" << (protocol == 6 ? "TCP" : (protocol == 17 ? "UDP" : std::to_string(protocol))) << ")";
    return ss.str();
}

FlowTable::FlowTable(size_t /*bucket_count*/, size_t num_stripes)
    : num_stripes_(num_stripes > 0 ? num_stripes : 64),
      stripes_(num_stripes_) {}

std::shared_ptr<FlowRecord> FlowTable::process_packet(const ParsedPacket& pkt, FlowDirection& out_dir) {
    if (!pkt.is_valid()) {
        return nullptr;
    }

    auto [key, dir] = FlowKey::from_packet(pkt);
    out_dir = dir;

    const size_t stripe_idx = key.hash() % num_stripes_;
    auto& stripe = stripes_[stripe_idx];

    std::shared_ptr<FlowRecord> record;
    {
        std::lock_guard<std::mutex> lock(stripe.mutex);
        for (auto& entry : stripe.entries) {
            if (entry.key == key) {
                record = entry.record;
                break;
            }
        }

        if (!record) {
            record = std::make_shared<FlowRecord>(key, pkt.timestamp_ns);
            ProcessInfo pinfo = ProcessResolver::instance().resolve(pkt.src_port(), key.protocol, key.is_ipv6 != 0);
            if (!pinfo.is_valid()) {
                pinfo = ProcessResolver::instance().resolve(pkt.dst_port(), key.protocol, key.is_ipv6 != 0);
            }
            record->process = std::move(pinfo);
            stripe.entries.push_back(BucketEntry{key, record});
        } else if (!record->process.is_valid()) {
            ProcessInfo pinfo = ProcessResolver::instance().resolve(pkt.src_port(), key.protocol, key.is_ipv6 != 0);
            if (!pinfo.is_valid()) {
                pinfo = ProcessResolver::instance().resolve(pkt.dst_port(), key.protocol, key.is_ipv6 != 0);
            }
            if (pinfo.is_valid()) {
                record->process = std::move(pinfo);
            }
        }
    }

    // Update statistics without holding the stripe lock
    record->last_seen_ns.store(pkt.timestamp_ns, std::memory_order_relaxed);
    const uint64_t bytes = pkt.raw_data.size();

    if (dir == FlowDirection::FORWARD) {
        record->fwd_packets.fetch_add(1, std::memory_order_relaxed);
        record->fwd_bytes.fetch_add(bytes, std::memory_order_relaxed);
    } else {
        record->rev_packets.fetch_add(1, std::memory_order_relaxed);
        record->rev_bytes.fetch_add(bytes, std::memory_order_relaxed);
    }

    // Advance TCP State
    if (pkt.is_tcp() && pkt.tcp) {
        const auto* tcp = pkt.tcp;
        TcpState current_state = record->tcp_state.load(std::memory_order_relaxed);

        if (tcp->rst()) {
            record->tcp_state.store(TcpState::RESET, std::memory_order_relaxed);
        } else if (tcp->fin()) {
            record->tcp_state.store(TcpState::FIN_WAIT, std::memory_order_relaxed);
        } else if (tcp->syn() && !tcp->ack()) {
            record->tcp_state.store(TcpState::SYN_SENT, std::memory_order_relaxed);
        } else if (tcp->syn() && tcp->ack()) {
            record->tcp_state.store(TcpState::SYN_RECEIVED, std::memory_order_relaxed);
        } else if (current_state == TcpState::SYN_RECEIVED || current_state == TcpState::SYN_SENT) {
            if (tcp->ack()) {
                record->tcp_state.store(TcpState::ESTABLISHED, std::memory_order_relaxed);
            }
        }
    }

    return record;
}

size_t FlowTable::evict_expired(uint64_t current_time_ns,
                                uint64_t tcp_timeout_ns,
                                uint64_t udp_timeout_ns) {
    size_t evicted_count = 0;

    for (auto& stripe : stripes_) {
        std::lock_guard<std::mutex> lock(stripe.mutex);
        auto it = stripe.entries.begin();
        while (it != stripe.entries.end()) {
            const auto& rec = it->record;
            const uint64_t last_seen = rec->last_seen_ns.load(std::memory_order_relaxed);
            const uint64_t age_ns = (current_time_ns >= last_seen) ? (current_time_ns - last_seen) : 0;

            bool expire = false;
            if (it->key.protocol == 6) { // TCP
                const TcpState st = rec->tcp_state.load(std::memory_order_relaxed);
                if (st == TcpState::CLOSED || st == TcpState::RESET) {
                    expire = (age_ns >= 10ULL * 1'000'000'000ULL); // 10s for closed/reset
                } else {
                    expire = (age_ns >= tcp_timeout_ns);
                }
            } else { // UDP / other
                expire = (age_ns >= udp_timeout_ns);
            }

            if (expire) {
                it = stripe.entries.erase(it);
                ++evicted_count;
            } else {
                ++it;
            }
        }
    }

    return evicted_count;
}

size_t FlowTable::active_flows() const noexcept {
    size_t count = 0;
    for (const auto& stripe : stripes_) {
        std::lock_guard<std::mutex> lock(stripe.mutex);
        count += stripe.entries.size();
    }
    return count;
}

void FlowTable::for_each_flow(const std::function<void(const std::shared_ptr<FlowRecord>&)>& callback) {
    for (auto& stripe : stripes_) {
        std::vector<std::shared_ptr<FlowRecord>> snapshot;
        {
            std::lock_guard<std::mutex> lock(stripe.mutex);
            snapshot.reserve(stripe.entries.size());
            for (const auto& entry : stripe.entries) {
                snapshot.push_back(entry.record);
            }
        }
        for (const auto& rec : snapshot) {
            callback(rec);
        }
    }
}

} // namespace dpi
