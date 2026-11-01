#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/shared_ptr.h>
#include <nanobind/ndarray.h>

#include "dpi/parser.hpp"
#include "dpi/flow_table.hpp"
#include "dpi/capture.hpp"
#include "dpi/protocols/tls.hpp"
#include "dpi/protocols/dns.hpp"
#include "dpi/protocols/http.hpp"

namespace nb = nanobind;
using namespace nb::literals;

struct PyPacketView {
    std::vector<uint8_t> data;
    uint64_t timestamp_ns{0};
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};
    size_t payload_offset{0};
    size_t payload_size{0};
};

class EngineSniffer {
public:
    EngineSniffer() : flow_table_(std::make_unique<dpi::FlowTable>(65536, 64)) {}

    bool open_pcap(const std::string& path) {
        capture_ = dpi::ICaptureDevice::create_pcap(path);
        return capture_->open(path);
    }

    bool open_live(const std::string& filter_or_if) {
#if defined(_WIN32)
        capture_ = dpi::ICaptureDevice::create_windivert();
#else
        capture_ = dpi::ICaptureDevice::create_afxdp();
#endif
        return capture_->open(filter_or_if);
    }

    std::optional<PyPacketView> next_packet() {
        if (!capture_) return std::nullopt;

        dpi::PacketSlot slot{};
        std::span<dpi::PacketSlot> batch(&slot, 1);

        size_t n = 0;
        {
            nb::gil_scoped_release release;
            n = capture_->receive_batch(batch);
        }

        if (n == 0) {
            return std::nullopt;
        }

        dpi::ParsedPacket pkt;
        if (!dpi::PacketParser::parse(std::span<const uint8_t>(slot.data, slot.length), slot.timestamp_ns, pkt)) {
            return std::nullopt;
        }

        dpi::FlowDirection dir;
        auto flow = flow_table_->process_packet(pkt, dir);

        // DPI Inspection on first packet with payload
        if (flow && !pkt.payload.empty()) {
            std::lock_guard<std::mutex> lock(flow->l7_mutex);

            // 1. Try TLS ClientHello
            if (!flow->tls_meta.has_value() && pkt.is_tcp() && (pkt.dst_port() == 443 || pkt.src_port() == 443)) {
                flow->tls_meta = dpi::protocols::parse_tls_client_hello(pkt.payload);
            }

            // 2. Try DNS
            if (!flow->dns_meta.has_value() && pkt.is_udp() && (pkt.dst_port() == 53 || pkt.src_port() == 53)) {
                flow->dns_meta = dpi::protocols::parse_dns_message(pkt.payload);
            }

            // 3. Try HTTP
            if (flow->http_method.empty() && pkt.is_tcp()) {
                auto req = dpi::protocols::parse_http_request(pkt.payload);
                if (req.has_value()) {
                    flow->http_method = std::string(req->method_string());
                    flow->http_uri = std::string(req->uri);
                    flow->http_host = std::string(req->host);
                    flow->http_user_agent = std::string(req->user_agent);
                }
            }
        }

        PyPacketView view;
        view.data.assign(slot.data, slot.data + slot.length);
        view.timestamp_ns = slot.timestamp_ns;

        if (pkt.l3_proto == dpi::L3Protocol::IPV4 && pkt.ipv4) {
            view.src_ip = pkt.ipv4->src_ip.to_string();
            view.dst_ip = pkt.ipv4->dst_ip.to_string();
            view.protocol = pkt.ipv4->protocol;
        } else if (pkt.l3_proto == dpi::L3Protocol::IPV6 && pkt.ipv6) {
            view.src_ip = pkt.ipv6->src_ip.to_string();
            view.dst_ip = pkt.ipv6->dst_ip.to_string();
            view.protocol = pkt.ipv6->next_header;
        }

        view.src_port = pkt.src_port();
        view.dst_port = pkt.dst_port();
        view.payload_offset = pkt.payload_offset;
        view.payload_size = pkt.payload.size();

        return view;
    }

    size_t active_flows() const noexcept {
        return flow_table_->active_flows();
    }

    std::vector<std::shared_ptr<dpi::FlowRecord>> get_flows() {
        std::vector<std::shared_ptr<dpi::FlowRecord>> list;
        flow_table_->for_each_flow([&](const std::shared_ptr<dpi::FlowRecord>& rec) {
            list.push_back(rec);
        });
        return list;
    }

private:
    std::unique_ptr<dpi::ICaptureDevice> capture_;
    std::unique_ptr<dpi::FlowTable> flow_table_;
};

NB_MODULE(_dpi_engine, m) {
    m.doc() = "Kernel-Bypass Network Engine & DPI Streamer";

    nb::class_<dpi::FlowKey>(m, "FlowKey")
        .def_ro("src_port", &dpi::FlowKey::src_port)
        .def_ro("dst_port", &dpi::FlowKey::dst_port)
        .def_ro("protocol", &dpi::FlowKey::protocol)
        .def_ro("is_ipv6", &dpi::FlowKey::is_ipv6)
        .def("__repr__", &dpi::FlowKey::to_string);

    nb::class_<dpi::FlowRecord>(m, "FlowRecord")
        .def_ro("key", &dpi::FlowRecord::key)
        .def_ro("start_time_ns", &dpi::FlowRecord::start_time_ns)
        .def_prop_ro("last_seen_ns", [](const dpi::FlowRecord& r) {
            return r.last_seen_ns.load();
        })
        .def_prop_ro("fwd_packets", [](const dpi::FlowRecord& r) {
            return r.fwd_packets.load();
        })
        .def_prop_ro("fwd_bytes", [](const dpi::FlowRecord& r) {
            return r.fwd_bytes.load();
        })
        .def_prop_ro("rev_packets", [](const dpi::FlowRecord& r) {
            return r.rev_packets.load();
        })
        .def_prop_ro("rev_bytes", [](const dpi::FlowRecord& r) {
            return r.rev_bytes.load();
        })
        .def_prop_ro("sni", [](dpi::FlowRecord& r) -> std::optional<std::string> {
            std::lock_guard<std::mutex> lock(r.l7_mutex);
            if (r.tls_meta.has_value() && !r.tls_meta->sni.empty()) {
                return r.tls_meta->sni;
            }
            return std::nullopt;
        })
        .def_prop_ro("ja3", [](dpi::FlowRecord& r) -> std::optional<std::string> {
            std::lock_guard<std::mutex> lock(r.l7_mutex);
            if (r.tls_meta.has_value() && !r.tls_meta->ja3_hash.empty()) {
                return r.tls_meta->ja3_hash;
            }
            return std::nullopt;
        })
        .def_prop_ro("http_host", [](dpi::FlowRecord& r) -> std::optional<std::string> {
            std::lock_guard<std::mutex> lock(r.l7_mutex);
            return r.http_host.empty() ? std::nullopt : std::make_optional(r.http_host);
        })
        .def_prop_ro("http_uri", [](dpi::FlowRecord& r) -> std::optional<std::string> {
            std::lock_guard<std::mutex> lock(r.l7_mutex);
            return r.http_uri.empty() ? std::nullopt : std::make_optional(r.http_uri);
        })
        .def_prop_ro("http_method", [](dpi::FlowRecord& r) -> std::optional<std::string> {
            std::lock_guard<std::mutex> lock(r.l7_mutex);
            return r.http_method.empty() ? std::nullopt : std::make_optional(r.http_method);
        });

    nb::class_<PyPacketView>(m, "PacketView")
        .def_ro("timestamp_ns", &PyPacketView::timestamp_ns)
        .def_ro("src_ip", &PyPacketView::src_ip)
        .def_ro("dst_ip", &PyPacketView::dst_ip)
        .def_ro("src_port", &PyPacketView::src_port)
        .def_ro("dst_port", &PyPacketView::dst_port)
        .def_ro("protocol", &PyPacketView::protocol)
        .def_prop_ro("raw_bytes", [](PyPacketView& p) {
            return nb::bytes(reinterpret_cast<const char*>(p.data.data()), p.data.size());
        })
        .def_prop_ro("payload", [](PyPacketView& p) {
            if (p.payload_size > 0 && p.payload_offset + p.payload_size <= p.data.size()) {
                return nb::bytes(reinterpret_cast<const char*>(p.data.data() + p.payload_offset), p.payload_size);
            }
            return nb::bytes("", 0);
        });

    nb::class_<EngineSniffer>(m, "Sniffer")
        .def(nb::init<>())
        .def("open_pcap", &EngineSniffer::open_pcap, "path"_a)
        .def("open_live", &EngineSniffer::open_live, "filter"_a = "true")
        .def("next_packet", &EngineSniffer::next_packet)
        .def("active_flows", &EngineSniffer::active_flows)
        .def("get_flows", &EngineSniffer::get_flows);
}
