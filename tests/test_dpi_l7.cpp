#include "dpi/protocols/tls.hpp"
#include "dpi/protocols/dns.hpp"
#include "dpi/protocols/http.hpp"
#include <iostream>
#include <cassert>
#include <vector>

void test_tls_client_hello() {
    std::cout << "[Test] Running TLS ClientHello DPI decoder test..." << std::endl;

    std::vector<uint8_t> tls_raw = {

        0x16, 0x03, 0x01, 0x00, 0x4e,

        0x01, 0x00, 0x00, 0x4a,

        0x03, 0x03,

        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,

        0x00,

        0x00, 0x04,
        0x13, 0x01,
        0xc0, 0x2f,

        0x01, 0x00,

        0x00, 0x1d,

        0x00, 0x00, 0x00, 0x10,

        0x00, 0x0e,

        0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',

        0x00, 0x0a, 0x00, 0x04,
        0x00, 0x02, 0x00, 0x1d
    };

    auto hello = dpi::protocols::parse_tls_client_hello(tls_raw);
    assert(hello.has_value());
    assert(hello->client_version == 0x0303);
    assert(hello->sni == "example.com");
    assert(hello->cipher_suites.size() == 2);
    assert(hello->supported_groups.size() == 1);
    assert(hello->supported_groups[0] == 0x001d);
    assert(!hello->ja3_string.empty());
    assert(!hello->ja3_hash.empty());
    assert(hello->ja3_hash.size() == 32);

    std::cout << "  -> Extracted SNI: " << hello->sni << std::endl;
    std::cout << "  -> JA3 Fingerprint: " << hello->ja3_hash << " (" << hello->ja3_string << ")" << std::endl;
}

void test_dns_parser() {
    std::cout << "[Test] Running DNS Query/Answer DPI decoder test..." << std::endl;

    std::vector<uint8_t> dns_raw = {
        0x12, 0x34,
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,

        6, 'g', 'o', 'o', 'g', 'l', 'e',
        3, 'c', 'o', 'm',
        0,
        0x00, 0x01,
        0x00, 0x01,

        0xc0, 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,
        142, 250, 180, 206
    };

    auto dns = dpi::protocols::parse_dns_message(dns_raw);
    assert(dns.has_value());
    assert(dns->transaction_id == 0x1234);
    assert(dns->is_response);
    assert(dns->questions.size() == 1);
    assert(dns->questions[0].name == "google.com");
    assert(dns->questions[0].qtype == dpi::protocols::dns_type::A);

    assert(dns->answers.size() == 1);
    assert(dns->answers[0].name == "google.com");
    assert(dns->answers[0].data == "142.250.180.206");

    std::cout << "  -> Decompressed QNAME: " << dns->questions[0].name << std::endl;
    std::cout << "  -> Resolved Answer IP: " << dns->answers[0].data << std::endl;
}

void test_http_parser() {
    std::cout << "[Test] Running HTTP/1.1 scanner test..." << std::endl;

    std::string http_text =
        "GET /api/v1/telemetry?node=42 HTTP/1.1\r\n"
        "Host: api.cluster.local\r\n"
        "User-Agent: KernelDPI-Agent/1.0\r\n"
        "Accept: application/json\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    std::span<const uint8_t> span(reinterpret_cast<const uint8_t*>(http_text.data()), http_text.size());
    auto req = dpi::protocols::parse_http_request(span);

    assert(req.has_value());
    assert(req->method == dpi::protocols::HttpMethod::GET);
    assert(req->uri == "/api/v1/telemetry?node=42");
    assert(req->host == "api.cluster.local");
    assert(req->user_agent == "KernelDPI-Agent/1.0");
    assert(req->content_length == 0);

    std::cout << "  -> Method: " << req->method_string() << ", URI: " << req->uri << std::endl;
    std::cout << "  -> Host: " << req->host << ", User-Agent: " << req->user_agent << std::endl;
}

int main() {
    test_tls_client_hello();
    test_dns_parser();
    test_http_parser();
    std::cout << "[All L7 DPI Tests Passed Cleanly]" << std::endl;
    return 0;
}
