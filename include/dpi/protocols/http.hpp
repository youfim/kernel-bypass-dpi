#pragma once

#include <string_view>
#include <string>
#include <span>
#include <vector>
#include <cstdint>
#include <optional>

namespace dpi::protocols {

enum class HttpMethod {
    UNKNOWN = 0,
    GET,
    POST,
    HEAD,
    PUT,
    DELETE,
    OPTIONS,
    CONNECT,
    TRACE,
    PATCH
};

struct HttpHeader {
    std::string_view name;
    std::string_view value;
};

struct HttpRequest {
    HttpMethod                method{HttpMethod::UNKNOWN};
    std::string_view          uri;
    std::string_view          version;
    std::string_view          host;
    std::string_view          user_agent;
    std::string_view          content_type;
    uint64_t                  content_length{0};
    std::vector<HttpHeader>   headers;
    std::span<const uint8_t>  body;

    [[nodiscard]] std::string_view method_string() const noexcept {
        switch (method) {
            case HttpMethod::GET:     return "GET";
            case HttpMethod::POST:    return "POST";
            case HttpMethod::HEAD:    return "HEAD";
            case HttpMethod::PUT:     return "PUT";
            case HttpMethod::DELETE:  return "DELETE";
            case HttpMethod::OPTIONS: return "OPTIONS";
            case HttpMethod::CONNECT: return "CONNECT";
            case HttpMethod::TRACE:   return "TRACE";
            case HttpMethod::PATCH:   return "PATCH";
            default:                  return "UNKNOWN";
        }
    }
};

std::optional<HttpRequest> parse_http_request(std::span<const uint8_t> payload);

}
