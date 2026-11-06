#include "dpi/protocols/http.hpp"
#include <algorithm>
#include <cctype>

namespace dpi::protocols {

namespace {

inline bool case_insensitive_equals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

}

std::optional<HttpRequest> parse_http_request(std::span<const uint8_t> payload) {
    if (payload.size() < 10) {
        return std::nullopt;
    }

    std::string_view text(reinterpret_cast<const char*>(payload.data()), payload.size());

    size_t line_end = text.find("\r\n");
    if (line_end == std::string_view::npos) {
        return std::nullopt;
    }

    std::string_view req_line = text.substr(0, line_end);

    size_t sp1 = req_line.find(' ');
    if (sp1 == std::string_view::npos) {
        return std::nullopt;
    }

    std::string_view method_str = req_line.substr(0, sp1);
    HttpRequest req;

    if (method_str == "GET") req.method = HttpMethod::GET;
    else if (method_str == "POST") req.method = HttpMethod::POST;
    else if (method_str == "HEAD") req.method = HttpMethod::HEAD;
    else if (method_str == "PUT") req.method = HttpMethod::PUT;
    else if (method_str == "DELETE") req.method = HttpMethod::DELETE;
    else if (method_str == "OPTIONS") req.method = HttpMethod::OPTIONS;
    else if (method_str == "CONNECT") req.method = HttpMethod::CONNECT;
    else if (method_str == "TRACE") req.method = HttpMethod::TRACE;
    else if (method_str == "PATCH") req.method = HttpMethod::PATCH;
    else {
        return std::nullopt;
    }

    size_t sp2 = req_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) {
        req.uri = req_line.substr(sp1 + 1);
        req.version = "HTTP/1.0";
    } else {
        req.uri = req_line.substr(sp1 + 1, sp2 - (sp1 + 1));
        req.version = req_line.substr(sp2 + 1);
    }

    size_t cur = line_end + 2;
    while (cur < text.size()) {
        size_t next_line = text.find("\r\n", cur);
        if (next_line == std::string_view::npos) {
            break;
        }

        if (next_line == cur) {
            cur += 2;
            if (cur < text.size()) {
                req.body = payload.subspan(cur);
            }
            break;
        }

        std::string_view header_line = text.substr(cur, next_line - cur);
        size_t colon = header_line.find(':');
        if (colon != std::string_view::npos) {
            std::string_view name = header_line.substr(0, colon);
            size_t val_start = colon + 1;
            while (val_start < header_line.size() && (header_line[val_start] == ' ' || header_line[val_start] == '\t')) {
                val_start++;
            }
            std::string_view value = header_line.substr(val_start);

            req.headers.push_back(HttpHeader{name, value});

            if (case_insensitive_equals(name, "Host")) {
                req.host = value;
            } else if (case_insensitive_equals(name, "User-Agent")) {
                req.user_agent = value;
            } else if (case_insensitive_equals(name, "Content-Type")) {
                req.content_type = value;
            } else if (case_insensitive_equals(name, "Content-Length")) {
                try {
                    req.content_length = std::stoull(std::string(value));
                } catch (...) {
                    req.content_length = 0;
                }
            }
        }
        cur = next_line + 2;
    }

    return req;
}

}
