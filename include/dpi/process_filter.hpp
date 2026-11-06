#pragma once

#include "process_resolver.hpp"
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace dpi {

namespace detail {
inline std::string to_lower(std::string_view s) {
    std::string res;
    res.reserve(s.size());
    for (char c : s) {
        res.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return res;
}
} // namespace detail

class ProcessFilter {
public:
    ProcessFilter() = default;

    // Inclusion rules (if any is specified, match requires matching at least one)
    ProcessFilter& include_app(std::string_view exe_name) {
        included_apps_.push_back(detail::to_lower(exe_name));
        return *this;
    }

    ProcessFilter& include_pid(uint32_t pid) {
        included_pids_.push_back(pid);
        return *this;
    }

    ProcessFilter& include_path_contains(std::string_view substr) {
        included_path_substrings_.push_back(detail::to_lower(substr));
        return *this;
    }

    // Exclusion rules (if any matches, rejected)
    ProcessFilter& exclude_app(std::string_view exe_name) {
        excluded_apps_.push_back(detail::to_lower(exe_name));
        return *this;
    }

    ProcessFilter& exclude_pid(uint32_t pid) {
        excluded_pids_.push_back(pid);
        return *this;
    }

    [[nodiscard]] bool matches(const ProcessInfo& proc) const {
        if (!proc.is_valid()) {
            // If no process filter is configured, allow unknown processes
            return included_apps_.empty() && included_pids_.empty() && included_path_substrings_.empty();
        }

        // 1. Check exclusions first
        for (uint32_t ex_pid : excluded_pids_) {
            if (proc.pid == ex_pid) return false;
        }

        const std::string lower_name = detail::to_lower(proc.name);
        for (const auto& ex_app : excluded_apps_) {
            if (lower_name == ex_app) return false;
            if (ex_app.find('.') == std::string::npos && (lower_name == ex_app + ".exe")) return false;
        }

        // 2. Check inclusions (if empty, matches everything not excluded)
        const bool has_inclusions = !included_apps_.empty() || !included_pids_.empty() || !included_path_substrings_.empty();
        if (!has_inclusions) {
            return true;
        }

        for (uint32_t in_pid : included_pids_) {
            if (proc.pid == in_pid) return true;
        }

        for (const auto& in_app : included_apps_) {
            if (lower_name == in_app) return true;
            if (in_app.find('.') == std::string::npos && (lower_name == in_app + ".exe")) return true;
        }

        if (!included_path_substrings_.empty() && !proc.path.empty()) {
            const std::string lower_path = detail::to_lower(proc.path);
            for (const auto& sub : included_path_substrings_) {
                if (lower_path.find(sub) != std::string::npos) return true;
            }
        }

        return false;
    }

    [[nodiscard]] bool has_rules() const noexcept {
        return !included_apps_.empty() || !included_pids_.empty() ||
               !included_path_substrings_.empty() || !excluded_apps_.empty() ||
               !excluded_pids_.empty();
    }

private:
    std::vector<std::string> included_apps_;
    std::vector<uint32_t>    included_pids_;
    std::vector<std::string> included_path_substrings_;

    std::vector<std::string> excluded_apps_;
    std::vector<uint32_t>    excluded_pids_;
};

} // namespace dpi
