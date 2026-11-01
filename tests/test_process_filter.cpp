#include "dpi/process_resolver.hpp"
#include "dpi/process_filter.hpp"
#include <iostream>
#include <cassert>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

void test_process_filter_rules() {
    std::cout << "[Test] Running ProcessFilter rule matching tests..." << std::endl;

    dpi::ProcessInfo chrome{1001, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"};
    dpi::ProcessInfo telegram{2002, "telegram.exe", "C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\telegram.exe"};
    dpi::ProcessInfo discord{3003, "Discord.exe", "C:\\Users\\User\\AppData\\Local\\Discord\\app-1.0.9000\\Discord.exe"};
    dpi::ProcessInfo svchost{4004, "svchost.exe", "C:\\Windows\\System32\\svchost.exe"};

    // 1. App name inclusion (case-insensitive)
    dpi::ProcessFilter f1;
    f1.include_app("Chrome.EXE");
    assert(f1.matches(chrome));
    assert(!f1.matches(telegram));

    // 2. PID inclusion
    dpi::ProcessFilter f2;
    f2.include_pid(2002);
    assert(f2.matches(telegram));
    assert(!f2.matches(chrome));

    // 3. Path substring inclusion
    dpi::ProcessFilter f3;
    f3.include_path_contains("discord");
    assert(f3.matches(discord));
    assert(!f3.matches(chrome));

    // 4. Exclusion overrides
    dpi::ProcessFilter f4;
    f4.exclude_app("svchost.exe");
    assert(!f4.matches(svchost));
    assert(f4.matches(chrome));

    std::cout << "  -> Passed." << std::endl;
}

void test_current_process_resolution() {
    std::cout << "[Test] Running current process resolution via ProcessResolver..." << std::endl;

#if defined(_WIN32)
    uint32_t current_pid = GetCurrentProcessId();
    auto info = dpi::ProcessResolver::query_process_by_pid(current_pid);
    assert(info.is_valid());
    assert(info.pid == current_pid);
    assert(!info.name.empty());
    std::cout << "  -> Resolved Current Process: " << info.name << " (PID: " << info.pid << ")" << std::endl;
#else
    std::cout << "  -> Skipped on non-Windows." << std::endl;
#endif
    std::cout << "  -> Passed." << std::endl;
}

int main() {
    test_process_filter_rules();
    test_current_process_resolution();
    std::cout << "[All Process Filter Tests Passed Cleanly]" << std::endl;
    return 0;
}
