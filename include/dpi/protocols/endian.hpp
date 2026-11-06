#pragma once

#include <cstdint>
#include <bit>

#if defined(_MSC_VER)
#include <stdlib.h>
#endif

namespace dpi::protocols {

[[nodiscard]] constexpr bool is_little_endian() noexcept {
    return std::endian::native == std::endian::little;
}

[[nodiscard]] inline uint16_t bswap16(uint16_t val) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ushort(val);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(val);
#else
    return static_cast<uint16_t>((val << 8) | (val >> 8));
#endif
}

[[nodiscard]] inline uint32_t bswap32(uint32_t val) noexcept {
#if defined(_MSC_VER)
    return _byteswap_ulong(val);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(val);
#else
    return ((val & 0x000000FFU) << 24) |
           ((val & 0x0000FF00U) << 8)  |
           ((val & 0x00FF0000U) >> 8)  |
           ((val & 0xFF000000U) >> 24);
#endif
}

[[nodiscard]] inline uint64_t bswap64(uint64_t val) noexcept {
#if defined(_MSC_VER)
    return _byteswap_uint64(val);
#elif defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(val);
#else
    val = ((val & 0x00000000FFFFFFFFULL) << 32) | ((val & 0xFFFFFFFF00000000ULL) >> 32);
    val = ((val & 0x0000FFFF0000FFFFULL) << 16) | ((val & 0xFFFF0000FFFF0000ULL) >> 16);
    val = ((val & 0x00FF00FF00FF00FFULL) << 8)  | ((val & 0xFF00FF00FF00FF00ULL) >> 8);
    return val;
#endif
}

[[nodiscard]] inline uint16_t ntoh16(uint16_t val) noexcept {
    return is_little_endian() ? bswap16(val) : val;
}

[[nodiscard]] inline uint32_t ntoh32(uint32_t val) noexcept {
    return is_little_endian() ? bswap32(val) : val;
}

[[nodiscard]] inline uint64_t ntoh64(uint64_t val) noexcept {
    return is_little_endian() ? bswap64(val) : val;
}

[[nodiscard]] inline uint16_t hton16(uint16_t val) noexcept {
    return is_little_endian() ? bswap16(val) : val;
}

[[nodiscard]] inline uint32_t hton32(uint32_t val) noexcept {
    return is_little_endian() ? bswap32(val) : val;
}

[[nodiscard]] inline uint64_t hton64(uint64_t val) noexcept {
    return is_little_endian() ? bswap64(val) : val;
}

}
