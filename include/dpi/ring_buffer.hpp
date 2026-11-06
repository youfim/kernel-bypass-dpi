#pragma once

#include "packet.hpp"
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>
#include <memory>
#include <new>

namespace dpi {

template <typename T, size_t Capacity>
class alignas(64) SpscRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");
    static constexpr size_t MASK = Capacity - 1;

public:
    SpscRingBuffer() : buffer_(std::make_unique<T[]>(Capacity)) {}

    ~SpscRingBuffer() = default;

    SpscRingBuffer(const SpscRingBuffer&) = delete;
    SpscRingBuffer& operator=(const SpscRingBuffer&) = delete;
    SpscRingBuffer(SpscRingBuffer&&) = delete;
    SpscRingBuffer& operator=(SpscRingBuffer&&) = delete;

    [[nodiscard]] constexpr size_t capacity() const noexcept {
        return Capacity;
    }

    [[nodiscard]] size_t size() const noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t tail = tail_.load(std::memory_order_relaxed);
        return (head >= tail) ? (head - tail) : (Capacity - (tail - head));
    }

    [[nodiscard]] bool empty() const noexcept {
        return head_.load(std::memory_order_relaxed) == tail_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] bool full() const noexcept {
        return ((head_.load(std::memory_order_relaxed) + 1) & MASK) ==
                tail_.load(std::memory_order_relaxed);
    }

    template <typename... Args>
    bool try_emplace(Args&&... args) noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t next_head = (current_head + 1) & MASK;

        if (next_head == cached_tail_) {
            cached_tail_ = tail_.load(std::memory_order_acquire);
            if (next_head == cached_tail_) {
                return false;
            }
        }

        new (&buffer_[current_head]) T(std::forward<Args>(args)...);
        head_.store(next_head, std::memory_order_release);
        return true;
    }

    [[nodiscard]] T* claim_write_slot() noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t next_head = (current_head + 1) & MASK;

        if (next_head == cached_tail_) {
            cached_tail_ = tail_.load(std::memory_order_acquire);
            if (next_head == cached_tail_) {
                return nullptr;
            }
        }
        return &buffer_[current_head];
    }

    void commit_write_slot() noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        head_.store((current_head + 1) & MASK, std::memory_order_release);
    }

    bool try_pop(T& out_item) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);

        if (current_tail == cached_head_) {
            cached_head_ = head_.load(std::memory_order_acquire);
            if (current_tail == cached_head_) {
                return false;
            }
        }

        out_item = std::move(buffer_[current_tail]);
        tail_.store((current_tail + 1) & MASK, std::memory_order_release);
        return true;
    }

    [[nodiscard]] const T* peek_read_slot() noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);

        if (current_tail == cached_head_) {
            cached_head_ = head_.load(std::memory_order_acquire);
            if (current_tail == cached_head_) {
                return nullptr;
            }
        }
        return &buffer_[current_tail];
    }

    void commit_read_slot() noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        tail_.store((current_tail + 1) & MASK, std::memory_order_release);
    }

    size_t pop_batch(std::span<T> out_batch) noexcept {
        const size_t max_items = out_batch.size();
        size_t count = 0;

        size_t current_tail = tail_.load(std::memory_order_relaxed);
        size_t available_head = cached_head_;

        if (current_tail == available_head) {
            available_head = head_.load(std::memory_order_acquire);
            cached_head_ = available_head;
        }

        while (current_tail != available_head && count < max_items) {
            out_batch[count++] = std::move(buffer_[current_tail]);
            current_tail = (current_tail + 1) & MASK;
        }

        if (count > 0) {
            tail_.store(current_tail, std::memory_order_release);
        }
        return count;
    }

private:
    std::unique_ptr<T[]> buffer_;

    alignas(64) std::atomic<size_t> head_{0};
    size_t cached_tail_{0};

    alignas(64) std::atomic<size_t> tail_{0};
    size_t cached_head_{0};
};

using PacketRingBuffer = SpscRingBuffer<PacketSlot, 65536>;

}
