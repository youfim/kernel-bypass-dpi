#include "dpi/ring_buffer.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <atomic>
#include <chrono>

void test_ring_basic() {
    std::cout << "[Test] Running SPSC Ring Buffer basic push/pop test..." << std::endl;
    dpi::SpscRingBuffer<uint64_t, 8> ring;

    assert(ring.empty());
    assert(!ring.full());

    for (uint64_t i = 1; i <= 7; ++i) {
        bool ok = ring.try_emplace(i);
        assert(ok);
    }
    assert(ring.full());
    assert(!ring.try_emplace(999));

    uint64_t val = 0;
    for (uint64_t i = 1; i <= 7; ++i) {
        bool ok = ring.try_pop(val);
        assert(ok);
        assert(val == i);
    }

    assert(ring.empty());
    std::cout << "  -> Passed." << std::endl;
}

void test_ring_multithreaded_throughput() {
    std::cout << "[Test] Running SPSC Ring Buffer multi-threaded producer/consumer test..." << std::endl;
    constexpr size_t TOTAL_PACKETS = 1'000'000;
    auto ring = std::make_unique<dpi::SpscRingBuffer<dpi::PacketSlot, 16384>>();

    std::atomic<bool> producer_done{false};
    uint64_t consumer_count = 0;
    uint64_t consumer_sum = 0;

    auto t_start = std::chrono::steady_clock::now();

    std::thread producer([&]() {
        for (uint64_t i = 1; i <= TOTAL_PACKETS; ++i) {
            dpi::PacketSlot* slot = nullptr;
            while ((slot = ring->claim_write_slot()) == nullptr) {

                std::this_thread::yield();
            }
            slot->timestamp_ns = i;
            slot->length = 64;
            ring->commit_write_slot();
        }
        producer_done.store(true, std::memory_order_release);
    });

    std::thread consumer([&]() {
        dpi::PacketSlot slot{};
        while (!producer_done.load(std::memory_order_acquire) || !ring->empty()) {
            if (ring->try_pop(slot)) {
                consumer_count++;
                consumer_sum += slot.timestamp_ns;
            } else {
                std::this_thread::yield();
            }
        }
    });

    producer.join();
    consumer.join();

    auto t_end = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration<double>(t_end - t_start).count();
    double mpps = (static_cast<double>(TOTAL_PACKETS) / seconds) / 1'000'000.0;

    assert(consumer_count == TOTAL_PACKETS);
    const uint64_t expected_sum = (TOTAL_PACKETS * (TOTAL_PACKETS + 1)) / 2;
    assert(consumer_sum == expected_sum);

    std::cout << "  -> Processed " << TOTAL_PACKETS << " packets in "
              << seconds << "s (" << mpps << " Mpps). Integrity verified." << std::endl;
}

int main() {
    test_ring_basic();
    test_ring_multithreaded_throughput();
    std::cout << "[All Ring Buffer Tests Passed Cleanly]" << std::endl;
    return 0;
}
