# Kernel-Bypass Network Engine & DPI Streamer (C++20 / Python)

High-performance, kernel-bypass network sniffer and zero-copy Deep Packet Inspection (DPI) engine delivering multi-million packets per second (Mpps) processing without memory allocations on the hot path, featuring low-latency metadata streaming to Python via nanobind.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                               Network NIC / Interface                             |
+-----------------------------------------------------------------------------------+
                                          |
                +-------------------------+-------------------------+
                | (Linux)                                           | (Windows)
       [ AF_XDP Socket ]                                     [ WinDivert / WFP ]
      UMEM Fill / RX Rings                                  Kernel Filter Driver
                |                                                   |
                +-------------------------+-------------------------+
                                          v
+-----------------------------------------------------------------------------------+
|                         C++20 In-Memory Engine Core                               |
|                                                                                   |
|  1. Lock-Free Zero-Copy Packet Ring (SPSC / MPMC, Cacheline 64B aligned)          |
|     - Preallocated packet buffer slots, fixed MTU chunks (2048 B)                 |
|                                                                                   |
|  2. Fast Header Parser (Zero-Copy Struct Overlays)                               |
|     - Ethernet II -> 802.1Q/802.1ad (VLAN/QinQ) -> IPv4/IPv6 -> TCP/UDP           |
|     - Endianness handling via compile-time byteswap, SIMD IP/TCP checksumming     |
|                                                                                   |
|  3. Lock-Free 5-Tuple Flow Table                                                  |
|     - Canonical bidirectional key: min(IP_a:Port_a, IP_b:Port_b)                  |
|     - Cache-friendly flat hash layout with atomic counters and TCP state tracker  |
|                                                                                   |
|  4. Zero-Copy L7 DPI Decoders                                                     |
|     - TLS 1.2 / 1.3 ClientHello (SNI, ALPN, Cipher Suites, JA3/JA4 fingerprint)  |
|     - DNS Decoder (QNAME label decompression, A/AAAA/CNAME answer records)        |
|     - HTTP/1.1 Scanner (Method, URI, Host, User-Agent, Content-Type)             |
+-----------------------------------------------------------------------------------+
                                          |
                                          | nanobind (Zero-Copy PyBuffer / ndarray)
                                          v
+-----------------------------------------------------------------------------------+
|                           Python High-Level Engine Layer                          |
|  - Sniffer: High-level generator streaming Flow events and packet batches         |
|  - DpiFilter: Fluent Python DSL for packet / flow filtering                       |
|  - Arrow / Polars Export: Zero-copy columnar batch conversion                    |
+-----------------------------------------------------------------------------------+
```

---

## Directory Layout

```
kernel-bypass-dpi/
├── CMakeLists.txt              # C++20 build configuration
├── pyproject.toml              # Python build specification
├── README.md                   # Technical reference & quickstart
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml              # Windows & Linux CI matrix
├── include/
│   └── dpi/
│       ├── capture.hpp         # ICaptureDevice abstraction
│       ├── packet.hpp          # PacketSlot & ParsedPacket zero-copy structs
│       ├── ring_buffer.hpp     # Lock-free SPSC 64B-aligned ring buffer
│       ├── flow_table.hpp      # Canonical 5-tuple table & TCP state machine
│       ├── parser.hpp          # L2-L4 zero-copy parser orchestrator
│       └── protocols/
│           ├── endian.hpp      # Bswap intrinsics
│           ├── ethernet.hpp    # Ethernet II
│           ├── vlan.hpp        # 802.1Q & 802.1ad (QinQ)
│           ├── ipv4.hpp        # IPv4 with checksum calculation
│           ├── ipv6.hpp        # IPv6 with extension header traversal
│           ├── tcp.hpp         # TCP header & options parser
│           ├── udp.hpp         # UDP header
│           ├── dns.hpp         # DNS decompressor & RR decoder
│           ├── tls.hpp         # TLS ClientHello, SNI & JA3 definitions
│           └── http.hpp        # HTTP/1.1 request line & headers
├── src/
│   ├── parser.cpp              # Protocol parsing logic
│   ├── flow_table.cpp          # Flow lifecycle & eviction
│   ├── dpi_tls.cpp             # TLS SNI & JA3 MD5 calculator
│   ├── dpi_dns.cpp             # DNS wire format decoder
│   ├── dpi_http.cpp            # HTTP scanner
│   ├── capture_windivert.cpp   # WinDivert 2.2+ backend
│   ├── capture_afxdp.cpp       # Linux AF_XDP backend
│   └── capture_pcap.cpp        # Zero-copy PCAP file reader
├── python/
│   ├── bindings.cpp            # nanobind module export
│   └── dpi_engine/
│       ├── __init__.py
│       ├── sniffer.py          # SnifferStream generator interface
│       └── filters.py          # Fluent filter DSL
├── tests/
│   ├── test_parsers.cpp        # L2-L4 parser unit tests
│   ├── test_ring_buffer.cpp    # Multi-threaded ring throughput test
│   ├── test_flow_table.cpp     # Bidirectional matching & eviction test
│   └── test_dpi_l7.cpp         # TLS SNI, JA3, DNS & HTTP tests
└── benchmarks/
    ├── pcap_replay.cpp         # C++ Mpps / latency benchmark
    └── bench_throughput.py     # Python stream benchmark runner
```

---

## Toolchain Prerequisites

- **C++ Compiler**: MSVC 19.34+ (VS 2022 / VS 18+), Clang 16+, or GCC 12+ with full C++20 standard support.
- **CMake**: Version 3.20 or newer.
- **Python**: 3.10 through 3.14.
- **Python packages**: `nanobind >= 2.0.0`, `scikit-build-core`.
- **Operating Systems**:
  - **Windows 10/11 / Server**: Native capture uses `WinDivert.dll` and `WinDivert64.sys` (version 2.2+).
  - **Linux**: Kernel 5.4+ with AF_XDP and `libbpf` support.

---

## Build Instructions

### Building C++ Core, Tests & Benchmarks

```powershell
# Configure build with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON

# Build all targets in parallel
cmake --build build --config Release --parallel

# Execute unit test suite
ctest --test-dir build -C Release --output-on-failure
```

### Running C++ High-Throughput Benchmark

```powershell
.\build\benchmarks\Release\bench_pcap_replay.exe 5000000
```

### Building & Installing Python Module

```powershell
pip install .
```

---

## 5-Line Usage Examples

### C++ Zero-Copy Parser & Flow Inspection

```cpp
#include "dpi/parser.hpp"
#include "dpi/flow_table.hpp"

dpi::FlowTable table;
dpi::ParsedPacket pkt;
if (dpi::PacketParser::parse(raw_bytes, timestamp_ns, pkt)) {
    dpi::FlowDirection dir;
    auto flow = table.process_packet(pkt, dir);
}
```

### Python 5-Line DPI Streamer

```python
from dpi_engine import SnifferStream, DpiFilter, Proto

sniffer = SnifferStream("traffic.pcap", is_pcap=True)
filt = DpiFilter().proto(Proto.TCP).port(443)
for pkt in sniffer.stream_packets():
    if filt.matches(pkt):
        print(f"{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}")
```
