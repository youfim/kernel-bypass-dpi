import time
import sys

def main():
    print("==========================================================")
    print("  DPI Python Streamer Throughput Benchmark")
    print("==========================================================")

    try:
        from dpi_engine import SnifferStream, DpiFilter, Proto
    except ImportError as e:
        print(f"Skipping benchmark: {e}")
        return

    print("Native module loaded. Initializing stream...")
    # Benchmarking stream iterator performance
    filter_rule = DpiFilter().proto(Proto.TCP).port(443)
    print("Filter initialized: TCP on port 443.")
    print("==========================================================")

if __name__ == "__main__":
    main()
