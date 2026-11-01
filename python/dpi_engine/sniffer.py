from typing import Iterator, Optional, Dict, Any, List
import time

try:
    import _dpi_engine
except ImportError:
    _dpi_engine = None


class SnifferStream:
    """
    High-level generator interface streaming packets and active session metadata.
    """

    def __init__(self, target: Optional[str] = None, is_pcap: bool = False):
        if _dpi_engine is None:
            raise RuntimeError(
                "_dpi_engine native C++ module not loaded. Build the extension using cmake / pip."
            )
        self._engine = _dpi_engine.Sniffer()
        self.is_pcap = is_pcap
        if target:
            if is_pcap:
                if not self._engine.open_pcap(target):
                    raise IOError(f"Could not open PCAP file: {target}")
            else:
                if not self._engine.open_live(target):
                    raise RuntimeError(f"Could not open live capture device with filter: {target}")

    def stream_packets(self, max_packets: Optional[int] = None) -> Iterator[Any]:
        """
        Stream parsed packets one by one with zero-copy payload views.
        """
        count = 0
        while True:
            pkt = self._engine.next_packet()
            if pkt is None:
                if self.is_pcap:
                    break
                time.sleep(0.001)
                continue

            yield pkt
            count += 1
            if max_packets is not None and count >= max_packets:
                break

    def get_flows(self) -> List[Any]:
        """
        Retrieve a snapshot of all active flows in the FlowTable.
        """
        return self._engine.get_flows()

    def export_stats_dict(self) -> List[Dict[str, Any]]:
        """
        Exports active flow statistics into list of dictionaries suitable for Polars/Pandas.
        """
        rows = []
        for flow in self.get_flows():
            rows.append({
                "src_port": flow.key.src_port,
                "dst_port": flow.key.dst_port,
                "protocol": flow.key.protocol,
                "is_ipv6": flow.key.is_ipv6,
                "start_time_ns": flow.start_time_ns,
                "last_seen_ns": flow.last_seen_ns,
                "fwd_packets": flow.fwd_packets,
                "fwd_bytes": flow.fwd_bytes,
                "rev_packets": flow.rev_packets,
                "rev_bytes": flow.rev_bytes,
                "sni": flow.sni,
                "ja3": flow.ja3,
                "http_host": flow.http_host,
                "http_uri": flow.http_uri,
                "http_method": flow.http_method,
            })
        return rows
