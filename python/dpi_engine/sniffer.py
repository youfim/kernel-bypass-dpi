from typing import Iterator, Optional, Dict, Any, List
import time
from datetime import datetime

try:
    import _dpi_engine
except ImportError:
    try:
        from . import _dpi_engine
    except ImportError:
        _dpi_engine = None


class SnifferStream:
    """
    High-level generator interface streaming packets, application flows, and L7 requests.
    """

    def __init__(
        self,
        target: Optional[str] = None,
        is_pcap: bool = False,
        app: Optional[str] = None,
        pid: Optional[int] = None,
        path_contains: Optional[str] = None,
        exclude_app: Optional[str] = None,
    ):
        if _dpi_engine is None:
            raise RuntimeError(
                "_dpi_engine native C++ module not loaded. Build the extension using cmake / pip."
            )
        self._engine = _dpi_engine.Sniffer()
        self.is_pcap = is_pcap

        if app:
            self._engine.include_app(app)
        if pid:
            self._engine.include_pid(pid)
        if path_contains:
            self._engine.include_path(path_contains)
        if exclude_app:
            self._engine.exclude_app(exclude_app)

        if target:
            if is_pcap:
                if not self._engine.open_pcap(target):
                    raise IOError(f"Could not open PCAP file: {target}")
            else:
                if not self._engine.open_live(target):
                    raise RuntimeError(f"Could not open live capture device with filter: {target}")

    def filter_app(self, app_name: str) -> "SnifferStream":
        self._engine.include_app(app_name)
        return self

    def filter_pid(self, pid: int) -> "SnifferStream":
        self._engine.include_pid(pid)
        return self

    def filter_path(self, substr: str) -> "SnifferStream":
        self._engine.include_path(substr)
        return self

    def exclude_app(self, app_name: str) -> "SnifferStream":
        self._engine.exclude_app(app_name)
        return self

    def stream_packets(self, max_packets: Optional[int] = None) -> Iterator[Any]:
        """
        Stream parsed packets matching process filters with zero-copy payload views.
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

    def stream_requests(self, max_requests: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Stream high-level L7 application requests (DNS, TLS/SNI, HTTP) with process metadata.
        """
        seen_flows = set()
        count = 0

        for pkt in self.stream_packets():
            for flow in self.get_flows():
                domain = flow.sni or flow.dns_query or flow.http_host
                if domain:
                    fid = (flow.key.src_port, flow.key.dst_port, flow.key.protocol, domain)
                    if fid in seen_flows:
                        continue
                    seen_flows.add(fid)
                    ts = datetime.fromtimestamp(flow.last_seen_ns / 1e9).strftime("%H:%M:%S.%f")[:-3]
                    req_type = "TLS" if flow.sni else ("DNS" if flow.dns_query else "HTTP")
                    yield {
                        "time": ts,
                        "app": flow.app_name or "Unknown",
                        "pid": flow.pid,
                        "path": flow.app_path,
                        "proto": req_type,
                        "target_ip": flow.server_ip or flow.key.dst_ip,
                        "target_port": flow.server_port or flow.key.dst_port,
                        "domain": domain,
                        "ja3": flow.ja3,
                        "http_method": flow.http_method,
                        "http_uri": flow.http_uri,
                        "dns_answers": flow.dns_answers,
                    }
                    count += 1
                    if max_requests is not None and count >= max_requests:
                        return

    def get_flows(self) -> List[Any]:
        """
        Retrieve a snapshot of all active flows matching the filter.
        """
        return self._engine.get_flows()

    def export_stats_dict(self) -> List[Dict[str, Any]]:
        """
        Exports active flow statistics with process metadata for Polars / Pandas.
        """
        rows = []
        for flow in self.get_flows():
            rows.append({
                "app": flow.app_name,
                "pid": flow.pid,
                "path": flow.app_path,
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
                "dns_query": flow.dns_query,
                "dns_answers": flow.dns_answers,
                "http_host": flow.http_host,
                "http_uri": flow.http_uri,
                "http_method": flow.http_method,
            })
        return rows
