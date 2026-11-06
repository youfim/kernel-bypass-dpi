from enum import IntEnum
from typing import Callable, Any, Optional

class Proto(IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17

class DpiFilter:
    """
    Fluent builder for filtering network packets, application processes, and session flows.
    """

    def __init__(self):
        self._predicates = []

    def proto(self, protocol: Proto) -> "DpiFilter":
        self._predicates.append(lambda x: getattr(x, "protocol", getattr(getattr(x, "key", None), "protocol", 0)) == int(protocol))
        return self

    def src_port(self, port: int) -> "DpiFilter":
        self._predicates.append(lambda x: getattr(x, "src_port", getattr(getattr(x, "key", None), "src_port", 0)) == port)
        return self

    def dst_port(self, port: int) -> "DpiFilter":
        self._predicates.append(lambda x: getattr(x, "dst_port", getattr(getattr(x, "key", None), "dst_port", 0)) == port)
        return self

    def port(self, port: int) -> "DpiFilter":
        self._predicates.append(
            lambda x: getattr(x, "src_port", getattr(getattr(x, "key", None), "src_port", 0)) == port
            or getattr(x, "dst_port", getattr(getattr(x, "key", None), "dst_port", 0)) == port
        )
        return self

    def ip(self, address: str) -> "DpiFilter":
        self._predicates.append(
            lambda x: getattr(x, "src_ip", "") == address or getattr(x, "dst_ip", "") == address
        )
        return self

    def app(self, app_name: str) -> "DpiFilter":
        """Filter by process executable name (case-insensitive), e.g. 'chrome.exe'"""
        target = app_name.lower()
        self._predicates.append(
            lambda x: getattr(x, "app_name", "").lower() == target
            or getattr(getattr(x, "process", None), "name", "").lower() == target
        )
        return self

    def pid(self, process_id: int) -> "DpiFilter":
        """Filter by Process ID"""
        self._predicates.append(
            lambda x: getattr(x, "pid", 0) == process_id
            or getattr(getattr(x, "process", None), "pid", 0) == process_id
        )
        return self

    def path_contains(self, substr: str) -> "DpiFilter":
        """Filter by substring in executable path"""
        sub = substr.lower()
        self._predicates.append(
            lambda x: sub in getattr(x, "app_path", "").lower()
            or sub in getattr(getattr(x, "process", None), "path", "").lower()
        )
        return self

    def exclude_app(self, app_name: str) -> "DpiFilter":
        """Exclude traffic from specific application name"""
        target = app_name.lower()
        self._predicates.append(
            lambda x: getattr(x, "app_name", "").lower() != target
            and getattr(getattr(x, "process", None), "name", "").lower() != target
        )
        return self

    def domain_contains(self, substr: str) -> "DpiFilter":
        """Filter by domain / SNI / DNS query substring"""
        sub = substr.lower()
        self._predicates.append(
            lambda x: sub in (getattr(x, "sni", "") or "").lower()
            or sub in (getattr(x, "dns_query", "") or "").lower()
            or sub in (getattr(x, "http_host", "") or "").lower()
            or sub in (x.get("domain", "") if isinstance(x, dict) else "").lower()
        )
        return self

    def custom(self, fn: Callable[[Any], bool]) -> "DpiFilter":
        self._predicates.append(fn)
        return self

    def matches(self, packet_or_flow: Any) -> bool:
        return all(predicate(packet_or_flow) for predicate in self._predicates)

    def __call__(self, item: Any) -> bool:
        return self.matches(item)
