from enum import IntEnum
from typing import Callable, Any, Optional


class Proto(IntEnum):
    ICMP = 1
    TCP = 6
    UDP = 17


class DpiFilter:
    """
    Fluent builder for filtering network packets and session flows.
    """

    def __init__(self):
        self._predicates = []

    def proto(self, protocol: Proto) -> "DpiFilter":
        self._predicates.append(lambda pkt: pkt.protocol == int(protocol))
        return self

    def src_port(self, port: int) -> "DpiFilter":
        self._predicates.append(lambda pkt: pkt.src_port == port)
        return self

    def dst_port(self, port: int) -> "DpiFilter":
        self._predicates.append(lambda pkt: pkt.dst_port == port)
        return self

    def port(self, port: int) -> "DpiFilter":
        self._predicates.append(lambda pkt: pkt.src_port == port or pkt.dst_port == port)
        return self

    def ip(self, address: str) -> "DpiFilter":
        self._predicates.append(lambda pkt: pkt.src_ip == address or pkt.dst_ip == address)
        return self

    def custom(self, fn: Callable[[Any], bool]) -> "DpiFilter":
        self._predicates.append(fn)
        return self

    def matches(self, packet_or_flow: Any) -> bool:
        return all(predicate(packet_or_flow) for predicate in self._predicates)

    def __call__(self, item: Any) -> bool:
        return self.matches(item)
