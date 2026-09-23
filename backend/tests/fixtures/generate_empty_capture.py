"""A capture with no packets, byte-for-byte what dumpcap writes for a quiet window.

The bytes below were taken from a real probe segment (a 30 s window on a NIC
with no link): a pcapng section header, one interface description block and one
interface statistics block, and not a single packet block. Analysis has to treat
that as "nothing happened", not as a broken file - Suricata only fails on it
after burning its entire startup timeout.
"""

from pathlib import Path

#: dumpcap 4.4.18, Linux 5.4.96, interface enp1s0, zero packets.
EMPTY_PCAPNG = bytes.fromhex(
    "0a0d0d0a5c0000004d3c2b1a01000000ffffffffffffffff030015004c69"
    "6e757820352e342e39362d31372d6b7239613000000004001a0044756d70"
    "636170202857697265736861726b2920342e342e31380000000000005c00"
    "00000100000048000000010000000000040002000600656e703173300000"
    "09000100090000000c0015004c696e757820352e342e39362d31372d6b72"
    "3961300000000000000048000000050000006c00000000000000275c0600"
    "684fae8701001c00436f756e746572732070726f76696465642062792064"
    "756d7063617002000800275c06007b31e48503000800275c06000a4fae87"
    "040008000000000000000000050008000000000000000000000000006c00"
    "0000"
)


def write_empty_capture(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(EMPTY_PCAPNG)
    return path
