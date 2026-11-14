import ipaddress
from typing import Any, Dict, List, Optional, Tuple

class TrieNode:
    __slots__ = ("children", "roas")

    def __init__(self):
        # 0 or 1 binary branches
        self.children: Dict[int, TrieNode] = {}
        # List of ROA dicts attached to this prefix: [{"asn": ..., "max_length": ..., "tai": ...}]
        self.roas: List[Dict[str, Any]] = []

class PrefixTrie:
    """A Radix Trie implementation for IPv4/IPv6 prefix lookups adhering to RFC 6811.
    Allows efficient retrieval of all covering ROAs for any announced route.
    """

    def __init__(self):
        self.root_v4 = TrieNode()
        self.root_v6 = TrieNode()

    def _get_root_and_bits(self, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Tuple[TrieNode, List[int], int]:
        root = self.root_v4 if net.version == 4 else self.root_v6
        total_bits = 32 if net.version == 4 else 128
        # Convert network integer to binary bit array
        net_int = int(net.network_address)
        bits = [(net_int >> (total_bits - 1 - i)) & 1 for i in range(net.prefixlen)]
        return root, bits, net.prefixlen

    def insert(self, prefix_str: str, max_length: int, asn: int, tai: str = "RIPE NCC") -> None:
        """Inserts a ROA rule into the trie."""
        net = ipaddress.ip_network(prefix_str, strict=False)
        root, bits, prefix_len = self._get_root_and_bits(net)

        curr = root
        for bit in bits:
            if bit not in curr.children:
                curr.children[bit] = TrieNode()
            curr = curr.children[bit]

        curr.roas.append({
            "prefix": str(net),
            "prefix_len": prefix_len,
            "max_length": max_length,
            "asn": asn,
            "tai": tai
        })

    def find_covering_roas(self, prefix_str: str) -> List[Dict[str, Any]]:
        """Traverses from root down to the prefix's length, collecting all ROAs

        attached to any ancestral (covering) prefix along the path.
        In RFC 6811, a ROA covers route P if P is a subnet of or equal to the ROA prefix.
        """
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            return []

        root, bits, prefix_len = self._get_root_and_bits(net)
        covering_roas = []

        curr = root
        # Check root (0.0.0.0/0) if any
        if curr.roas:
            covering_roas.extend(curr.roas)

        for bit in bits:
            if bit not in curr.children:
                break
            curr = curr.children[bit]
            if curr.roas:
                covering_roas.extend(curr.roas)

        return covering_roas

    def clear(self) -> None:
        self.root_v4 = TrieNode()
        self.root_v6 = TrieNode()
