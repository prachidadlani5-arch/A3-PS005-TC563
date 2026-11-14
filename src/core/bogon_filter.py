import ipaddress
from typing import List, Tuple

class BogonFilter:
    """Detects Bogon IP prefixes and Private/Reserved Autonomous System Numbers (ASNs)
    as standardized across RFC 5398, RFC 6793, RFC 6996, RFC 7300, and RFC 7607.
    """

    RESERVED_ASN_RANGES: List[Tuple[int, int, str]] = [
        (0, 0, "RFC 7607: ASN 0 Reserved"),
        (23456, 23456, "RFC 6793: AS_TRANS Reserved"),
        (64496, 64511, "RFC 5398: 16-bit Documentation ASN"),
        (64512, 65534, "RFC 6996: 16-bit Private Use ASN"),
        (65535, 65535, "RFC 7300: 16-bit Last ASN Reserved"),
        (65536, 65551, "RFC 5398: 32-bit Documentation ASN"),
        (65552, 131071, "IANA Reserved 32-bit ASNs"),
        (4200000000, 4294967294, "RFC 6996: 32-bit Private Use ASN"),
        (4294967295, 4294967295, "RFC 7300: 32-bit Max ASN Reserved")
    ]

    BOGON_IPV4_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
    ]

    @classmethod
    def is_bogon_asn(cls, asn: int) -> Tuple[bool, str]:
        """Checks if an ASN falls within reserved or private allocations."""
        for start, end, label in cls.RESERVED_ASN_RANGES:
            if start <= asn <= end:
                return True, label
        return False, "Public ASN"

    @classmethod
    def is_bogon_prefix(cls, prefix_str: str) -> Tuple[bool, str]:
        """Checks if an announced prefix is within a bogon or private space."""
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            return True, "Invalid/Unparseable IP prefix"

        if net.version == 4:
            for bogon in cls.BOGON_IPV4_NETWORKS:
                if net.subnet_of(bogon) or net == bogon:
                    return True, f"Bogon IPv4 prefix (falls within {bogon})"
        elif net.version == 6:
            if net.is_private or net.is_reserved or net.is_loopback or net.is_link_local:
                return True, "Bogon/Private IPv6 prefix"

        return False, "Public routable prefix"

    @classmethod
    def check_as_path_bogons(cls, as_path: str | List[int]) -> List[Tuple[int, str]]:
        """Scans every ASN in an AS_PATH and returns any detected bogon ASNs."""
        if isinstance(as_path, str):
            asns = [int(a) for a in as_path.split() if a.isdigit()]
        else:
            asns = [int(a) for a in as_path]

        bogons_found = []
        for asn in asns:
            is_bogon, label = cls.is_bogon_asn(asn)
            if is_bogon:
                bogons_found.append((asn, label))
        return bogons_found
