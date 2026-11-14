import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional
from src.core.prefix_trie import PrefixTrie
from src.config import (
    STATE_VALID, STATE_NOT_FOUND, STATE_INVALID_ASN, STATE_INVALID_LENGTH
)

class RFC6811State(str, Enum):
    VALID = STATE_VALID
    NOT_FOUND = STATE_NOT_FOUND
    INVALID_ASN = STATE_INVALID_ASN
    INVALID_LENGTH = STATE_INVALID_LENGTH
    INVALID_BOTH = "INVALID_BOTH"

@dataclass
class ValidationResult:
    state: RFC6811State
    rfc_state: str                       # 'VALID', 'NOT_FOUND', or 'INVALID'
    matched_roas: List[Dict[str, Any]]
    expected_asns: List[int]
    max_lengths: List[int]
    prefix_len: int
    reason: str

class RPKIValidator:
    """RFC 6811 compliant BGP Prefix Origin Validation Engine.
    Uses PrefixTrie for high-throughput lookup.
    """

    def __init__(self, roa_records: Optional[List[Dict[str, Any]]] = None):
        self.trie = PrefixTrie()
        self._roa_count = 0
        if roa_records:
            self.load_roas(roa_records)

    def load_roas(self, roa_records: List[Dict[str, Any]]) -> int:
        """Loads a list of ROA dictionaries into the trie."""
        self.trie.clear()
        count = 0
        for roa in roa_records:
            try:
                self.trie.insert(
                    prefix_str=roa["prefix"],
                    max_length=int(roa["max_length"]),
                    asn=int(roa["asn"]),
                    tai=roa.get("tai", "RIPE NCC")
                )
                count += 1
            except Exception:
                continue
        self._roa_count = count
        return count

    def validate(self, prefix: str, origin_asn: int) -> ValidationResult:
        """Validates a prefix and origin ASN according to RFC 6811."""
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            prefix_len = net.prefixlen
        except ValueError:
            return ValidationResult(
                state=RFC6811State.NOT_FOUND,
                rfc_state="NOT_FOUND",
                matched_roas=[],
                expected_asns=[],
                max_lengths=[],
                prefix_len=0,
                reason="Malformed IP prefix string"
            )

        covering_roas = self.trie.find_covering_roas(prefix)

        # Step 1: RFC 6811 - If no covering ROAs exist -> NotFound
        if not covering_roas:
            return ValidationResult(
                state=RFC6811State.NOT_FOUND,
                rfc_state="NOT_FOUND",
                matched_roas=[],
                expected_asns=[],
                max_lengths=[],
                prefix_len=prefix_len,
                reason=f"No covering ROA found for prefix {prefix}."
            )

        expected_asns = sorted(list({r["asn"] for r in covering_roas}))
        max_lengths = sorted(list({r["max_length"] for r in covering_roas}))

        # Step 2: Check for at least one ROA satisfying both:
        # (1) prefix_len <= ROA.max_length AND (2) origin_asn == ROA.asn
        for roa in covering_roas:
            if origin_asn == roa["asn"] and prefix_len <= roa["max_length"]:
                return ValidationResult(
                    state=RFC6811State.VALID,
                    rfc_state="VALID",
                    matched_roas=covering_roas,
                    expected_asns=expected_asns,
                    max_lengths=max_lengths,
                    prefix_len=prefix_len,
                    reason=f"Authorized by ROA ({roa['prefix']} max-len /{roa['max_length']} for AS{roa['asn']})."
                )

        # Step 3: Covering ROAs exist, but none fully satisfied -> RFC 6811 INVALID.
        # Determine exact granular violation for explainability:
        asn_matches = any(roa["asn"] == origin_asn for roa in covering_roas)
        len_allowed_by_any = any(prefix_len <= roa["max_length"] for roa in covering_roas)

        if asn_matches and not any(roa["asn"] == origin_asn and prefix_len <= roa["max_length"] for roa in covering_roas):
            # The ASN is authorized for the supernet, but the announced subprefix is more specific than max_length!
            return ValidationResult(
                state=RFC6811State.INVALID_LENGTH,
                rfc_state="INVALID",
                matched_roas=covering_roas,
                expected_asns=expected_asns,
                max_lengths=max_lengths,
                prefix_len=prefix_len,
                reason=(
                    f"Subprefix Hijack (Invalid-Length): Announced /{prefix_len} exceeds "
                    f"maximum authorized length /{max(max_lengths)} for AS{origin_asn}."
                )
            )

        if not asn_matches and len_allowed_by_any:
            # Length is permissible, but announcing ASN does not match authorized ASN(s)
            asns_str = ", ".join(f"AS{a}" for a in expected_asns)
            return ValidationResult(
                state=RFC6811State.INVALID_ASN,
                rfc_state="INVALID",
                matched_roas=covering_roas,
                expected_asns=expected_asns,
                max_lengths=max_lengths,
                prefix_len=prefix_len,
                reason=(
                    f"Unexpected Origin (Invalid-ASN): Announcing origin AS{origin_asn} "
                    f"is unauthorized. ROA authorizes: [{asns_str}]."
                )
            )

        # Both ASN is unauthorized and length exceeds max_length
        asns_str = ", ".join(f"AS{a}" for a in expected_asns)
        return ValidationResult(
            state=RFC6811State.INVALID_BOTH,
            rfc_state="INVALID",
            matched_roas=covering_roas,
            expected_asns=expected_asns,
            max_lengths=max_lengths,
            prefix_len=prefix_len,
            reason=(
                f"Unauthorized Origin and Subprefix Exceeded: AS{origin_asn} is unauthorized "
                f"(expected [{asns_str}]) and announced /{prefix_len} exceeds max-len /{max(max_lengths)}."
            )
        )
