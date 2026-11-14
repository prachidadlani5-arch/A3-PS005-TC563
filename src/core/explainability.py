from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from src.core.rpki_validator import ValidationResult, RFC6811State
from src.ml.pipeline import AnomalyEvaluation

@dataclass
class ExplainabilityDossier:
    headline: str
    summary: str
    anomaly_category: str
    evidence_breakdown: Dict[str, Any]
    passive_advisory: str

class ExplainabilityEngine:
    """Generates transparent, human-auditable evidence strings and structured dossiers

    for BGP routing alerts in compliance with RFC 6811.
    """

    @classmethod
    def generate(
        cls,
        update: Dict[str, Any],
        val_result: ValidationResult,
        ml_eval: AnomalyEvaluation,
        bogon_info: Optional[List[Any]] = None
    ) -> ExplainabilityDossier:
        prefix = update.get("prefix", "Unknown")
        origin_asn = update.get("origin_asn", 0)
        as_path = str(update.get("as_path", ""))
        hops = [int(h) for h in as_path.split() if h.isdigit()]
        rpki_state = val_result.state

        evidence_breakdown = {
            "announced_prefix": prefix,
            "announced_origin_asn": origin_asn,
            "as_path": hops,
            "as_path_length": len(hops),
            "rf_confidence_pct": round(ml_eval.rf_confidence * 100, 1),
            "if_anomaly_score_pct": round(ml_eval.if_score * 100, 1),
            "threat_score": ml_eval.threat_score,
            "rfc6811_state": val_result.rfc_state,
            "covering_roas": val_result.matched_roas,
            "authorized_asns": val_result.expected_asns,
            "authorized_max_lengths": val_result.max_lengths,
        }

        # Case 1: Bogon Filter Trigger
        if bogon_info:
            bogon_labels = [f"AS{asn} ({reason})" for asn, reason in bogon_info]
            headline = f"Bogon ASN Detected in Path for {prefix}"
            summary = (
                f"Bogon/Private ASN Violation: AS_PATH contains reserved ASN(s): "
                f"{', '.join(bogon_labels)}. Private and reserved ASNs must not be propagated "
                f"in public DFZ routing tables according to RFC 6996 / RFC 7300."
            )
            category = "BOGON_ASN"
            advisory = (
                "Passive Advisory: Filter outbound route announcement or notify transit peer "
                f"AS{hops[0] if hops else 'Peer'} to strip private ASNs from AS_PATH."
            )

        # Case 2: Subprefix Hijack (Invalid-Length)
        elif rpki_state in (RFC6811State.INVALID_LENGTH, RFC6811State.INVALID_BOTH):
            max_len = max(val_result.max_lengths) if val_result.max_lengths else 0
            delta = val_result.prefix_len - max_len
            headline = f"Subprefix Hijack Detected on {prefix} (/{delta} Exceeded)"
            summary = (
                f"Subprefix Hijack (RFC 6811 Invalid-Length): Announced prefix {prefix} has prefix length "
                f"/{val_result.prefix_len}, which is more specific than the maximum authorized length "
                f"/{max_len} registered in the RPKI ROA. Subprefix announcements hijack traffic by "
                f"exploiting longest-prefix-match forwarding."
            )
            category = "SUBPREFIX_HIJACK"
            advisory = (
                "Passive Advisory: Verify if this is an internal traffic engineering sub-allocation. "
                "If not, contact origin AS" + str(origin_asn) + " or issue an updated RPKI ROA."
            )

        # Case 3: Unexpected Origin (Invalid-ASN)
        elif rpki_state == RFC6811State.INVALID_ASN:
            auth_asns = ", ".join(f"AS{a}" for a in val_result.expected_asns)
            headline = f"Unauthorized Origin AS{origin_asn} for {prefix}"
            summary = (
                f"Unexpected Origin (RFC 6811 Invalid-ASN): Announced by origin AS{origin_asn}, "
                f"which is unauthorized for prefix {prefix}. Valid ROA explicitly authorizes [{auth_asns}]. "
                f"This indicates a potential prefix hijacking event or severe BGP configuration error."
            )
            category = "UNEXPECTED_ORIGIN"
            advisory = (
                f"Passive Advisory: Review route validation policy. Upstream transit networks should "
                f"drop Invalid-ASN routes per RPKI RFC 6811 guidance."
            )

        # Case 4: Path Spike or Outlier on NotFound / Valid
        elif ml_eval.path_spike_flag:
            headline = f"Anomalous AS_PATH Length Spike ({len(hops)} hops) for {prefix}"
            summary = (
                f"Path Length Anomaly: AS_PATH length ({len(hops)} hops) is significantly longer than "
                f"internet average (3.8 hops), with an Isolation Forest outlier score of {round(ml_eval.if_score, 2)}. "
                f"Possible route leak, path prepending churn, or transit detour."
            )
            category = "PATH_SPIKE"
            advisory = (
                "Passive Advisory: Monitor route convergence. Path will likely stabilize or withdraw."
            )

        else:
            headline = f"Benign Telemetry for {prefix}"
            summary = f"Route announcement matches baseline expectations. RFC state: {val_result.rfc_state}."
            category = "BENIGN"
            advisory = "No action required."

        return ExplainabilityDossier(
            headline=headline,
            summary=summary,
            anomaly_category=category,
            evidence_breakdown=evidence_breakdown,
            passive_advisory=advisory
        )
