"""Traceability matrix builder for linking requirements, threats, and controls."""

import json
from typing import Dict, List

from security_requirements_system.data_models import TraceabilityEntry, TraceabilityMatrix

# Common stop words for text matching
_STOP_WORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "but",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "with",
    "by",
    "from",
    "as",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "have",
    "has",
    "had",
    "do",
    "does",
    "did",
    "will",
    "would",
    "should",
    "could",
    "may",
    "might",
    "must",
    "can",
}


def build_traceability_matrix(
    detailed_requirements: str,
    threats: str,
    security_controls: str,
) -> str:
    """
    Build comprehensive traceability matrix linking requirements → threats → controls → verification.

    Args:
        detailed_requirements: JSON string of detailed requirements
        threats: JSON string of threat modeling output
        security_controls: JSON string of security controls mapping

    Returns:
        JSON string of traceability matrix
    """
    print("\n" + "=" * 80)
    print("Building Traceability Matrix")
    print("=" * 80)

    try:
        # Parse all JSON data
        detailed_reqs = json.loads(detailed_requirements) if detailed_requirements else []
        threats_data = json.loads(threats) if threats else {}
        controls_data = json.loads(security_controls) if security_controls else {}

        # Extract data
        threats_list = threats_data.get("threats", []) if isinstance(threats_data, dict) else []
        requirements_mapping = controls_data.get("requirements_mapping", []) if isinstance(controls_data, dict) else []

        # Create lookup dictionaries for better matching
        req_text_to_id = {}
        for req in detailed_reqs:
            req_text = req.get("requirement_text", "").strip().lower()
            req_id = req.get("requirement_id", "")
            if req_text and req_id:
                req_text_to_id[req_text] = req_id

        # Populate requirement_ids in mappings if missing
        for mapping in requirements_mapping:
            if not mapping.get("requirement_id"):
                high_level_req = mapping.get("high_level_requirement", "").strip().lower()
                mapping["requirement_id"] = req_text_to_id.get(high_level_req, "")

        # Create controls lookup
        controls_lookup = {}
        for rm in requirements_mapping:
            high_level_req = rm.get("high_level_requirement", "").strip().lower()
            req_id = rm.get("requirement_id", "")
            controls_lookup[high_level_req] = rm
            if req_id:
                controls_lookup[req_id.lower()] = rm

        # Build traceability entries
        entries = []

        for req in detailed_reqs:
            req_text = req.get("requirement_text", "")
            req_id = req.get("requirement_id", "")
            req_text_lower = req_text.strip().lower()

            # Find related threats
            related_threats = _find_related_threats(req, req_text_lower, threats_list)

            # Find related security controls
            req_mapping = _find_security_controls(req_id, req_text_lower, controls_lookup)

            # Get security controls (multi-standard)
            all_controls = req_mapping.get("security_controls", []) if req_mapping else []

            # Extract verification methods and priority
            verification_methods = list(
                set([ctrl.get("verification_method", "Manual Review") for ctrl in all_controls if ctrl.get("verification_method")])
            )

            priority = _determine_priority(all_controls, req)

            # Build control IDs and descriptions with standard prefixes
            control_ids, control_descriptions = _format_controls(all_controls)

            # Build entry
            entry = TraceabilityEntry(
                req_id=req_id or f"REQ-{len(entries) + 1:03d}",
                high_level_requirement=req_text,
                functional_category=req.get("business_category", req.get("functional_category", "General")),
                security_sensitivity=req.get("security_sensitivity", "Medium"),
                threat_ids=[t.get("threat_id", "") for t in related_threats[:10]],
                threat_descriptions=[
                    t.get("description", "")[:80] + "..." if len(t.get("description", "")) > 80 else t.get("description", "")
                    for t in related_threats[:10]
                ],
                owasp_control_ids=control_ids,
                owasp_control_descriptions=control_descriptions,
                priority=priority,
                verification_methods=verification_methods or ["Manual Review"],
                implementation_status="Pending",
            )

            entries.append(entry)

        # Build summary
        total_reqs = len(entries)
        with_threats = sum(1 for e in entries if e.threat_ids)
        with_controls = sum(1 for e in entries if e.owasp_control_ids)
        coverage_pct = (with_controls / total_reqs * 100) if total_reqs > 0 else 0

        summary = (
            f"Traceability matrix contains {total_reqs} requirements. "
            f"{with_threats} requirements ({with_threats / total_reqs * 100:.1f}%) linked to threats. "
            f"{with_controls} requirements ({coverage_pct:.1f}%) mapped to security controls. "
            "Coverage: " + ("Complete" if coverage_pct >= 90 else "Partial" if coverage_pct >= 70 else "Needs Improvement") + "."
        )

        # Create traceability matrix
        matrix = TraceabilityMatrix(entries=entries, summary=summary)

        print("\n✓ Traceability matrix built successfully")
        print(f"  - Total requirements: {total_reqs}")
        print(f"  - Requirements with threats: {with_threats}")
        print(f"  - Requirements with controls: {with_controls}")
        print(f"  - Coverage: {coverage_pct:.1f}%")

        return matrix.model_dump_json(indent=2)

    except Exception as e:
        print(f"\n⚠ Error building traceability matrix: {e}")
        # Create empty matrix
        return TraceabilityMatrix(entries=[], summary="Error building traceability matrix. Manual review required.").model_dump_json(
            indent=2
        )


def _find_related_threats(req: Dict, req_text_lower: str, threats_list: List[Dict]) -> List[Dict]:
    """Find threats related to a requirement."""
    related_threats = []
    req_keywords = set(req_text_lower.split())

    for t in threats_list:
        threat_desc = t.get("description", "").lower()
        threat_component = t.get("component", "").lower()

        # Filter meaningful keywords
        meaningful_keywords = {kw for kw in req_keywords if len(kw) > 3 and kw not in _STOP_WORDS}
        keyword_matches = sum(1 for kw in meaningful_keywords if kw in threat_desc)

        # Check component matches
        component_match = any(kw in threat_component for kw in meaningful_keywords)
        business_category = req.get("business_category", "").lower()
        category_match = business_category in threat_component or threat_component in business_category
        component_in_req = any(word in req_text_lower for word in threat_component.split() if len(word) > 3)

        # Match if any condition met
        if keyword_matches >= 1 or component_match or category_match or component_in_req:
            related_threats.append(t)

    return related_threats


def _find_security_controls(req_id: str, req_text_lower: str, controls_lookup: Dict) -> Dict:
    """Find security controls for a requirement."""
    # Strategy 1: Exact match on requirement_id
    if req_id:
        req_mapping = controls_lookup.get(req_id.lower())
        if req_mapping:
            return req_mapping

    # Strategy 2: Exact match on requirement text
    req_mapping = controls_lookup.get(req_text_lower)
    if req_mapping:
        return req_mapping

    # Strategy 3: Fuzzy match on keywords
    req_keywords = set(req_text_lower.split())
    req_keywords_filtered = {kw for kw in req_keywords if kw not in _STOP_WORDS and len(kw) > 2}

    for rm_text, rm in controls_lookup.items():
        # Skip ID keys
        if rm_text.startswith("req-") and len(rm_text) < 10:
            continue

        # Check keyword overlap
        rm_keywords = set(rm_text.split())
        rm_keywords_filtered = {kw for kw in rm_keywords if kw not in _STOP_WORDS and len(kw) > 2}
        overlap = req_keywords_filtered.intersection(rm_keywords_filtered)

        # If significant keywords overlap
        if len(overlap) >= max(2, min(len(req_keywords_filtered), len(rm_keywords_filtered)) * 0.3):
            return rm

    return {}


def _determine_priority(all_controls: List[Dict], req: Dict) -> str:
    """Determine priority from controls or requirement."""
    priority_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    priorities = [ctrl.get("priority", "Medium") for ctrl in all_controls]

    if priorities:
        return max(priorities, key=lambda p: priority_map.get(p.lower(), 2))
    return req.get("priority", "Medium")


def _format_controls(all_controls: List[Dict]) -> tuple[List[str], List[str]]:
    """Format control IDs and descriptions with standard prefixes."""
    control_ids = []
    control_descriptions = []

    for ctrl in all_controls:
        standard = ctrl.get("standard", "UNKNOWN")
        ctrl_id = ctrl.get("req_id", "")
        ctrl_desc = ctrl.get("requirement", "")

        # Format control ID with standard prefix
        if standard and ctrl_id:
            formatted_id = f"[{standard}] {ctrl_id}"
            control_ids.append(formatted_id)
        elif ctrl_id:
            control_ids.append(ctrl_id)

        # Format description with standard prefix
        if standard and ctrl_desc:
            formatted_desc = f"[{standard}] {ctrl_desc[:80]}{'...' if len(ctrl_desc) > 80 else ''}"
            control_descriptions.append(formatted_desc)
        elif ctrl_desc:
            control_descriptions.append(ctrl_desc[:80] + "..." if len(ctrl_desc) > 80 else ctrl_desc)

    return control_ids, control_descriptions
