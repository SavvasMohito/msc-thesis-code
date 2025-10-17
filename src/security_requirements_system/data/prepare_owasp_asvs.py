"""
Script to prepare OWASP ASVS data for ingestion into Weaviate.

This script processes OWASP ASVS (Application Security Verification Standard)
requirements and converts them into a structured JSON format.

Source: https://github.com/OWASP/ASVS
"""

import json
from pathlib import Path


def prepare_owasp_asvs():
    """
    Prepare OWASP ASVS controls from the raw JSON file.

    Reads from: data/raw/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json
    Outputs to: data/prepared/owasp_asvs.json
    """

    # Load raw OWASP ASVS data
    raw_file = Path(__file__).parent / "raw" / "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"

    if not raw_file.exists():
        print(f"Error: Raw OWASP file not found at {raw_file}")
        return

    with open(raw_file, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # Transform the data structure
    owasp_controls = []
    for req in raw_data.get("requirements", []):
        control = {
            "standard": "OWASP ASVS 5.0",
            "req_id": req.get("req_id", ""),
            "req_description": req.get("req_description", ""),
            "chapter_id": req.get("chapter_id", ""),
            "chapter_name": req.get("chapter_name", ""),
            "section_id": req.get("section_id", ""),
            "section_name": req.get("section_name", ""),
            "level": f"L{req.get('L', '')}" if req.get("L") else "",
        }
        owasp_controls.append(control)

    # Save to prepared directory
    output_file = Path(__file__).parent / "prepared" / "owasp_asvs.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(owasp_controls, f, indent=2, ensure_ascii=False)

    print(f"OWASP ASVS data prepared: {len(owasp_controls)} controls")
    print(f"Saved to: {output_file}")


if __name__ == "__main__":
    prepare_owasp_asvs()
