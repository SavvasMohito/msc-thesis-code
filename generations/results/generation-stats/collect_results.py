#!/usr/bin/env python3
"""
Collect metrics from all generation folders and compile into a CSV file.

This script extracts metrics relevant to thesis sections:
- 6.1.1 Translation Quality Assessment
- 6.1.2 Standards Compliance Validation
"""

import json
import csv
from pathlib import Path
from typing import Any


def load_json(filepath: Path) -> Any:
    """Load a JSON file, return None if not found or invalid."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  Warning: Could not load {filepath.name}: {e}")
        return None


def extract_validation_metrics(artifacts_dir: Path) -> dict:
    """Extract metrics from validation.json."""
    data = load_json(artifacts_dir / "validation.json")
    if not data:
        return {}
    
    dims = data.get("dims", {})
    
    # Handle both lowercase and uppercase dimension keys
    def get_dim(key: str):
        return dims.get(key) or dims.get(key.upper())
    
    return {
        "overall_score": data.get("score"),
        "completeness": get_dim("completeness"),
        "consistency": get_dim("consistency"),
        "correctness": get_dim("correctness"),
        "implementability": get_dim("implementability"),
        "alignment": get_dim("alignment"),
        "validation_passed": data.get("passed"),
    }


def extract_coverage_metrics(artifacts_dir: Path) -> dict:
    """Extract metrics from coverage.json."""
    data = load_json(artifacts_dir / "coverage.json")
    if not data or not isinstance(data, list):
        return {}
    
    total_requirements = len(data)
    reqs_with_threats = sum(1 for r in data if r.get("has_threat"))
    reqs_with_controls = sum(1 for r in data if r.get("has_controls"))
    reqs_with_tests = sum(1 for r in data if r.get("tests", 0) > 0)
    total_tests = sum(r.get("tests", 0) for r in data)
    avg_tests_per_req = total_tests / total_requirements if total_requirements > 0 else 0
    
    return {
        "total_requirements": total_requirements,
        "reqs_with_threats": reqs_with_threats,
        "reqs_with_controls": reqs_with_controls,
        "reqs_with_tests": reqs_with_tests,
        "avg_tests_per_req": round(avg_tests_per_req, 2),
    }


def extract_threats_metrics(artifacts_dir: Path) -> dict:
    """Extract metrics from threats.json."""
    data = load_json(artifacts_dir / "threats.json")
    if not data or not isinstance(data, list):
        return {}
    
    total_threats = len(data)
    
    # Count by risk level
    risk_levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for threat in data:
        level = threat.get("risk_level", "")
        if level in risk_levels:
            risk_levels[level] += 1
    
    # Unique categories
    categories = set(threat.get("category", "") for threat in data if threat.get("category"))
    
    # Unique components
    components = set(threat.get("component", "") for threat in data if threat.get("component"))
    
    return {
        "total_threats": total_threats,
        "threats_critical": risk_levels["Critical"],
        "threats_high": risk_levels["High"],
        "threats_medium": risk_levels["Medium"],
        "threats_low": risk_levels["Low"],
        "threat_categories": "; ".join(sorted(categories)),
        "threat_category_count": len(categories),
        "components_with_threats": len(components),
    }


def extract_priorities_metrics(artifacts_dir: Path) -> dict:
    """Extract metrics from priorities.json."""
    data = load_json(artifacts_dir / "priorities.json")
    if not data or not isinstance(data, list):
        return {}
    
    priorities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in data:
        level = item.get("level", "")
        count = item.get("count", 0)
        if level in priorities:
            priorities[level] = count
    
    return {
        "priority_critical": priorities["Critical"],
        "priority_high": priorities["High"],
        "priority_medium": priorities["Medium"],
        "priority_low": priorities["Low"],
    }


def extract_asvs_mapping_metrics(artifacts_dir: Path) -> dict:
    """Extract metrics from asvs_mapping.json."""
    data = load_json(artifacts_dir / "asvs_mapping.json")
    if not data or not isinstance(data, list):
        return {}
    
    total_controls = len(data)
    
    # Count by standard
    owasp_controls = sum(1 for c in data if c.get("standard") == "OWASP")
    nist_controls = sum(1 for c in data if c.get("standard") == "NIST")
    iso_controls = sum(1 for c in data if c.get("standard") == "ISO27001")
    
    # Count by priority
    critical_controls = sum(1 for c in data if c.get("priority") == "Critical")
    
    # Count by ASVS level (only for OWASP controls)
    asvs_l1 = sum(1 for c in data if c.get("standard") == "OWASP" and c.get("level") == "L1")
    asvs_l2 = sum(1 for c in data if c.get("standard") == "OWASP" and c.get("level") == "L2")
    asvs_l3 = sum(1 for c in data if c.get("standard") == "OWASP" and c.get("level") == "L3")
    
    return {
        "total_controls": total_controls,
        "owasp_controls": owasp_controls,
        "nist_controls": nist_controls,
        "iso_controls": iso_controls,
        "critical_controls": critical_controls,
        "asvs_l1_controls": asvs_l1,
        "asvs_l2_controls": asvs_l2,
        "asvs_l3_controls": asvs_l3,
    }


def find_artifacts_dir(generation_dir: Path) -> Path | None:
    """Find the artifacts subfolder in a generation directory."""
    outputs_dir = generation_dir / "outputs"
    if not outputs_dir.exists():
        return None
    
    # Find artifacts_* folder
    for item in outputs_dir.iterdir():
        if item.is_dir() and item.name.startswith("artifacts_"):
            return item
    
    return None


def collect_generation_metrics(generation_dir: Path) -> dict | None:
    """Collect all metrics for a single generation."""
    artifacts_dir = find_artifacts_dir(generation_dir)
    if not artifacts_dir:
        print(f"  Skipping {generation_dir.name}: no artifacts folder found")
        return None
    
    print(f"  Processing {generation_dir.name} from {artifacts_dir.name}")
    
    metrics = {"generation_name": generation_dir.name}
    
    # Extract from each JSON file
    metrics.update(extract_validation_metrics(artifacts_dir))
    metrics.update(extract_coverage_metrics(artifacts_dir))
    metrics.update(extract_threats_metrics(artifacts_dir))
    metrics.update(extract_priorities_metrics(artifacts_dir))
    metrics.update(extract_asvs_mapping_metrics(artifacts_dir))
    
    # Calculate derived metrics
    total_reqs = metrics.get("total_requirements", 0)
    reqs_with_controls = metrics.get("reqs_with_controls", 0)
    total_controls = metrics.get("total_controls", 0)
    
    if total_reqs > 0:
        metrics["control_coverage_pct"] = round(reqs_with_controls / total_reqs * 100, 1)
        metrics["avg_controls_per_req"] = round(total_controls / total_reqs, 2)
    else:
        metrics["control_coverage_pct"] = 0
        metrics["avg_controls_per_req"] = 0
    
    return metrics


def main():
    """Main entry point."""
    generations_dir = Path(__file__).parent
    output_file = generations_dir / "results.csv"
    
    print("Collecting generation metrics...")
    print(f"Source directory: {generations_dir}")
    
    # Find all generation subdirectories (exclude files like generate.ipynb)
    generation_dirs = sorted([
        d for d in generations_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])
    
    print(f"Found {len(generation_dirs)} generation folders")
    
    all_metrics = []
    for gen_dir in generation_dirs:
        metrics = collect_generation_metrics(gen_dir)
        if metrics:
            all_metrics.append(metrics)
    
    if not all_metrics:
        print("No metrics collected!")
        return
    
    # Define column order
    columns = [
        # Identification
        "generation_name",
        # Section 6.1.1 - Translation Quality Assessment
        "overall_score",
        "completeness",
        "consistency",
        "correctness",
        "implementability",
        "alignment",
        "validation_passed",
        "total_requirements",
        "reqs_with_threats",
        "reqs_with_controls",
        "reqs_with_tests",
        "avg_tests_per_req",
        "priority_critical",
        "priority_high",
        "priority_medium",
        "priority_low",
        # Threat Analysis
        "total_threats",
        "threats_critical",
        "threats_high",
        "threats_medium",
        "threats_low",
        "threat_categories",
        "threat_category_count",
        "components_with_threats",
        # Section 6.1.2 - Standards Compliance Validation
        "total_controls",
        "owasp_controls",
        "nist_controls",
        "iso_controls",
        "control_coverage_pct",
        "avg_controls_per_req",
        "critical_controls",
        "asvs_l1_controls",
        "asvs_l2_controls",
        "asvs_l3_controls",
    ]
    
    # Write CSV
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_metrics)
    
    print(f"\nResults written to: {output_file}")
    print(f"Total generations processed: {len(all_metrics)}")
    
    # Print summary
    print("\n--- Summary ---")
    for m in all_metrics:
        print(f"  {m['generation_name']}: score={m.get('overall_score', 'N/A')}, "
              f"reqs={m.get('total_requirements', 'N/A')}, "
              f"controls={m.get('total_controls', 'N/A')}, "
              f"threats={m.get('total_threats', 'N/A')}")


if __name__ == "__main__":
    main()

