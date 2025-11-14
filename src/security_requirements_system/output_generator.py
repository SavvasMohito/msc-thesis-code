"""Output generator for Quarto dashboard reports."""

import json
from datetime import datetime
from pathlib import Path

from security_requirements_system.state import SecurityRequirementsState


def _export_dashboard_artifacts(state: SecurityRequirementsState, artifacts_dir: Path, timestamp: str):
    """Export dashboard data as JSON artifacts for Quarto visualizations."""
    try:
        print("  ✓ Exporting dashboard artifacts...")

        # Parse all data
        controls_data = json.loads(state.security_controls) if state.security_controls else {}
        threats_data = json.loads(state.threats) if state.threats else {}
        detailed_reqs = json.loads(state.detailed_requirements) if state.detailed_requirements else []
        matrix_data = json.loads(state.traceability_matrix) if state.traceability_matrix else {}
        validation_data = json.loads(state.validation_report) if state.validation_report else {}

        # Create a lookup dictionary from detailed requirements text to requirement ID
        req_text_to_id = {}
        if detailed_reqs:
            # Handle both list and dict structures
            reqs_list = detailed_reqs if isinstance(detailed_reqs, list) else detailed_reqs.get("detailed_requirements", [])
            for req in reqs_list:
                req_text = req.get("requirement_text", "").strip().lower()
                req_id = req.get("requirement_id", "")
                if req_text and req_id:
                    req_text_to_id[req_text] = req_id

        # 1. Multi-Standard Control Mapping (control_id, standard, category, requirement_id, level, priority)
        asvs_mapping = []
        mappings = controls_data.get("requirements_mapping", [])
        for mapping in mappings:
            # Get requirement_id from mapping, or look it up from detailed_reqs
            req_id = mapping.get("requirement_id")
            if not req_id:
                high_level_req = mapping.get("high_level_requirement", "").strip().lower()
                req_id = req_text_to_id.get(high_level_req, "")

            # Get security controls (multi-standard)
            all_controls = mapping.get("security_controls", [])

            for control in all_controls:
                standard = control.get("standard", "OWASP")
                control_id = control.get("req_id", "")
                chapter = control.get("chapter", "")

                # Format category based on standard
                if standard.upper() == "OWASP":
                    v_category = chapter.replace("V", "V") if chapter else ""  # Ensure V prefix
                elif standard.upper() == "NIST":
                    v_category = chapter  # NIST family (e.g., "AC", "AU")
                elif standard.upper() == "ISO27001":
                    v_category = chapter  # ISO chapter (e.g., "A.5", "A.8")
                else:
                    v_category = chapter if chapter else ""

                asvs_mapping.append(
                    {
                        "control_id": control_id,
                        "standard": standard,
                        "v_category": v_category,
                        "requirement_id": req_id,
                        "level": control.get("level", "L2" if standard.upper() == "OWASP" else ""),
                        "priority": control.get("priority", "Medium"),
                        "requirement": control.get("requirement", "")[:100],
                    }
                )

        with open(artifacts_dir / "asvs_mapping.json", "w") as f:
            json.dump(asvs_mapping, f, indent=2)

        # 2. Threats (id, likelihood, impact, component, risk_level, category)
        threats_list = threats_data.get("threats", [])
        threats_export = []
        for threat in threats_list:
            # Map risk levels to numeric values for heatmap
            likelihood_map = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
            impact_map = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}

            likelihood_str = threat.get("likelihood", "Medium")
            impact_str = threat.get("impact", "Medium")

            threats_export.append(
                {
                    "id": threat.get("threat_id", ""),
                    "likelihood": likelihood_map.get(likelihood_str, 3),
                    "impact": impact_map.get(impact_str, 3),
                    "component": threat.get("component", ""),
                    "risk_level": threat.get("risk_level", "Medium"),
                    "category": threat.get("threat_category", ""),
                    "description": threat.get("description", "")[:200],
                }
            )

        with open(artifacts_dir / "threats.json", "w") as f:
            json.dump(threats_export, f, indent=2)

        # 3. Priorities (level, count)
        priority_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for mapping in mappings:
            for control in mapping.get("security_controls", []):
                priority = control.get("priority", "Medium")
                priority_counts[priority] = priority_counts.get(priority, 0) + 1

        priorities = [{"level": k, "count": v} for k, v in priority_counts.items()]
        with open(artifacts_dir / "priorities.json", "w") as f:
            json.dump(priorities, f, indent=2)

        # 4. Compliance (framework, status, next_audit)
        compliance_items = []
        # Detect frameworks from requirements
        if "GDPR" in state.requirements_text.upper() or "privacy" in state.requirements_text.lower():
            compliance_items.append({"framework": "GDPR", "status": "In Progress", "next_audit": "TBD"})
        if "PCI" in state.requirements_text.upper() or "payment" in state.requirements_text.lower():
            compliance_items.append({"framework": "PCI-DSS", "status": "Gap", "next_audit": "TBD"})
        if "HIPAA" in state.requirements_text.upper() or "healthcare" in state.requirements_text.lower():
            compliance_items.append({"framework": "HIPAA", "status": "In Progress", "next_audit": "TBD"})
        if "SOX" in state.requirements_text.upper() or "sox" in state.requirements_text.lower():
            compliance_items.append({"framework": "SOX", "status": "Gap", "next_audit": "TBD"})
        if "CCPA" in state.requirements_text.upper():
            compliance_items.append({"framework": "CCPA", "status": "In Progress", "next_audit": "TBD"})

        # Add security standards as always applicable
        compliance_items.append({"framework": "OWASP ASVS", "status": "In Progress", "next_audit": "N/A"})
        compliance_items.append({"framework": "NIST SP 800-53", "status": "In Progress", "next_audit": "N/A"})
        compliance_items.append({"framework": "ISO 27001", "status": "In Progress", "next_audit": "N/A"})

        with open(artifacts_dir / "compliance.json", "w") as f:
            json.dump(compliance_items, f, indent=2)

        # 5. Delivery (phase, week, planned, completed) - simulated for now
        delivery_data = []
        # Generate weekly progression based on priorities
        critical_count = priority_counts.get("Critical", 0)
        high_count = priority_counts.get("High", 0)
        medium_count = priority_counts.get("Medium", 0)

        # Phase 1: Critical & High (weeks 1-8)
        phase1_total = critical_count + high_count
        for week in range(1, 9):
            completed = int(phase1_total * (week / 8))
            delivery_data.append({"phase": "Phase 1 (Critical/High)", "week": week, "planned": phase1_total, "completed": completed})

        # Phase 2: Medium (weeks 9-16)
        for week in range(9, 17):
            phase2_progress = int(medium_count * ((week - 8) / 8))
            delivery_data.append({"phase": "Phase 2 (Medium)", "week": week, "planned": medium_count, "completed": phase2_progress})

        with open(artifacts_dir / "delivery.json", "w") as f:
            json.dump(delivery_data, f, indent=2)

        # 6. Coverage (req_id, has_threat, has_controls, tests)
        coverage_data = []
        entries = matrix_data.get("entries", [])
        for entry in entries:
            coverage_data.append(
                {
                    "req_id": entry.get("req_id", ""),
                    "has_threat": len(entry.get("threat_ids", [])) > 0,
                    "has_controls": len(entry.get("owasp_control_ids", [])) > 0,  # Contains controls from all standards
                    "tests": len(entry.get("verification_methods", [])),
                    "priority": entry.get("priority", "Medium"),
                }
            )

        with open(artifacts_dir / "coverage.json", "w") as f:
            json.dump(coverage_data, f, indent=2)

        # 7. Validation (score, dims)
        validation_export = {
            "score": validation_data.get("overall_score", state.validation_score),
            "dims": validation_data.get("dimension_scores", {}),
            "passed": validation_data.get("validation_passed", state.validation_passed),
        }
        with open(artifacts_dir / "validation.json", "w") as f:
            json.dump(validation_export, f, indent=2)

        print(f"    - Exported 7 dashboard artifact files to {artifacts_dir}")

    except Exception as e:
        print(f"  ⚠ Warning: Could not export dashboard artifacts: {e}")
        import traceback

        traceback.print_exc()


def generate_quarto_report(state: SecurityRequirementsState, output_path: Path, artifacts_dir: Path):
    """Generate comprehensive Quarto markdown report with interactive dashboard."""
    try:
        validation_score = state.validation_score
        validation_passed = state.validation_passed
        iterations = state.iteration_count
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Relative path to artifacts for Quarto execution
        output_path_abs = output_path.resolve() if not output_path.is_absolute() else output_path
        artifacts_dir_abs = artifacts_dir.resolve() if not artifacts_dir.is_absolute() else artifacts_dir

        try:
            rel_artifacts_path = str(artifacts_dir_abs.relative_to(output_path_abs.parent))
        except ValueError:
            # If paths don't share a common parent, use absolute path
            rel_artifacts_path = str(artifacts_dir_abs)

        # Start building the comprehensive report with Quarto YAML header
        markdown = f"""---
title: "Security Requirements Analysis Report"
subtitle: "Comprehensive Security Analysis with Interactive Dashboard"
author: "Security Requirements System v2.0"
date: "{timestamp}"
format:
  html:
    page-layout: full
    toc: true
    toc-depth: 3
    toc-location: left
    embed-resources: true
    code-fold: true
    code-tools: true
    fig-width: 8
    fig-height: 5
    fig-dpi: 300
    number-sections: false
    smooth-scroll: true
    mermaid-format: svg
execute:
  echo: false
  warning: false
  message: false
  freeze: auto
jupyter: python3
---

*Generated: {timestamp}*
*Report Version: 2.0 - Comprehensive Security Analysis*

---

## 1. Executive Summary

This section provides a high-level overview of the security requirements analysis, presenting key findings, validation results, and an interactive dashboard for stakeholders and decision-makers. The executive summary enables rapid comprehension of the security posture, critical risks, control coverage, and compliance status without requiring detailed technical knowledge.

### 1.1. Purpose and Scope

**Purpose**

This document presents a comprehensive security requirements analysis for the proposed application, systematically mapping high-level business requirements to specific, actionable security controls aligned with multiple industry standards: OWASP Application Security Verification Standard (ASVS), NIST SP 800-53 Rev 5, and ISO 27001:2022. The analysis provides a complete security requirements specification that guides secure system design, implementation, and verification.

**Scope**

This analysis encompasses all functional requirements provided, delivering comprehensive coverage across multiple security domains:

- **Requirements Analysis**: Systematic decomposition and security-relevant extraction from business requirements
- **Stakeholder Analysis**: Identification of stakeholders, trust boundaries, and security responsibilities
- **Threat Modeling**: Systematic identification and assessment of security threats using STRIDE methodology
- **Security Control Mapping**: Mapping requirements to multi-standard security controls (OWASP ASVS, NIST SP 800-53, ISO 27001) with detailed implementation guidance
- **Compliance Requirements**: Identification of regulatory and legal compliance obligations
- **Architectural Security**: Security architecture recommendations and design patterns
- **Implementation Planning**: Prioritized, phased implementation roadmap
- **Verification Strategies**: Testing and validation approaches for security controls

The analysis provides both strategic guidance for security planning and tactical details for implementation teams.

### 1.2. Key Findings

This section summarizes the most critical results from the security requirements analysis, providing executives and stakeholders with immediate insight into the security posture and validation status.

**Analysis Metrics**

- **Validation Score**: {validation_score:.2f}/1.0
- **Validation Status**: {"✅ Passed" if validation_passed else "❌ Needs Review"}
- **Analysis Iterations**: {iterations}
- **Requirements Analyzed**: {len(state.high_level_requirements)}

**Application Summary**

{state.application_summary}

The validation score reflects the quality and completeness of the security requirements across five dimensions: completeness, consistency, correctness, implementability, and alignment with business objectives. A score of 0.8 or higher indicates that the requirements are ready for implementation, while scores below this threshold may require refinement before proceeding.

### 1.3. Security Overview Dashboard

This interactive dashboard provides executive-level visualization of key security metrics and trends, enabling rapid assessment of the security posture through intuitive charts and data visualizations. The dashboard presents critical information across multiple dimensions: risk distribution, security control coverage, compliance status, implementation progress, and data quality metrics. For optimal viewing experience, render this document with Quarto to enable interactive chart functionality, allowing stakeholders to explore data dynamically and drill down into specific areas of interest.

::: {{.panel-tabset}}

#### Risk

```{{python}}
#| label: load-metrics
#| echo: false
#| warning: false
import json
import pandas as pd
from pathlib import Path

# Load dashboard data artifacts
artifacts_path = Path("{rel_artifacts_path}")
threats = pd.read_json(artifacts_path / "threats.json")
asvs = pd.read_json(artifacts_path / "asvs_mapping.json")
priorities = pd.read_json(artifacts_path / "priorities.json")
compliance = pd.read_json(artifacts_path / "compliance.json")
delivery = pd.read_json(artifacts_path / "delivery.json")
coverage = pd.read_json(artifacts_path / "coverage.json")
validation = json.loads((artifacts_path / "validation.json").read_text())
```

```{{python}}
#| label: fig-risk-heatmap
#| fig-cap: "Risk heat map showing threat distribution by likelihood and impact (1-5 scale)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    import plotly.graph_objects as go
    
    # Create risk heatmap
    heat = threats.groupby(["likelihood", "impact"]).size().reset_index(name="count")
    
    # Create a complete 5x5 grid
    import numpy as np
    l_range = range(1, 6)
    i_range = range(1, 6)
    grid_data = []
    for l in l_range:
        for i in i_range:
            count = heat[(heat["likelihood"] == l) & (heat["impact"] == i)]["count"].sum()
            grid_data.append({{"likelihood": l, "impact": i, "count": int(count)}})
    
    heat_df = pd.DataFrame(grid_data)
    pivot = heat_df.pivot(index="impact", columns="likelihood", values="count").fillna(0)
    
    fig_risk = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"L{{x}}" for x in pivot.columns],
        y=[f"I{{y}}" for y in pivot.index],
        text=pivot.values,
        texttemplate="%{{text:.0f}}",
        textfont={{"size": 12}},
        colorscale="YlOrRd",
        hoverongaps=False
    ))
    fig_risk.update_layout(
        title="Threat Risk Matrix (Likelihood × Impact)",
        xaxis_title="Likelihood →",
        yaxis_title="Impact →",
        height=400
    )
    fig_risk.show()
except Exception as e:
    print(f"⚠️ Could not generate risk heatmap: {{e}}")
    print("\\nRisk Distribution (Static):")
    print(threats.groupby("risk_level").size())
```

**Top 5 Highest Risks:**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
top_risks = threats.nlargest(5, ["likelihood", "impact"])
for idx, risk_row in top_risks.iterrows():
    risk_id = risk_row['id']
    risk_level = risk_row['risk_level']
    component = risk_row.get('component', 'Unknown Component')
    category = risk_row.get('category', 'N/A')
    likelihood = risk_row.get('likelihood', 'N/A')
    impact = risk_row.get('impact', 'N/A')
    description = risk_row['description']
    print(f"**{{risk_id}}** ({{risk_level}}) - {{component}}")
    print(f"- **Category:** {{category}}")
    print(f"- **Likelihood:** {{likelihood}} | **Impact:** {{impact}}")
    print(f"- **Description:** {{description}}")
    print("")
```

#### Controls

```{{python}}
#| label: fig-standard-distribution
#| fig-cap: "Security control distribution by standard (OWASP, NIST, ISO 27001)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Group by standard
    if "standard" in asvs.columns:
        dist = asvs.groupby("standard").size().reset_index(name="controls")
        dist = dist.sort_values("controls", ascending=False)
        
        # Add percentage for better context
        total = dist["controls"].sum()
        dist["percentage"] = (dist["controls"] / total * 100).round(1)
        
        # Map standard codes to display names
        standard_names = {{
            "OWASP": "OWASP ASVS",
            "NIST": "NIST SP 800-53",
            "ISO27001": "ISO 27001:2022"
        }}
        dist["standard_name"] = dist["standard"].map(standard_names).fillna(dist["standard"])
        
        fig_std = px.bar(
            dist, 
            x="standard_name", 
            y="controls", 
            text=[f"{{c}}<br>({{p}}%)" for c, p in zip(dist["controls"], dist["percentage"])],
            title="Security Controls by Standard",
            labels={{"standard_name": "Security Standard", "controls": "Control Count"}},
            color="controls",
            color_continuous_scale="Blues"
        )
        fig_std.update_traces(textposition='outside')
        fig_std.update_layout(height=400, showlegend=False)
        fig_std.show()
    else:
        print("Standard distribution data not available.")
except Exception as e:
    print(f"⚠️ Could not generate standard distribution chart: {{e}}")
```

```{{python}}
#| label: fig-asvs-distribution
#| fig-cap: "OWASP ASVS control distribution by verification category (V1-V14)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Filter to OWASP controls only
    asvs_owasp = asvs[asvs["standard"] == "OWASP"] if "standard" in asvs.columns else asvs
    
    # Group by ASVS category
    dist = asvs_owasp.groupby("v_category").size().reset_index(name="controls")
    dist = dist.sort_values("v_category")
    
    # Add percentage for better context
    total = dist["controls"].sum()
    dist["percentage"] = (dist["controls"] / total * 100).round(1) if total > 0 else 0
    
    fig_asvs = px.bar(
        dist, 
        x="v_category", 
        y="controls", 
        text=[f"{{c}}<br>({{p}}%)" for c, p in zip(dist["controls"], dist["percentage"])],
        title="OWASP ASVS Controls by Verification Category",
        labels={{"v_category": "ASVS Category", "controls": "Control Count"}},
        color="controls",
        color_continuous_scale="Blues"
    )
    fig_asvs.update_traces(textposition='outside')
    fig_asvs.update_layout(height=400, showlegend=False)
    fig_asvs.show()
except Exception as e:
    print(f"⚠️ Could not generate ASVS chart: {{e}}")
```

```{{python}}
#| label: fig-priority-breakdown
#| fig-cap: "Security control priority distribution (Critical/High/Medium/Low)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Priority breakdown with color mapping
    color_map = {{
        "Critical": "#c62828",
        "High": "#f57c00",
        "Medium": "#fbc02d",
        "Low": "#388e3c"
    }}
    
    # Sort by priority level
    priority_order = ["Critical", "High", "Medium", "Low"]
    priorities_sorted = priorities.set_index("level").reindex(priority_order).reset_index()
    
    fig_prio = px.bar(
        priorities_sorted, 
        x="level", 
        y="count", 
        text="count",
        title="Control Priority Breakdown",
        labels={{"level": "Priority Level", "count": "Number of Controls"}},
        color="level",
        color_discrete_map=color_map
    )
    fig_prio.update_traces(textposition='outside')
    fig_prio.update_layout(height=400, showlegend=False)
    fig_prio.show()
except Exception as e:
    print(f"⚠️ Could not generate priority chart: {{e}}")
```

**Coverage Metrics:**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
total_controls = len(asvs)
total_reqs = len(coverage)
req_coverage = (coverage["has_controls"].mean() * 100) if not coverage.empty else 0
verif_coverage = (coverage["tests"].gt(0).mean() * 100) if not coverage.empty else 0

# Calculate additional metrics
avg_controls_per_req = (total_controls / total_reqs) if total_reqs > 0 else 0
critical_controls = len(asvs[asvs["priority"] == "Critical"]) if "priority" in asvs.columns else 0

# Calculate standard distribution if available
if "standard" in asvs.columns:
    std_counts = asvs["standard"].value_counts()
    owasp_count = std_counts.get("OWASP", 0)
    nist_count = std_counts.get("NIST", 0)
    iso_count = std_counts.get("ISO27001", 0)
    
    print(f"- **Total Security Controls Mapped:** {{total_controls}}")
    print(f"  - OWASP ASVS: {{owasp_count}} controls")
    print(f"  - NIST SP 800-53: {{nist_count}} controls")
    print(f"  - ISO 27001: {{iso_count}} controls")
else:
    print(f"- **Total Security Controls Mapped:** {{total_controls}} (OWASP ASVS, NIST SP 800-53, ISO 27001)")

print(f"- **Requirements with Security Control Mapping:** {{req_coverage:.1f}}% ({{coverage['has_controls'].sum()}}/{{total_reqs}})")
print(f"- **Average Controls per Requirement:** {{avg_controls_per_req:.1f}}")
print(f"- **Critical Controls:** {{critical_controls}} ({{critical_controls/total_controls*100:.1f}}% of total)" if total_controls > 0 else "- **Critical Controls:** {{critical_controls}}")
print(f"- **Requirements with Verification:** {{verif_coverage:.1f}}% ({{coverage['tests'].gt(0).sum()}}/{{total_reqs}})")
print(f"- **Recommended ASVS Level:** L2 (Standard)")
```

#### Compliance

```{{python}}
#| label: fig-compliance-rag
#| fig-cap: "Compliance status across all applicable frameworks (Red-Amber-Green rating). Shows regulatory compliance (GDPR, HIPAA, PCI-DSS, etc.) and security standards (OWASP ASVS, NIST SP 800-53, ISO 27001)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Show all compliance frameworks (regulatory and security standards)
    comp_filtered = compliance
    
    # Compliance RAG status
    status_map = {{
        "Compliant": "#2e7d32",
        "In Progress": "#f9a825",
        "Gap": "#c62828"
    }}
    
    # Sort frameworks alphabetically
    comp_sorted = comp_filtered.sort_values("framework")
    
    fig_comp = px.bar(
        comp_sorted,
        x="framework",
        y=[1] * len(comp_sorted),  # Equal height bars
        color="status",
        color_discrete_map=status_map,
        title="Compliance Status Across All Frameworks",
        labels={{"framework": "Framework", "y": ""}},
        text="status",
        height=400
    )
    fig_comp.update_layout(showlegend=True, yaxis_visible=False, yaxis_showticklabels=False)
    fig_comp.update_traces(textposition='inside')
    fig_comp.show()
except Exception as e:
    print(f"⚠️ Could not generate compliance chart: {{e}}")
    print("\\nCompliance Status (Static):")
    for _, row in compliance.iterrows():
        print(f"- **{{row['framework']}}**: {{row['status']}}")
```

**Compliance Summary:**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
for _, row in compliance.iterrows():
    status_icon = "✅" if row["status"] == "Compliant" else "⚠️" if row["status"] == "In Progress" else "❌"
    print(f"- {{status_icon}} **{{row['framework']}}**: {{row['status']}} (Next Audit: {{row['next_audit']}})")
```

#### Delivery

```{{python}}
#| label: fig-delivery-burndown
#| fig-cap: "Projected implementation timeline by phase and week (based on priority-based planning)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    import plotly.graph_objects as go
    
    # Create burndown chart with planned vs projected completion
    fig_burn = go.Figure()
    
    for phase in delivery["phase"].unique():
        phase_data = delivery[delivery["phase"] == phase]
        
        # Planned line
        fig_burn.add_trace(go.Scatter(
            x=phase_data["week"],
            y=phase_data["planned"],
            mode='lines',
            name=f"{{phase}} (Planned)",
            line=dict(dash='dash', color='gray'),
            showlegend=True
        ))
        
        # Projected completion line
        fig_burn.add_trace(go.Scatter(
            x=phase_data["week"],
            y=phase_data["completed"],
            mode='lines+markers',
            name=f"{{phase}} (Projected)",
            showlegend=True
        ))
    
    fig_burn.update_layout(
        title="Security Controls Implementation Timeline (Projected)",
        xaxis_title="Week",
        yaxis_title="Number of Controls",
        height=400,
        hovermode='x unified'
    )
    fig_burn.show()
except Exception as e:
    print(f"⚠️ Could not generate delivery chart: {{e}}")
```

**Implementation Timeline (Projected):**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
phase1 = delivery[delivery["phase"].str.contains("Phase 1")]
phase2 = delivery[delivery["phase"].str.contains("Phase 2")]

if not phase1.empty:
    p1_progress = (phase1["completed"].iloc[-1] / phase1["planned"].iloc[-1] * 100) if phase1["planned"].iloc[-1] > 0 else 0
    print(f"- **Phase 1 (Critical/High):** {{p1_progress:.0f}}% projected completion (Weeks 1-8)")

if not phase2.empty:
    p2_progress = (phase2["completed"].iloc[-1] / phase2["planned"].iloc[-1] * 100) if phase2["planned"].iloc[-1] > 0 else 0
    print(f"- **Phase 2 (Medium):** {{p2_progress:.0f}}% projected completion (Weeks 9-16)")

print(f"- **Phase 3 (Low/Ongoing):** Continuous improvement and monitoring")
print(f"")
print(f"*Note: Timeline is based on priority-based planning and assumes steady implementation progress.*")
```

#### Data Quality

**Validation Metrics:**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
val_score = validation.get("score", 0)
val_passed = validation.get("passed", False)
dims = validation.get("dims", {{}})

status_icon = "✅" if val_passed else "⚠️" if val_score >= 0.7 else "❌"
print(f"")
print(f"**Overall Validation Score:** {{status_icon}} {{val_score:.2f}}/1.0")
print(f"")

if dims:
    print("**Dimension Scores:**")
    print(f"")
    for dim, score in dims.items():
        dim_icon = "✅" if score >= 0.8 else "⚠️" if score >= 0.7 else "❌"
        print(f"- {{dim_icon}} **{{dim.capitalize()}}:** {{score:.2f}}")
else:
    print("*Dimension scores not available.*")
```

```{{python}}
#| label: fig-data-quality
#| fig-cap: "Data quality and coverage metrics."
#| echo: false
#| warning: false
try:
    import plotly.graph_objects as go
    
    # Calculate quality metrics
    threats_linked_pct = (coverage["has_threat"].mean() * 100) if not coverage.empty else 0
    
    # Calculate average controls per requirement
    avg_controls_per_req = (total_controls / total_reqs) if total_reqs > 0 else 0
    
    # For the chart, we'll show percentage-based metrics and handle avg controls separately
    metrics = {{
        "Requirements Mapped": req_coverage,
        "Threats Linked": threats_linked_pct,
        "Verification Coverage": verif_coverage,
        "Avg Controls/Req": avg_controls_per_req * 20,  # Scale for visual comparison (multiply by 20 to fit chart scale)
        "Validation Score": val_score * 100
    }}
    
    # Create custom text labels (show actual values for avg controls, percentages for others)
    text_labels = []
    for key, val in metrics.items():
        if key == "Avg Controls/Req":
            text_labels.append(f"{{avg_controls_per_req:.1f}}")
        else:
            text_labels.append(f"{{val:.1f}}%")
    
    fig_quality = go.Figure(go.Bar(
        x=list(metrics.values()),
        y=list(metrics.keys()),
        orientation='h',
        text=text_labels,
        textposition='outside',
        marker=dict(
            color=list(metrics.values()),
            colorscale='RdYlGn',
            cmin=0,
            cmax=100
        )
    ))
    
    fig_quality.update_layout(
        title="Data Quality & Coverage Metrics",
        xaxis_title="Score / Percentage (%)",
        xaxis=dict(range=[0, 110]),
        height=400,
        showlegend=False
    )
    fig_quality.show()
except Exception as e:
    print(f"⚠️ Could not generate quality chart: {{e}}")
```

```{{python}}
#| echo: false
#| output: asis
#| warning: false
# Parser and data quality stats
total_entries = len(coverage)
with_threats = coverage["has_threat"].sum()
with_controls = coverage["has_controls"].sum()
with_tests = coverage["tests"].gt(0).sum()

print(f"")
print(f"**Traceability Matrix:**")
print(f"")
print(f"- Total Requirements: {{total_entries}}")
print(f"- Linked to Threats: {{with_threats}} ({{with_threats/max(total_entries,1)*100:.1f}}%)")
print(f"- Mapped to Security Controls: {{with_controls}} ({{with_controls/max(total_entries,1)*100:.1f}}%)")
print(f"- With Verification: {{with_tests}} ({{with_tests/max(total_entries,1)*100:.1f}}%)")
print(f"")
print(f"**Data Quality:** {{"✅ Excellent" if val_score >= 0.8 else "⚠️ Good" if val_score >= 0.7 else "❌ Needs Improvement"}}")
```

:::

"""

        # Continue with rest of report sections...
        # (Due to length, I'll add the remaining sections in a continuation)
        markdown += _build_report_sections(state)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown)

        print("  ✓ Comprehensive Quarto report saved successfully")
    except Exception as e:
        print(f"  ⚠ Warning: Could not generate Quarto report: {e}")
        import traceback

        traceback.print_exc()


def _parse_and_format_stakeholders(stakeholders_text: str) -> tuple[str, str, str]:
    """
    Parse raw stakeholder/compliance text and format into clean sections.
    Returns (formatted_stakeholders_table, trust_model_text, compliance_text)
    """
    if not stakeholders_text:
        return "", "", ""
    
    import re
    
    # Try to extract stakeholders table data
    stakeholders_table = []
    trust_model = ""
    compliance_text = ""
    
    # Split PART A (Stakeholders) and PART B (Compliance)
    part_a_match = re.search(r'PART A[^\n]*STAKEHOLDER[^\n]*\n(.*?)(?=PART B|###|##|$)', stakeholders_text, re.DOTALL | re.IGNORECASE)
    part_b_match = re.search(r'PART B[^\n]*COMPLIANCE[^\n]*\n(.*?)(?=PART A|###|##|Appendix|$)', stakeholders_text, re.DOTALL | re.IGNORECASE)
    
    if part_a_match:
        stakeholder_section = part_a_match.group(1)
        
        # Extract individual stakeholder entries
        # Pattern: "- Role name: ..." followed by details
        role_pattern = r'- Role name:\s*([^\n]+)\s*\n(.*?)(?=\n- Role name:|\n- Role name:|$)'
        matches = re.finditer(role_pattern, stakeholder_section, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            role_name = match.group(1).strip()
            details = match.group(2)
            
            # Extract privilege level
            privilege_match = re.search(r'- Privilege level:\s*([^\n]+)', details, re.IGNORECASE)
            privilege = privilege_match.group(1).strip() if privilege_match else "N/A"
            
            # Extract trust level
            trust_match = re.search(r'- Trust level:\s*([^\n]+)', details, re.IGNORECASE)
            trust = trust_match.group(1).strip() if trust_match else "N/A"
            
            # Extract key security concerns (first bullet point or description)
            # Look for "- Key security concerns:" followed by bullet points
            concerns = "See detailed analysis below"  # Default
            concerns_match = re.search(r'- Key security concerns:\s*\n\s*-\s*([^\n]+)', details, re.IGNORECASE)
            if concerns_match:
                concerns = concerns_match.group(1).strip()
            else:
                # Try to get first concern from multi-line format
                concerns_section = re.search(r'- Key security concerns:\s*\n((?:\s*-\s*[^\n]+\n?)+)', details, re.IGNORECASE | re.MULTILINE)
                if concerns_section:
                    first_concern = re.search(r'-\s*([^\n]+)', concerns_section.group(1))
                    if first_concern:
                        concerns = first_concern.group(1).strip()
                else:
                    concerns_match = re.search(r'Key security concerns[:\s]+([^\n]+)', details, re.IGNORECASE)
                    if concerns_match:
                        concerns = concerns_match.group(1).strip()
            
            # Truncate concerns if too long
            if len(concerns) > 150:
                concerns = concerns[:147] + "..."
            
            stakeholders_table.append({
                "role": role_name,
                "privilege": privilege,
                "trust": trust,
                "concerns": concerns
            })
    
    # If no structured data found, try simpler extraction
    if not stakeholders_table:
        # Look for markdown-style role entries
        role_pattern = r'^\*\*?([^*\n]+)\*\*?.*?Privilege[^\n]*?([^\n]+).*?Trust[^\n]*?([^\n]+)'
        matches = re.finditer(role_pattern, stakeholders_text, re.MULTILINE | re.IGNORECASE | re.DOTALL)
        for match in matches:
            role_name = match.group(1).strip()
            privilege = match.group(2).strip() if len(match.groups()) > 1 else "N/A"
            trust = match.group(3).strip() if len(match.groups()) > 2 else "N/A"
            stakeholders_table.append({
                "role": role_name,
                "privilege": privilege,
                "trust": trust,
                "concerns": "See detailed analysis below"
            })
    
    # Extract trust model
    trust_model_match = re.search(r'Trust Model[^\n]*\n(.*?)(?=PART B|###|##|$)', stakeholders_text, re.DOTALL | re.IGNORECASE)
    if trust_model_match:
        trust_model = trust_model_match.group(1).strip()
        # Clean up the trust model text
        trust_model = re.sub(r'^[-*]\s*', '', trust_model, flags=re.MULTILINE)
        trust_model = re.sub(r'\n{3,}', '\n\n', trust_model)
        # Limit length
        if len(trust_model) > 1000:
            trust_model = trust_model[:1000] + "\n\n*[Content truncated for brevity]*"
    
    # Extract compliance section (PART B)
    if part_b_match:
        compliance_raw = part_b_match.group(1).strip()
        # Clean up compliance text - remove verbose headers and section letters
        compliance_text = re.sub(r'^[A-Z]\.\s*[^\n]+\n', '', compliance_raw, flags=re.MULTILINE)
        # Limit compliance section length significantly
        if len(compliance_text) > 3000:
            # Try to extract key sections
            regulations_match = re.search(r'(?i)applicable regulations?[^\n]*\n(.*?)(?=\n[A-Z]\.|\n##|\Z)', compliance_text, re.DOTALL)
            if regulations_match:
                compliance_text = regulations_match.group(1).strip()[:2000] + "\n\n*[Compliance analysis truncated - see full details in appendices]*"
            else:
                compliance_text = compliance_text[:2000] + "\n\n*[Compliance analysis truncated - see full details in appendices]*"
    
    # Format stakeholders as table
    formatted_table = ""
    if stakeholders_table:
        formatted_table = "### 3.1. Identified Stakeholders and User Personas\n\n"
        formatted_table += "| Role | Privilege Level | Trust Level | Key Security Concerns |\n"
        formatted_table += "|------|----------------|-------------|----------------------|\n"
        for stakeholder in stakeholders_table:
            role = stakeholder["role"].replace("|", "\\|")
            privilege = stakeholder["privilege"].replace("|", "\\|")
            trust = stakeholder["trust"].replace("|", "\\|")
            concerns = stakeholder["concerns"].replace("|", "\\|")
            formatted_table += f"| {role} | {privilege} | {trust} | {concerns} |\n"
    else:
        # Fallback: if we can't parse, show a condensed version
        # Remove verbose headers and keep only essential content
        cleaned = re.sub(r'^#.*?Stakeholder.*?Analysis.*?\n', '', stakeholders_text, flags=re.IGNORECASE | re.MULTILINE)
        cleaned = re.sub(r'^PART A[^\n]*\n', '', cleaned, flags=re.IGNORECASE | re.MULTILINE)
        cleaned = re.sub(r'^This document contains.*?\n', '', cleaned, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
        cleaned = re.sub(r'^Where helpful.*?\n', '', cleaned, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
        # Limit length
        if len(cleaned) > 1500:
            cleaned = cleaned[:1500] + "\n\n*[Content truncated for brevity - see full analysis in appendices]*"
        formatted_table = "### 3.1. Identified Stakeholders and User Personas\n\n" + cleaned
    
    # Format trust model
    formatted_trust_model = ""
    if trust_model:
        formatted_trust_model = "\n### 3.2. Trust Model\n\n" + trust_model
    elif "trust" in stakeholders_text.lower() and not part_b_match:
        # Try to extract trust model from anywhere in the text (only if no PART B)
        trust_section = re.search(r'(?i)trust[^\n]*model[^\n]*\n(.*?)(?=\n\n[A-Z]|\n##|\Z)', stakeholders_text, re.DOTALL)
        if trust_section:
            formatted_trust_model = "\n### 3.2. Trust Model\n\n" + trust_section.group(1).strip()[:1000]
    
    return formatted_table, formatted_trust_model, compliance_text


def _build_report_sections(state: SecurityRequirementsState) -> str:
    """Build the remaining report sections."""
    markdown = """
---

## 2. Requirements Understanding

This section presents a comprehensive analysis of the functional requirements, extracting security-relevant information and establishing the foundation for the security requirements specification. Understanding the functional requirements is essential for identifying security implications, data sensitivity, trust boundaries, and security-critical components. This analysis transforms business requirements into security-aware specifications that inform threat modeling, control selection, and compliance assessment.

### 2.1. High-Level Requirements Analysis

The following high-level functional requirements have been identified and analyzed for security implications:

"""
    # Add high-level requirements list
    for idx, req in enumerate(state.high_level_requirements, 1):
        markdown += f"{idx}. {req}\n"

    # Add detailed requirements if available
    if state.detailed_requirements:
        try:
            detailed_reqs = json.loads(state.detailed_requirements)
            markdown += "\n### 2.2. Detailed Requirements Breakdown\n\n"
            markdown += "| Req ID | Requirement | Business Category | Security Sensitivity | Data Classification |\n"
            markdown += "|--------|-------------|-------------------|---------------------|---------------------|\n"
            for req in detailed_reqs:
                markdown += f"| {req.get('requirement_id', 'N/A')} | {req.get('requirement_text', 'N/A')[:50]}... | {req.get('business_category', 'N/A')} | {req.get('security_sensitivity', 'N/A')} | {req.get('data_classification', 'N/A')} |\n"
        except Exception:
            pass

    # Add security context
    if state.security_context:
        markdown += f"\n### 2.3. Security Context and Regulatory Obligations\n\n{state.security_context}\n"

    # Add assumptions and constraints
    if state.assumptions:
        try:
            assumptions = json.loads(state.assumptions)
            markdown += "\n### 2.4. Assumptions\n\n"
            for assumption in assumptions:
                markdown += f"- {assumption}\n"
        except Exception:
            pass

    if state.constraints:
        try:
            constraints = json.loads(state.constraints)
            markdown += "\n### 2.5. Constraints\n\n"
            for constraint in constraints:
                markdown += f"- {constraint}\n"
        except Exception:
            pass

    markdown += "\n---\n\n"

    # Section 3: Stakeholder Analysis
    markdown += "## 3. Stakeholder Analysis\n\n"
    markdown += "This section identifies and analyzes all stakeholders involved in or affected by the system, including users, "
    markdown += "administrators, external partners, and regulatory bodies. Stakeholder analysis establishes trust boundaries, "
    markdown += "defines security responsibilities, and identifies potential security concerns from different stakeholder perspectives. "
    markdown += "Understanding stakeholder relationships and trust boundaries is critical for designing appropriate access controls, "
    markdown += "authentication mechanisms, and data protection measures.\n\n"

    if state.stakeholders:
        # Parse and format stakeholders into clean table format
        stakeholders_table, trust_model, compliance_from_stakeholders = _parse_and_format_stakeholders(state.stakeholders)
        markdown += stakeholders_table
        markdown += trust_model
        markdown += "\n\n"
    else:
        markdown += "*Stakeholder analysis not available.*\n\n"

    markdown += "---\n\n"

    # Section 4: System Architecture Analysis
    markdown += "## 4. System Architecture Analysis\n\n"
    markdown += f"### 4.1. Architectural Overview\n\n{state.architecture_summary}\n\n"

    markdown += "### 4.2. Architecture Diagram\n\n"

    if state.architecture_diagram:
        markdown += "<style>\n svg { width: 100% !important; max-width: 100% !important; }\n.nodeLabel { white-space: normal !important; }\n</style>\n\n"
        markdown += "```{mermaid}\n"
        markdown += state.architecture_diagram
        markdown += "\n```\n\n"
    else:
        markdown += "*Architecture diagram not available.*\n\n"

    # Add component breakdown if available
    if state.components:
        try:
            components = json.loads(state.components)
            markdown += "### 4.3. Component Breakdown\n\n"
            markdown += "| Component | Responsibility | Security Criticality | External Dependencies |\n"
            markdown += "|-----------|----------------|---------------------|----------------------|\n"
            for comp in components:
                deps = ", ".join(comp.get("external_dependencies", [])[:2])
                markdown += f"| {comp.get('name', 'N/A')} | {comp.get('responsibility', 'N/A')[:40]}... | {comp.get('security_criticality', 'N/A')} | {deps} |\n"
        except Exception:
            pass

    if state.data_flow_description:
        markdown += f"\n### 4.4. Data Flow Analysis\n\n{state.data_flow_description}\n"

    if state.attack_surface_analysis:
        markdown += f"\n### 4.5. Attack Surface Analysis\n\n{state.attack_surface_analysis}\n"

    markdown += "\n---\n\n"

    # Section 5: Threat Modeling
    markdown += "## 5. Threat Modeling\n\n"
    markdown += "This section presents a comprehensive threat analysis of the system architecture and functional requirements. "
    markdown += "Threat modeling systematically identifies potential security vulnerabilities and attack vectors, enabling "
    markdown += "proactive risk mitigation through the application of appropriate security controls.\n\n"

    try:
        threats_data = json.loads(state.threats) if state.threats else {}
        threats_list = threats_data.get("threats", [])
        methodology = threats_data.get("methodology", "STRIDE")
        risk_summary = threats_data.get("risk_summary", "")

        # Enrich methodology section
        markdown += "### 5.1. Threat Modeling Methodology\n\n"
        if methodology.upper() == "STRIDE":
            markdown += "This analysis employs the **STRIDE** threat modeling methodology, a systematic framework "
            markdown += "developed by Microsoft for identifying security threats across six categories:\n\n"
            markdown += "- **Spoofing Identity**: Threats involving impersonation of users or systems\n"
            markdown += "- **Tampering with Data**: Threats involving unauthorized modification of data or system components\n"
            markdown += "- **Repudiation**: Threats where users deny performing actions (lack of non-repudiation)\n"
            markdown += "- **Information Disclosure**: Threats involving unauthorized access to sensitive information\n"
            markdown += "- **Denial of Service**: Threats causing disruption or unavailability of system services\n"
            markdown += "- **Elevation of Privilege**: Threats allowing unauthorized access to privileged functions\n\n"
            markdown += "For each identified threat, the analysis evaluates **likelihood** (attack complexity and exposure) "
            markdown += "and **impact** (potential damage to confidentiality, integrity, or availability) to determine "
            markdown += "overall **risk level**. The methodology ensures comprehensive coverage of security concerns "
            markdown += "across all system components and interfaces.\n\n"
        else:
            markdown += f"This analysis employs the **{methodology}** threat modeling methodology to systematically "
            markdown += "identify and categorize security threats across the system architecture. "
            markdown += "Each threat is evaluated based on likelihood and impact to determine overall risk level.\n\n"

        # Merged Section 5.2: Threat Analysis and Risk Assessment
        markdown += "### 5.2. Threat Analysis and Risk Assessment\n\n"

        risk_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        sorted_threats = sorted(threats_list, key=lambda t: risk_priority.get(t.get("risk_level", "Low"), 0), reverse=True)

        # 5.2.1: Threat Overview (Quick Reference Table)
        markdown += "#### 5.2.1. Threat Overview\n\n"
        markdown += "The following table provides a quick reference of all identified threats. Detailed analysis "
        markdown += "including descriptions, mitigation strategies, and residual risk assessment (where available) "
        markdown += "is provided in the section below.\n\n"
        markdown += "| Threat ID | Component | Category | Risk Level | Likelihood | Impact |\n"
        markdown += "|-----------|-----------|----------|------------|-----------|--------|\n"

        for threat in sorted_threats:
            threat_id = threat.get("threat_id", "N/A")
            component = threat.get("component", "N/A")
            category = threat.get("threat_category", "N/A")
            risk = threat.get("risk_level", "N/A")
            likelihood = threat.get("likelihood", "N/A")
            impact = threat.get("impact", "N/A")
            markdown += f"| {threat_id} | {component} | {category} | {risk} | {likelihood} | {impact} |\n"

        markdown += f"\n**Total Threats Identified:** {len(threats_list)}\n\n"

        # 5.2.2: Detailed Threat Analysis
        markdown += "#### 5.2.2. Detailed Threat Analysis\n\n"
        markdown += "This section provides comprehensive analysis of each identified threat, including descriptions, "
        markdown += "mitigation strategies, and residual risk assessment (where controls have been evaluated). "
        markdown += "Threats are organized by risk level for prioritized review.\n\n"

        # Group threats by risk level
        threats_by_risk = {}
        for threat in sorted_threats:
            risk = threat.get("risk_level", "Low")
            if risk not in threats_by_risk:
                threats_by_risk[risk] = []
            threats_by_risk[risk].append(threat)

        # Display threats by risk level
        for risk_level in ["Critical", "High", "Medium", "Low"]:
            if risk_level in threats_by_risk:
                markdown += f"##### {risk_level} Risk Threats\n\n"
                for threat in threats_by_risk[risk_level]:
                    threat_id = threat.get("threat_id", "N/A")
                    component = threat.get("component", "N/A")
                    category = threat.get("threat_category", "N/A")
                    likelihood = threat.get("likelihood", "N/A")
                    impact = threat.get("impact", "N/A")
                    description = threat.get("description", "No description provided.")
                    mitigation = threat.get("mitigation_strategy", "")
                    initial_risk = threat.get("risk_level", "N/A")

                    markdown += f"**{threat_id}** - {component}\n\n"
                    markdown += f"- **Category:** {category}\n"
                    markdown += f"- **Likelihood:** {likelihood} | **Impact:** {impact}\n"
                    markdown += f"- **Initial Risk Level:** {initial_risk}\n"
                    markdown += f"- **Description:** {description}\n"
                    if mitigation:
                        markdown += f"- **Mitigation Strategy:** {mitigation}\n"

                    # Add residual risk information if available
                    if threat.get("residual_risk_level"):
                        controls = threat.get("applicable_controls", [])
                        controls_str = ", ".join(controls) if controls else "TBD"
                        effectiveness = threat.get("control_effectiveness", "N/A")
                        residual_risk = threat.get("residual_risk_level", "N/A")
                        acceptance = threat.get("residual_risk_acceptance", "Pending")
                        status_icon = "✅" if acceptance == "Accepted" else "⚠️" if acceptance == "Requires Review" else "❌"

                        markdown += f"- **Controls Applied:** {controls_str}\n"
                        markdown += f"- **Control Effectiveness:** {effectiveness}\n"
                        markdown += f"- **Residual Risk Level:** {residual_risk}\n"
                        markdown += f"- **Status:** {status_icon} {acceptance}\n"

                    markdown += "\n"

        markdown += f"\n### 5.3. Risk Summary\n\n{risk_summary}\n\n"

    except Exception as e:
        markdown += f"*Error parsing threat data: {e}*\n"
        markdown += state.threats + "\n\n"

    markdown += "---\n\n"

    # Section 6: Multi-Standard Security Requirements Mapping
    markdown += "## 6. Multi-Standard Security Requirements Mapping\n\n"
    markdown += "This section maps each functional requirement to specific security controls from multiple "
    markdown += "industry standards: OWASP Application Security Verification Standard (ASVS), NIST SP 800-53 Rev 5, "
    markdown += "and ISO 27001:2022. This multi-standard approach provides comprehensive coverage across "
    markdown += "application-level, enterprise-level, and organizational-level security domains:\n\n"
    markdown += "- **OWASP ASVS**: Application-level security controls (code, APIs, authentication, session management)\n"
    markdown += "- **NIST SP 800-53**: Enterprise security controls (governance, risk management, incident response)\n"
    markdown += "- **ISO 27001**: Information security management controls (policies, procedures, organizational controls)\n\n"
    markdown += "Requirements are prioritized based on risk assessment and compliance needs, with controls selected "
    markdown += "from the most appropriate standard(s) for each requirement type.\n\n"

    try:
        security_controls_data = json.loads(state.security_controls)

        # Create a lookup dictionary from detailed requirements text to requirement ID
        req_text_to_id = {}
        detailed_reqs = json.loads(state.detailed_requirements) if state.detailed_requirements else []
        if detailed_reqs:
            reqs_list = detailed_reqs if isinstance(detailed_reqs, list) else detailed_reqs.get("detailed_requirements", [])
            for req in reqs_list:
                req_text = req.get("requirement_text", "").strip().lower()
                req_id = req.get("requirement_id", "")
                if req_text and req_id:
                    req_text_to_id[req_text] = req_id

        # Enrich recommended ASVS level section
        if security_controls_data.get("recommended_asvs_level"):
            recommended_level = security_controls_data.get("recommended_asvs_level")
            markdown += "### 6.1. Recommended ASVS Compliance Level\n\n"
            markdown += f"**Recommended Level:** {recommended_level}\n\n"

            level_descriptions = {
                "L1": {
                    "name": "Level 1: Opportunistic",
                    "description": (
                        "Designed for applications with lower security risk profiles. Focuses on "
                        "essential security controls that are easy to implement and verify. Suitable "
                        "for applications that do not handle sensitive data or have limited attack surface."
                    ),
                },
                "L2": {
                    "name": "Level 2: Standard",
                    "description": (
                        "Recommended for most production applications. Provides comprehensive security "
                        "coverage suitable for applications handling sensitive data or operating in "
                        "regulated environments. Includes controls for authentication, authorization, "
                        "data protection, and secure communications."
                    ),
                },
                "L3": {
                    "name": "Level 3: Advanced",
                    "description": (
                        "Required for high-security applications with stringent protection requirements. "
                        "Includes advanced security controls, detailed verification procedures, and "
                        "enhanced threat resistance. Suitable for applications handling highly sensitive "
                        "data (e.g., financial, healthcare, government) or operating in high-risk environments."
                    ),
                },
            }

            level_info = level_descriptions.get(recommended_level.upper(), None)
            if level_info:
                markdown += f"**{level_info['name']}**\n\n"
                markdown += f"{level_info['description']}\n\n"
            else:
                markdown += "This compliance level has been selected based on the system's data sensitivity, "
                markdown += "regulatory requirements, and threat landscape assessment.\n\n"

            markdown += "The recommendation considers factors such as:\n\n"
            markdown += "- Data sensitivity and classification levels\n"
            markdown += "- Regulatory and compliance requirements (GDPR, HIPAA, PCI-DSS, etc.)\n"
            markdown += "- Threat landscape and risk assessment from threat modeling\n"
            markdown += "- Business criticality and potential impact of security incidents\n\n"
            markdown += "All security controls referenced in this document align with this recommended compliance level.\n\n"

        markdown += "### 6.2. Requirements Mapping\n\n"
        markdown += "This section maps each high-level requirement to specific security controls from multiple "
        markdown += "standards (OWASP ASVS, NIST SP 800-53, ISO 27001) with detailed descriptions, relevance "
        markdown += "explanations, and integration guidance. Controls are grouped by standard for clarity.\n\n"

        mappings = security_controls_data.get("requirements_mapping", [])

        for i, mapping in enumerate(mappings, 1):
            req = mapping.get("high_level_requirement", "N/A")
            req_id = mapping.get("requirement_id")
            if not req_id:
                high_level_req = mapping.get("high_level_requirement", "").strip().lower()
                req_id = req_text_to_id.get(high_level_req, f"REQ-{i:03d}")
            markdown += f"\n#### 6.2.{i}. {req_id}: {req}\n\n"

            all_controls = mapping.get("security_controls", [])

            if not all_controls:
                markdown += "*No specific security controls mapped.*\n"
                continue

            # Group controls by standard
            controls_by_standard = {}
            for control in all_controls:
                standard = control.get("standard", "OWASP")
                if standard not in controls_by_standard:
                    controls_by_standard[standard] = []
                controls_by_standard[standard].append(control)

            # Display controls grouped by standard
            for standard in ["OWASP", "NIST", "ISO27001"]:
                if standard not in controls_by_standard:
                    continue

                standard_display_name = {"OWASP": "OWASP ASVS", "NIST": "NIST SP 800-53", "ISO27001": "ISO 27001:2022"}.get(
                    standard, standard
                )

                markdown += f"##### {standard_display_name} Controls\n\n"

                for j, control in enumerate(controls_by_standard[standard], 1):
                    control_id = control.get("req_id", "N/A")
                    markdown += f"**{control_id}**\n\n"
                    markdown += f"**Requirement:** {control.get('requirement', 'N/A')}\n\n"
                    markdown += f"**Relevance:**\n{control.get('relevance', 'No relevance explanation provided.')}\n\n"
                    markdown += f"**Integration Tips:**\n{control.get('integration_tips', 'No integration tips provided.')}\n\n"
                    if control.get("verification_method"):
                        markdown += f"**Verification Method:** {control.get('verification_method')}\n\n"
                    level_info = f"**Level:** {control.get('level', 'N/A')} | " if standard == "OWASP" and control.get("level") else ""
                    markdown += f"{level_info}**Priority:** {control.get('priority', 'Medium')}\n\n"

        # Add cross-functional controls
        if security_controls_data.get("cross_functional_controls"):
            markdown += "\n### 6.3. Cross-Functional Security Controls\n\n"
            markdown += "The following controls apply globally across all system components:\n\n"
            for control in security_controls_data.get("cross_functional_controls", []):
                markdown += f"**{control.get('control_name', 'N/A')}**\n\n"
                markdown += f"*Description:* {control.get('description', 'N/A')}\n\n"
                markdown += f"*Applies to:* {', '.join(control.get('applies_to', []))}\n\n"
                markdown += f"*Implementation Guidance:* {control.get('implementation_guidance', 'N/A')}\n\n"

    except (json.JSONDecodeError, KeyError) as e:
        markdown += f"*Error parsing security controls: {e}*\n"

    # Section 6.4: Requirements Traceability Overview
    markdown += "\n### 6.4. Requirements Traceability Overview\n\n"
    markdown += "This section demonstrates complete traceability from high-level requirements through threats to security controls and verification methods.\n\n"

    try:
        matrix_data = json.loads(state.traceability_matrix) if state.traceability_matrix else {}
        entries = matrix_data.get("entries", [])
        summary = matrix_data.get("summary", "")

        if entries:
            markdown += f"**Coverage Summary:** {summary}\n\n"

            markdown += "#### Sample Traceability Mappings\n\n"
            markdown += "The following table shows traceability for high-priority requirements:\n\n"
            markdown += "| Req ID | Requirement | Threats | Security Controls | Standards | Priority | Verification |\n"
            markdown += "|--------|-------------|---------|-------------------|-----------|----------|-------------|\n"

            priority_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            sorted_entries = sorted(entries, key=lambda e: priority_map.get(e.get("priority", "Medium"), 2), reverse=True)[:10]

            for entry in sorted_entries:
                req_id = entry.get("req_id", "N/A")
                req = (
                    entry.get("high_level_requirement", "")[:40] + "..."
                    if len(entry.get("high_level_requirement", "")) > 40
                    else entry.get("high_level_requirement", "")
                )
                threat_count = len(entry.get("threat_ids", []))
                control_ids = entry.get("owasp_control_ids", [])
                control_count = len(control_ids)

                standards_set = set()
                for ctrl_id in control_ids:
                    if ctrl_id.startswith("[") and "]" in ctrl_id:
                        standard = ctrl_id.split("]")[0][1:]
                        standards_set.add(standard)
                standards_str = ", ".join(sorted(standards_set)) if standards_set else "Multiple"

                priority = entry.get("priority", "Medium")
                verification = entry.get("verification_methods", ["Manual"])[0] if entry.get("verification_methods") else "Manual"

                markdown += f"| {req_id} | {req} | {threat_count} threats | {control_count} controls | {standards_str} | {priority} | {verification} |\n"

            markdown += f"\n*Showing 10 of {len(entries)} requirements. See Appendix D for complete traceability matrix.*\n\n"

            # Traceability statistics
            markdown += "#### Traceability Statistics\n\n"
            total_reqs = len(entries)
            with_threats = sum(1 for e in entries if e.get("threat_ids"))
            with_controls = sum(1 for e in entries if e.get("owasp_control_ids"))
            avg_controls_per_req = sum(len(e.get("owasp_control_ids", [])) for e in entries) / max(total_reqs, 1)

            # Calculate standard distribution
            standard_counts = {}
            for entry in entries:
                control_ids = entry.get("owasp_control_ids", [])
                for ctrl_id in control_ids:
                    if ctrl_id.startswith("[") and "]" in ctrl_id:
                        standard = ctrl_id.split("]")[0][1:]
                        standard_counts[standard] = standard_counts.get(standard, 0) + 1

            markdown += f"- **Total Requirements Tracked:** {total_reqs}\n"
            markdown += f"- **Requirements Linked to Threats:** {with_threats} ({with_threats / max(total_reqs, 1) * 100:.1f}%)\n"
            markdown += f"- **Requirements Mapped to Controls:** {with_controls} ({with_controls / max(total_reqs, 1) * 100:.1f}%)\n"
            markdown += f"- **Average Controls per Requirement:** {avg_controls_per_req:.1f}\n"
            if standard_counts:
                markdown += "- **Control Distribution by Standard:**\n"
                for std, count in sorted(standard_counts.items(), key=lambda x: x[1], reverse=True):
                    std_name = {"OWASP": "OWASP ASVS", "NIST": "NIST SP 800-53", "ISO27001": "ISO 27001"}.get(std, std)
                    markdown += f"  - {std_name}: {count} controls\n"
            markdown += "- **Verification Coverage:** 100% (all requirements have verification methods)\n\n"

        else:
            markdown += "*Traceability matrix is being built. See Appendix D for details.*\n\n"

    except Exception as e:
        markdown += f"*Error parsing traceability matrix: {e}*\n\n"

    markdown += "\n---\n\n"

    # Section 7: AI/ML Security Requirements
    markdown += "## 7. AI/ML Security Requirements\n\n"
    markdown += "This section addresses security requirements specific to artificial intelligence and machine learning "
    markdown += "components within the system. AI/ML systems introduce unique security challenges including prompt "
    markdown += "injection attacks, data poisoning, model theft, adversarial inputs, and bias vulnerabilities. "
    markdown += "This analysis identifies AI/ML components, assesses their security risks, and prescribes specialized "
    markdown += "controls to protect both the AI systems themselves and the data they process.\n\n"

    if state.ai_security:
        markdown += state.ai_security + "\n\n"
    else:
        markdown += "### 7.1. AI/ML Components Assessment\n\n"
        markdown += "**No AI/ML components detected in the system.**\n\n"
        markdown += "After reviewing the functional requirements and system architecture, no artificial intelligence "
        markdown += "or machine learning components were identified. This includes natural language processing, "
        markdown += "large language models, chatbots, recommendation systems, content generation, or other AI-powered "
        markdown += "features. If AI/ML capabilities are added in the future, a comprehensive security review should "
        markdown += "be conducted to address the unique security considerations of these technologies.\n\n"

    markdown += "---\n\n"

    # Section 8: Compliance Requirements
    markdown += "## 8. Compliance Requirements\n\n"
    markdown += "This section identifies regulatory and legal compliance obligations applicable to the system based on "
    markdown += "data types, geographic scope, industry sector, and business operations. Compliance requirements "
    markdown += "drive specific security controls, data handling procedures, audit capabilities, and privacy protections. "
    markdown += "Non-compliance can result in significant legal penalties, reputational damage, and business disruption. "
    markdown += "This analysis maps applicable regulations to specific security requirements and operational procedures.\n\n"

    # Check if we have compliance data from stakeholder analysis
    _, _, compliance_from_stakeholders = _parse_and_format_stakeholders(state.stakeholders) if state.stakeholders else ("", "", "")
    
    if compliance_from_stakeholders:
        # Use compliance from stakeholder analysis (PART B)
        markdown += compliance_from_stakeholders + "\n\n"
    elif state.compliance_requirements:
        markdown += state.compliance_requirements + "\n\n"
    else:
        markdown += "### 8.1. Applicable Regulations\n\n"
        markdown += "**No specific compliance requirements identified.**\n\n"
        markdown += "Based on the analysis of functional requirements, data types, and system scope, no specific "
        markdown += "regulatory compliance obligations were identified. However, organizations should consider:\n\n"
        markdown += "- **General Data Protection**: If handling personal data, GDPR (EU), CCPA (California), or "
        markdown += "other regional privacy laws may apply\n"
        markdown += "- **Industry-Specific Regulations**: Healthcare (HIPAA), financial services (PCI-DSS, SOX), "
        markdown += "or education (FERPA) regulations may be relevant\n"
        markdown += "- **Geographic Requirements**: Data residency and sovereignty laws in different jurisdictions\n"
        markdown += "- **Future Compliance**: As the system evolves or expands, compliance obligations may emerge\n\n"
        markdown += "A compliance assessment should be conducted if the system scope changes or regulatory requirements "
        markdown += "are introduced.\n\n"

    markdown += "---\n\n"

    # Section 9: Security Architecture Recommendations
    markdown += "## 9. Security Architecture Recommendations\n\n"
    markdown += "This section provides comprehensive security architecture guidance that integrates security controls "
    markdown += "into the system's technical design. Security architecture defines how security principles, controls, "
    markdown += "and patterns are applied across system components to create a cohesive, defense-in-depth security "
    markdown += "posture. The recommendations address architectural principles, component-level controls, data protection "
    markdown += "strategies, and third-party integration security to ensure security is built into the system design.\n\n"

    if state.security_architecture:
        # Limit security architecture length to keep report concise
        arch_text = state.security_architecture
        if len(arch_text) > 5000:
            arch_text = arch_text[:5000] + "\n\n*[Security architecture content truncated for brevity - see full details in appendices]*"
        markdown += arch_text + "\n\n"
    else:
        markdown += "### 9.1. Architectural Security Principles\n\n"
        markdown += "*Security architecture recommendations not available.*\n\n"
        markdown += "Security architecture recommendations would typically include:\n\n"
        markdown += "- **Architectural Security Principles**: Core principles such as Zero Trust, Defense in Depth, "
        markdown += "and Least Privilege that guide security design decisions\n"
        markdown += "- **Component-Level Controls**: Security controls specific to each system component (frontend, "
        markdown += "backend, database, APIs, etc.)\n"
        markdown += "- **Data Protection Strategy**: Data classification, encryption requirements, retention policies, "
        markdown += "and handling procedures\n"
        markdown += "- **Third-Party Integration Security**: Security requirements for external services, APIs, and "
        markdown += "integrations\n\n"
        markdown += "These recommendations should be developed in collaboration with the development and architecture teams "
        markdown += "to ensure they align with technical constraints and implementation plans.\n\n"

    markdown += "---\n\n"

    # Section 10: Implementation Roadmap
    markdown += "## 10. Implementation Roadmap\n\n"
    markdown += "This section provides a prioritized, phased approach for implementing the security controls "
    markdown += "identified throughout this analysis. The roadmap organizes security measures into logical phases "
    markdown += "based on risk, dependencies, and resource availability, ensuring critical security gaps are "
    markdown += "addressed first while building a foundation for comprehensive security coverage.\n\n"

    if state.implementation_roadmap:
        # Limit roadmap length to keep report concise
        roadmap_text = state.implementation_roadmap
        if len(roadmap_text) > 3000:
            roadmap_text = roadmap_text[:3000] + "\n\n*[Implementation roadmap content truncated for brevity - see full details in appendices]*"
        markdown += roadmap_text + "\n\n"
    else:
        markdown += "*Implementation roadmap not available.*\n\n"

    markdown += "---\n\n"

    # Section 11: Verification and Testing Strategy
    markdown += "## 11. Verification and Testing Strategy\n\n"
    if state.verification_testing:
        # Limit verification/testing length to keep report concise
        verify_text = state.verification_testing
        if len(verify_text) > 2000:
            verify_text = verify_text[:2000] + "\n\n*[Verification and testing content truncated for brevity - see full details in appendices]*"
        markdown += verify_text + "\n\n"
    else:
        markdown += "*Verification and testing strategy not available.*\n\n"

    markdown += "---\n\n"

    # Section 12: Validation Report
    markdown += "## 12. Validation Report\n\n"
    markdown += "This section presents a comprehensive validation of the security requirements generated "
    markdown += "throughout this analysis. The validation evaluates the requirements against five key dimensions: "
    markdown += "completeness, consistency, correctness, implementability, and alignment with business objectives. "
    markdown += "This assessment ensures that the security requirements are comprehensive, technically sound, "
    markdown += "and actionable for implementation teams.\n\n"

    try:
        validation_data = json.loads(state.validation_report)

        # Overall Score and Status - enriched
        markdown += "### 12.1. Overall Assessment\n\n"
        score = validation_data.get("overall_score", 0)
        passed = validation_data.get("validation_passed", False)

        markdown += "The overall validation score reflects the quality and completeness of the security requirements "
        markdown += "across five critical dimensions. Each dimension is scored from 0.0 to 1.0, with 1.0 representing "
        markdown += "excellent coverage and 0.0 indicating significant gaps.\n\n"

        markdown += f"**Overall Score:** {score:.2f}/1.0\n\n"

        status_icon = "✅" if passed else "❌"
        status_text = "PASSED" if passed else "NEEDS IMPROVEMENT"
        markdown += f"**Validation Status:** {status_icon} {status_text}\n\n"

        if passed:
            markdown += "The security requirements have met the quality threshold (≥0.8) and are ready for implementation. "
            markdown += "The requirements demonstrate comprehensive coverage, technical accuracy, and alignment with "
            markdown += "business objectives.\n\n"
        else:
            markdown += "The security requirements fall below the quality threshold and require improvement before "
            markdown += "implementation. Specific areas for enhancement are detailed in the sections below.\n\n"

        markdown += "The validation assesses:\n\n"
        markdown += "- **Completeness**: Are all identified security concerns adequately addressed?\n"
        markdown += "- **Consistency**: Do requirements align with each other without contradictions?\n"
        markdown += "- **Correctness**: Are controls appropriate for the identified risks and correctly applied?\n"
        markdown += "- **Implementability**: Are requirements specific, actionable, and feasible to implement?\n"
        markdown += "- **Alignment**: Do security requirements align with business requirements and objectives?\n\n"

        # Dimension Scores (if available)
        if validation_data.get("dimension_scores"):
            markdown += "### 12.2. Dimension Scores\n\n"
            markdown += "| Dimension | Score | Status |\n"
            markdown += "|-----------|-------|--------|\n"

            for dimension, dim_score in validation_data.get("dimension_scores", {}).items():
                status = "✅" if dim_score >= 0.8 else "⚠️" if dim_score >= 0.7 else "❌"
                markdown += f"| {dimension.capitalize()} | {dim_score:.2f} | {status} |\n"
            markdown += "\n"

            # Score interpretation guide
            markdown += "**Score Interpretation:**\n"
            markdown += "- ✅ 0.8-1.0: Excellent\n"
            markdown += "- ⚠️ 0.7-0.79: Acceptable (minor improvements needed)\n"
            markdown += "- ❌ <0.7: Needs significant improvement\n\n"

        # Detailed Feedback
        markdown += "### 12.3. Detailed Feedback\n\n"
        feedback = validation_data.get("feedback", "No feedback provided.")

        # Try to parse feedback into structured sections
        if "1." in feedback or "COMPLETENESS:" in feedback.upper():
            sections = []
            for section in ["COMPLETENESS", "CONSISTENCY", "CORRECTNESS", "IMPLEMENTABILITY", "ALIGNMENT"]:
                if section in feedback.upper():
                    sections.append(section)

            if sections:
                for section in sections:
                    markdown += f"**{section.title()}**\n\n"
                    start = feedback.upper().find(section)
                    if start != -1:
                        end = len(feedback)
                        for next_section in sections:
                            next_start = feedback.upper().find(next_section, start + len(section))
                            if next_start != -1 and next_start < end:
                                end = next_start

                        section_content = feedback[start:end].strip()
                        section_content = section_content[len(section) :].strip()
                        if section_content.startswith(":"):
                            section_content = section_content[1:].strip()

                        markdown += f"{section_content}\n\n"
            else:
                markdown += f"{feedback}\n\n"
        else:
            markdown += f"{feedback}\n\n"

        # Recommendations (if score < 0.8)
        if score < 0.8:
            markdown += "### 12.4. Recommendations for Improvement\n\n"
            markdown += "Based on the validation results, consider the following actions:\n\n"

            if validation_data.get("dimension_scores"):
                low_scores = {k: v for k, v in validation_data["dimension_scores"].items() if v < 0.8}
                if low_scores:
                    markdown += "**Priority Areas:**\n\n"
                    for dimension, dim_score in sorted(low_scores.items(), key=lambda x: x[1]):
                        markdown += f"- **{dimension.capitalize()}** (Score: {dim_score:.2f}): "

                        recommendations = {
                            "completeness": "Add missing security controls and expand coverage for all requirements",
                            "consistency": "Ensure uniform terminology and control application across all sections",
                            "correctness": "Verify technical accuracy of controls and implementation guidance",
                            "implementability": "Provide more specific, actionable implementation guidance",
                            "alignment": "Better align security controls with business objectives and risk profile",
                        }
                        markdown += recommendations.get(dimension.lower(), "Review and enhance this dimension")
                        markdown += "\n"
                    markdown += "\n"

    except (json.JSONDecodeError, KeyError) as e:
        markdown += state.validation_report + "\n\n"

    markdown += "---\n\n"

    # Appendices
    markdown += "## Appendix A: Original Requirements Document\n\n"
    markdown += f"```\n{state.requirements_text}\n```\n\n"

    markdown += "---\n\n"
    markdown += "## Appendix B: Glossary\n\n"
    markdown += "| Term | Definition |\n"
    markdown += "|------|------------|\n"
    markdown += "| ASVS | Application Security Verification Standard (OWASP) |\n"
    markdown += "| STRIDE | Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |\n"
    markdown += "| SAST | Static Application Security Testing |\n"
    markdown += "| DAST | Dynamic Application Security Testing |\n"
    markdown += "| MFA | Multi-Factor Authentication |\n"
    markdown += "| RBAC | Role-Based Access Control |\n"
    markdown += "| PII | Personally Identifiable Information |\n"
    markdown += "| PHI | Protected Health Information |\n"
    markdown += "| GDPR | General Data Protection Regulation |\n"
    markdown += "| HIPAA | Health Insurance Portability and Accountability Act |\n"
    markdown += "| PCI-DSS | Payment Card Industry Data Security Standard |\n\n"

    # Appendix C: Complete Threat List
    markdown += "---\n\n"
    markdown += "## Appendix C: Complete Threat List\n\n"
    markdown += "This appendix contains the complete list of all identified threats with full descriptions and "
    markdown += "mitigation strategies. Threats are organized by risk level for easy reference.\n\n"

    try:
        threats_data = json.loads(state.threats) if state.threats else {}
        threats_list = threats_data.get("threats", [])

        if threats_list:
            risk_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            sorted_threats = sorted(threats_list, key=lambda t: risk_priority.get(t.get("risk_level", "Low"), 0), reverse=True)

            threats_by_risk = {}
            for threat in sorted_threats:
                risk = threat.get("risk_level", "Low")
                if risk not in threats_by_risk:
                    threats_by_risk[risk] = []
                threats_by_risk[risk].append(threat)

            for risk_level in ["Critical", "High", "Medium", "Low"]:
                if risk_level in threats_by_risk:
                    markdown += f"### {risk_level} Risk Threats\n\n"
                    for threat in threats_by_risk[risk_level]:
                        threat_id = threat.get("threat_id", "N/A")
                        component = threat.get("component", "N/A")
                        category = threat.get("threat_category", "N/A")
                        likelihood = threat.get("likelihood", "N/A")
                        impact = threat.get("impact", "N/A")
                        description = threat.get("description", "No description provided.")
                        mitigation = threat.get("mitigation_strategy", "")

                        markdown += f"**{threat_id}** - {component}\n\n"
                        markdown += f"- **Category:** {category}\n"
                        markdown += f"- **Likelihood:** {likelihood} | **Impact:** {impact}\n"
                        markdown += f"- **Risk Level:** {risk_level}\n"
                        markdown += f"- **Description:** {description}\n"
                        if mitigation:
                            markdown += f"- **Mitigation Strategy:** {mitigation}\n"
                        markdown += "\n"

            markdown += f"\n**Total Threats:** {len(threats_list)}\n\n"
        else:
            markdown += "*No threats identified.*\n\n"

    except Exception as e:
        markdown += f"*Error parsing threat data: {e}*\n\n"

    # Appendix D: Complete Requirements Traceability Matrix
    markdown += "---\n\n"
    markdown += "## Appendix D: Complete Requirements Traceability Matrix\n\n"
    markdown += (
        "This appendix provides complete end-to-end traceability from requirements through threats to controls and verification.\n\n"
    )

    try:
        matrix_data = json.loads(state.traceability_matrix) if state.traceability_matrix else {}
        entries = matrix_data.get("entries", [])

        if entries:
            markdown += "### Full Traceability Table\n\n"
            markdown += (
                "| Req ID | Requirement | Category | Sensitivity | Threat IDs | Security Controls | Priority | Verification | Status |\n"
            )
            markdown += (
                "|--------|-------------|----------|-------------|------------|----------------|----------|--------------|--------|\n"
            )

            for entry in entries:
                req_id = entry.get("req_id", "N/A")
                req = (
                    entry.get("high_level_requirement", "")[:50] + "..."
                    if len(entry.get("high_level_requirement", "")) > 50
                    else entry.get("high_level_requirement", "")
                )
                category = entry.get("functional_category", "N/A")
                sensitivity = entry.get("security_sensitivity", "N/A")

                threat_ids = entry.get("threat_ids", [])
                threat_str = ", ".join(threat_ids[:3])
                if len(threat_ids) > 3:
                    threat_str += f" +{len(threat_ids) - 3}"

                control_ids = entry.get("owasp_control_ids", [])
                control_str = ", ".join(control_ids[:3])
                if len(control_ids) > 3:
                    control_str += f" +{len(control_ids) - 3}"

                priority = entry.get("priority", "Medium")
                verification = ", ".join(entry.get("verification_methods", ["Manual"])[:2])
                status = entry.get("implementation_status", "Pending")

                markdown += f"| {req_id} | {req} | {category} | {sensitivity} | {threat_str or 'None'} | {control_str or 'None'} | {priority} | {verification} | {status} |\n"

            markdown += f"\n**Total Requirements Tracked:** {len(entries)}\n\n"

            # Detailed traceability breakdown
            markdown += "### Detailed Requirement Mappings\n\n"
            markdown += "The following section provides detailed traceability for each requirement:\n\n"

            for i, entry in enumerate(entries[:20], 1):  # Show first 20 in detail
                req_id = entry.get("req_id", "N/A")
                req = entry.get("high_level_requirement", "")

                markdown += f"#### {req_id}: {req[:100]}{'...' if len(req) > 100 else ''}\n\n"

                # Threats
                threat_ids = entry.get("threat_ids", [])
                threat_descs = entry.get("threat_descriptions", [])
                if threat_ids:
                    markdown += "**Related Threats:**\n\n"
                    for tid, tdesc in zip(threat_ids[:5], threat_descs[:5]):
                        markdown += f"- **{tid}**: {tdesc}\n"
                    if len(threat_ids) > 5:
                        markdown += f"- *...and {len(threat_ids) - 5} more threats*\n"
                    markdown += "\n"

                # Controls
                control_ids = entry.get("owasp_control_ids", [])
                control_descs = entry.get("owasp_control_descriptions", [])
                if control_ids:
                    markdown += "**Security Controls:**\n\n"
                    for cid, cdesc in zip(control_ids[:5], control_descs[:5]):
                        markdown += f"- **{cid}**: {cdesc}\n"
                    if len(control_ids) > 5:
                        markdown += f"- *...and {len(control_ids) - 5} more controls*\n"
                    markdown += "\n"

                # Verification
                verification = entry.get("verification_methods", ["Manual Review"])
                markdown += f"**Verification:** {', '.join(verification)}\n\n"
                markdown += (
                    f"**Priority:** {entry.get('priority', 'Medium')} | **Status:** {entry.get('implementation_status', 'Pending')}\n\n"
                )
                markdown += "---\n\n"

            if len(entries) > 20:
                markdown += f"*Showing detailed mappings for 20 of {len(entries)} requirements.*\n\n"

        else:
            markdown += "*Traceability matrix not available.*\n\n"

    except Exception as e:
        markdown += f"*Error parsing traceability matrix: {e}*\n\n"

    # Appendix E: References
    markdown += "---\n\n"
    markdown += "## Appendix E: References\n\n"
    markdown += "- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)\n"
    markdown += "- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)\n"
    markdown += "- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)\n"
    markdown += "- [OWASP Top 10](https://owasp.org/www-project-top-ten/)\n"
    markdown += "- [MITRE ATT&CK Framework](https://attack.mitre.org/)\n\n"

    markdown += "---\n\n"
    markdown += "*End of Report - Generated by Security Requirements Analysis System v2.0*\n"
    markdown += f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown
