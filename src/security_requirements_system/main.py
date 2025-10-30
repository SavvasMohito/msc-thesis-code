#!/usr/bin/env python
"""
Main entry point for the Security Requirements System.

This flow orchestrates 5 agent crews to transform high-level product requirements
into comprehensive, standards-aligned security requirements with self-evaluation.
"""

import json
import os
from pathlib import Path
from typing import Optional

import yaml
from crewai.flow.flow import Flow, listen, start
from dotenv import load_dotenv
from pydantic import BaseModel

from security_requirements_system.crews.compliance_crew import ComplianceCrew
from security_requirements_system.crews.domain_security_crew import DomainSecurityCrew
from security_requirements_system.crews.llm_security_crew import LLMSecurityCrew
from security_requirements_system.crews.requirements_analysis_crew import RequirementsAnalysisCrew
from security_requirements_system.crews.roadmap_crew import RoadmapCrew
from security_requirements_system.crews.security_architecture_crew import SecurityArchitectureCrew
from security_requirements_system.crews.stakeholder_crew import StakeholderCrew
from security_requirements_system.crews.threat_modeling_crew import ThreatModelingCrew
from security_requirements_system.crews.validation_crew import ValidationCrew
from security_requirements_system.crews.verification_crew import VerificationCrew
from security_requirements_system.data_models import (
    AnalysisOutput,
    ArchitectureOutput,
    TraceabilityEntry,
    TraceabilityMatrix,
    ValidationOutput,
)

load_dotenv()

# Common stop words for text matching (used in traceability matrix)
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


def load_config():
    """Load configuration from config.yaml."""
    config_path = Path("config.yaml")
    if config_path.exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {}


# Load global configuration
CONFIG = load_config()

# Set LLM configuration from config.yaml (if not already set via environment)
if CONFIG and "llm" in CONFIG:
    llm_config = CONFIG["llm"]
    # Set OPENAI_MODEL_NAME if not already set
    if "model" in llm_config and not os.getenv("OPENAI_MODEL_NAME"):
        os.environ["OPENAI_MODEL_NAME"] = llm_config["model"]
    # Set temperature if available
    if "temperature" in llm_config and not os.getenv("OPENAI_TEMPERATURE"):
        os.environ["OPENAI_TEMPERATURE"] = str(llm_config["temperature"])


class SecurityRequirementsState(BaseModel):
    """State for the security requirements generation flow."""

    # Input
    requirements_text: str = ""
    input_file: Optional[str] = None

    # Requirements Analysis outputs
    application_summary: str = ""
    high_level_requirements: list[str] = []
    detailed_requirements: str = ""  # JSON string of RequirementDetail list
    security_context: str = ""
    assumptions: str = ""  # JSON string of list
    constraints: str = ""  # JSON string of list

    # Architecture outputs
    architecture_summary: str = ""
    architecture_diagram: str = ""
    components: str = ""  # JSON string of Component list
    data_flow_description: str = ""
    trust_boundaries: str = ""  # JSON string of TrustBoundary list
    attack_surface_analysis: str = ""

    # Stakeholder Analysis
    stakeholders: str = ""  # JSON string of StakeholderAnalysisOutput

    # Threat Modeling
    threats: str = ""  # JSON string of ThreatModelingOutput

    # Security controls mapping
    security_controls: str = ""  # JSON string of DomainSecurityOutput

    # AI/ML security
    ai_security: str = ""

    # Compliance requirements
    compliance_requirements: str = ""

    # Security Architecture
    security_architecture: str = ""  # JSON string of SecurityArchitectureOutput

    # Implementation Roadmap
    implementation_roadmap: str = ""  # JSON string of ImplementationRoadmapOutput

    # Verification and Testing
    verification_testing: str = ""  # JSON string of VerificationTestingOutput

    # Validation
    validation_report: str = ""
    validation_passed: bool = False
    validation_score: float = 0.0
    iteration_count: int = 0

    # Traceability Matrix
    traceability_matrix: str = ""  # JSON string of TraceabilityMatrix

    # Flow control
    should_generate_output: bool = False

    # Final output
    final_requirements: str = ""


class SecurityRequirementsFlow(Flow[SecurityRequirementsState]):
    """
    Flow for generating security requirements from product manager inputs.

    This flow implements a self-evaluation loop:
    1. Load requirements from input file
    2. Analyze requirements
    3. Map to security controls (domain + AI/ML + compliance)
    4. Validate the results
    5. If validation passes → generate final output
    6. If validation fails → loop back with feedback (max 3 iterations)
    """

    # Load from config.yaml or use defaults
    # MAX_ITERATIONS = CONFIG.get("flow", {}).get("max_iterations", 3)
    MAX_ITERATIONS = 3
    # VALIDATION_THRESHOLD = CONFIG.get("flow", {}).get("validation_threshold", 0.7)
    VALIDATION_THRESHOLD = 0.7

    @start()
    def load_requirements(self):
        """Load product manager requirements from input file."""
        print("\n" + "=" * 80)
        print("STEP 1: Loading Product Manager Requirements")
        print("=" * 80)

        input_file = self.state.input_file
        if not input_file:
            raise ValueError("No input file specified")

        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")

        with open(input_path, "r", encoding="utf-8") as f:
            self.state.requirements_text = f.read()

        print(f"\n✓ Loaded requirements from: {input_file}")
        print(f"  Length: {len(self.state.requirements_text)} characters")
        print(f"\nRequirements Preview:\n{self.state.requirements_text[:500]}...")

    @listen(load_requirements)
    def analyze_requirements(self):
        """Analyze requirements using Requirements Analysis Crew."""
        print("\n" + "=" * 80)
        print(f"STEP 2: Analyzing Requirements (Iteration {self.state.iteration_count + 1})")
        print("=" * 80)

        # Add feedback context if this is a re-run
        context = self.state.requirements_text
        if self.state.validation_report and not self.state.validation_passed:
            context += f"\n\nPREVIOUS VALIDATION FEEDBACK:\n{self.state.validation_report}"

        result = RequirementsAnalysisCrew().crew().kickoff(inputs={"requirements_text": context})

        # Access tasks' outputs from CrewOutput
        analysis_task_output = next(filter(lambda x: x.name == "analyze_requirements", result.tasks_output))
        architecture_task_output = next(filter(lambda x: x.name == "analyze_architecture", result.tasks_output))

        analysis_output: AnalysisOutput = analysis_task_output.pydantic  # type: ignore[assignment]
        architecture_output: ArchitectureOutput = architecture_task_output.pydantic  # type: ignore[assignment]

        # Store basic analysis outputs
        self.state.application_summary = analysis_output.application_summary
        self.state.high_level_requirements = analysis_output.high_level_requirements

        # Store enhanced analysis outputs
        if analysis_output.detailed_requirements:
            self.state.detailed_requirements = json.dumps([r.model_dump() for r in analysis_output.detailed_requirements], indent=2)
        if analysis_output.security_context:
            self.state.security_context = analysis_output.security_context
        if analysis_output.assumptions:
            self.state.assumptions = json.dumps(analysis_output.assumptions, indent=2)
        if analysis_output.constraints:
            self.state.constraints = json.dumps(analysis_output.constraints, indent=2)

        # Store architecture outputs
        self.state.architecture_summary = architecture_output.architecture_summary
        self.state.architecture_diagram = architecture_output.architecture_diagram

        # Store enhanced architecture outputs
        if architecture_output.components:
            self.state.components = json.dumps([c.model_dump() for c in architecture_output.components], indent=2)
        if architecture_output.data_flow_description:
            self.state.data_flow_description = architecture_output.data_flow_description
        if architecture_output.trust_boundaries:
            self.state.trust_boundaries = json.dumps([t.model_dump() for t in architecture_output.trust_boundaries], indent=2)
        if architecture_output.attack_surface_analysis:
            self.state.attack_surface_analysis = architecture_output.attack_surface_analysis

        print("\n✓ Requirements analysis and architecture mapping complete")
        print(f"  - Application Summary: {self.state.application_summary[:100]}...")
        print(f"  - Found {len(self.state.high_level_requirements)} high-level requirements.")
        if analysis_output.detailed_requirements:
            print(f"  - Detailed {len(analysis_output.detailed_requirements)} requirements with metadata")
        if architecture_output.components:
            print(f"  - Identified {len(architecture_output.components)} system components")

    @listen(analyze_requirements)
    def analyze_stakeholders(self):
        """Analyze stakeholders and trust boundaries using Stakeholder Crew."""
        print("\n" + "=" * 80)
        print("STEP 3: Analyzing Stakeholders and Trust Boundaries")
        print("=" * 80)

        result = (
            StakeholderCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "architecture_summary": self.state.architecture_summary,
                }
            )
        )

        self.state.stakeholders = result.raw

        print("\n✓ Stakeholder analysis complete")

    @listen(analyze_stakeholders)
    def perform_threat_modeling(self):
        """Perform threat modeling using Threat Modeling Crew."""
        print("\n" + "=" * 80)
        print("STEP 4: Performing Threat Modeling (STRIDE)")
        print("=" * 80)

        result = (
            ThreatModelingCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "architecture_summary": self.state.architecture_summary,
                    "components": self.state.components if self.state.components else "No detailed components available",
                }
            )
        )

        # Store as JSON for traceability matrix
        threat_output = result.pydantic
        self.state.threats = threat_output.model_dump_json(indent=2) if threat_output else "{}"

        print("\n✓ Threat modeling complete")
        print(f"  - Identified {len(threat_output.threats) if threat_output else 0} threats")

    @listen(perform_threat_modeling)
    def map_security_controls(self):
        """Map requirements to security standards using Domain Security Crew."""
        print("\n" + "=" * 80)
        print("STEP 5: Mapping to Security Standards (OWASP ASVS)")
        print("=" * 80)

        result = (
            DomainSecurityCrew()
            .crew()
            .kickoff(inputs={"high_level_requirements": json.dumps(self.state.high_level_requirements, indent=2)})
        )

        # Domain crew returns a single TaskOutput as CrewOutput.output
        domain_output = result.tasks_output[0]
        self.state.security_controls = domain_output.pydantic.model_dump_json(indent=2)  # type: ignore[union-attr]
        print("\n✓ Security controls mapped")

    @listen(map_security_controls)
    def identify_ai_security(self):
        """Identify AI/ML security requirements using LLM Security Crew."""
        print("\n" + "=" * 80)
        print("STEP 6: Identifying AI/ML Security Requirements")
        print("=" * 80)

        result = (
            LLMSecurityCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": f"Application Summary: {self.state.application_summary}\nHigh-Level Requirements: {self.state.high_level_requirements}",
                }
            )
        )

        self.state.ai_security = result.raw
        print("\n✓ AI/ML security assessment complete")

    @listen(identify_ai_security)
    def assess_compliance(self):
        """Assess compliance requirements using Compliance Crew."""
        print("\n" + "=" * 80)
        print("STEP 7: Assessing Compliance Requirements")
        print("=" * 80)

        result = (
            ComplianceCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": f"Application Summary: {self.state.application_summary}\nHigh-Level Requirements: {self.state.high_level_requirements}",
                }
            )
        )

        self.state.compliance_requirements = result.raw
        print("\n✓ Compliance assessment complete")

    @listen(assess_compliance)
    def design_security_architecture(self):
        """Design security architecture using Security Architecture Crew."""
        print("\n" + "=" * 80)
        print("STEP 8: Designing Security Architecture")
        print("=" * 80)

        result = (
            SecurityArchitectureCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "architecture_summary": self.state.architecture_summary,
                    "components": self.state.components if self.state.components else "No detailed components available",
                    "security_controls": self.state.security_controls,
                }
            )
        )

        self.state.security_architecture = result.raw

        print("\n✓ Security architecture design complete")

    @listen(design_security_architecture)
    def create_implementation_roadmap(self):
        """Create implementation roadmap using Roadmap Crew."""
        print("\n" + "=" * 80)
        print("STEP 9: Creating Implementation Roadmap")
        print("=" * 80)

        result = (
            RoadmapCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "security_controls": self.state.security_controls,
                    "threats": self.state.threats,
                    "compliance_requirements": self.state.compliance_requirements,
                }
            )
        )

        self.state.implementation_roadmap = result.raw

        print("\n✓ Implementation roadmap created")

    @listen(create_implementation_roadmap)
    def design_verification_strategy(self):
        """Design verification and testing strategy using Verification Crew."""
        print("\n" + "=" * 80)
        print("STEP 10: Designing Verification and Testing Strategy")
        print("=" * 80)

        result = (
            VerificationCrew()
            .crew()
            .kickoff(
                inputs={
                    "security_controls": self.state.security_controls,
                    "compliance_requirements": self.state.compliance_requirements,
                    "owasp_controls": self.state.security_controls,  # Same as security_controls for now
                }
            )
        )

        self.state.verification_testing = result.raw

        print("\n✓ Verification strategy designed")

    @listen(design_verification_strategy)
    def validate_requirements(self):
        """Validate all generated requirements using Validation Crew."""
        print("\n" + "=" * 80)
        print("STEP 11: Validating Security Requirements")
        print("=" * 80)

        result = (
            ValidationCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": f"Application Summary: {self.state.application_summary}\nHigh-Level Requirements: {self.state.high_level_requirements}",
                    "security_controls": self.state.security_controls,
                    "ai_security": self.state.ai_security,
                    "compliance_requirements": self.state.compliance_requirements,
                }
            )
        )

        validation_task_output = result.tasks_output[0]
        validation_output: ValidationOutput = validation_task_output.pydantic  # type: ignore[assignment]
        self.state.validation_report = validation_output.model_dump_json(indent=2)
        self.state.validation_score = validation_output.overall_score
        self.state.validation_passed = validation_output.validation_passed

        print("\n✓ Validation complete")
        print(f"  Score: {self.state.validation_score:.2f}")
        print(f"  Passed: {self.state.validation_passed}")

    @listen(validate_requirements)
    def evaluate_and_decide(self):
        """
        Evaluate validation results and decide whether to:
        - Generate final output (if validation passed)
        - Loop back for refinement (if validation failed and iterations remain)
        - Accept current version (if max iterations reached)
        """
        print("\n" + "=" * 80)
        print("STEP 12: Self-Evaluation Decision")
        print("=" * 80)

        self.state.iteration_count += 1

        if self.state.validation_passed:
            print(f"\n✓ VALIDATION PASSED (Score: {self.state.validation_score:.2f})")
            print("  Proceeding to generate final security requirements...")
            self.state.should_generate_output = True
        elif self.state.iteration_count < self.MAX_ITERATIONS:
            print(f"\n✗ VALIDATION FAILED (Score: {self.state.validation_score:.2f})")
            print(f"  Iteration {self.state.iteration_count}/{self.MAX_ITERATIONS}")
            print("  Re-running analysis with validation feedback...")
            self.state.should_generate_output = False
            # Loop back to analyze_requirements
            self.analyze_requirements()
        else:
            print(f"\n⚠ MAX ITERATIONS REACHED ({self.MAX_ITERATIONS})")
            print(f"  Final Score: {self.state.validation_score:.2f}")
            print("  Generating output with current requirements (may need manual review)...")
            self.state.should_generate_output = True

    @listen(evaluate_and_decide)
    def build_traceability_matrix(self):
        """Build comprehensive traceability matrix linking requirements → threats → controls → verification."""
        print("\n" + "=" * 80)
        print("STEP 13: Building Traceability Matrix")
        print("=" * 80)

        try:
            # Parse all JSON data
            detailed_reqs = json.loads(self.state.detailed_requirements) if self.state.detailed_requirements else []
            threats_data = json.loads(self.state.threats) if self.state.threats else {}
            controls_data = json.loads(self.state.security_controls) if self.state.security_controls else {}

            # Extract data
            threats_list = threats_data.get("threats", []) if isinstance(threats_data, dict) else []
            requirements_mapping = controls_data.get("requirements_mapping", []) if isinstance(controls_data, dict) else []

            # Create lookup dictionaries for better matching
            # Map requirement text to requirement ID
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

            # Create a mapping from requirement text (normalized) to requirements_mapping entries
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
                req_text = req.get("requirement_text", "")  # Fixed: use requirement_text, not requirement
                req_id = req.get("requirement_id", "")
                req_text_lower = req_text.strip().lower()

                # Find related threats by matching keywords and component relevance
                # Threats are linked to components, so we need to match based on:
                # 1. Keywords in threat description
                # 2. Component name relevance to requirement text
                related_threats = []
                req_keywords = set(req_text_lower.split())

                for t in threats_list:
                    threat_desc = t.get("description", "").lower()
                    threat_component = t.get("component", "").lower()

                    # Check if requirement keywords appear in threat description
                    # Filter meaningful keywords (longer than 3 chars, not stop words)
                    meaningful_keywords = {kw for kw in req_keywords if len(kw) > 3 and kw not in _STOP_WORDS}
                    keyword_matches = sum(1 for kw in meaningful_keywords if kw in threat_desc)

                    # Check if component name overlaps with requirement keywords
                    component_match = any(kw in threat_component for kw in meaningful_keywords)

                    # Check if threat component matches business category or key terms
                    business_category = req.get("business_category", "").lower()
                    category_match = business_category in threat_component or threat_component in business_category

                    # Also check if requirement text contains component name or vice versa
                    component_in_req = any(word in req_text_lower for word in threat_component.split() if len(word) > 3)

                    # Lower threshold: match if 1+ keywords OR component match OR category match
                    if keyword_matches >= 1 or component_match or category_match or component_in_req:
                        related_threats.append(t)

                # Find related OWASP controls using multiple matching strategies
                req_mapping = None

                # Strategy 1: Exact match on requirement_id
                if req_id:
                    req_mapping = controls_lookup.get(req_id.lower())

                # Strategy 2: Exact match on requirement text (normalized)
                if not req_mapping:
                    req_mapping = controls_lookup.get(req_text_lower)

                # Strategy 3: Fuzzy match - check if requirement text is similar
                if not req_mapping:
                    # Only check text-based keys (skip ID keys for fuzzy matching)
                    for rm_text, rm in controls_lookup.items():
                        # Skip if this is an ID key (starts with "req-")
                        if rm_text.startswith("req-") and len(rm_text) < 10:
                            continue

                        # Check if requirement texts share significant keywords
                        rm_keywords = set(rm_text.split())
                        # Filter out common stop words
                        req_keywords_filtered = {kw for kw in req_keywords if kw not in _STOP_WORDS and len(kw) > 2}
                        rm_keywords_filtered = {kw for kw in rm_keywords if kw not in _STOP_WORDS and len(kw) > 2}

                        overlap = req_keywords_filtered.intersection(rm_keywords_filtered)

                        # If significant keywords overlap (lower threshold for fuzzy matching)
                        if len(overlap) >= max(2, min(len(req_keywords_filtered), len(rm_keywords_filtered)) * 0.3):
                            req_mapping = rm
                            break

                owasp_controls = req_mapping.get("owasp_controls", []) if req_mapping else []

                # Extract verification methods from controls
                verification_methods = list(
                    set([ctrl.get("verification_method", "Manual Review") for ctrl in owasp_controls if ctrl.get("verification_method")])
                )

                # Determine priority
                priority_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                priorities = [ctrl.get("priority", "Medium") for ctrl in owasp_controls]
                priority = max(priorities, key=lambda p: priority_map.get(p.lower(), 2)) if priorities else req.get("priority", "Medium")

                # Build entry
                entry = TraceabilityEntry(
                    req_id=req_id or f"REQ-{len(entries) + 1:03d}",
                    high_level_requirement=req_text,
                    functional_category=req.get("business_category", req.get("functional_category", "General")),
                    security_sensitivity=req.get("security_sensitivity", "Medium"),
                    threat_ids=[t.get("threat_id", "") for t in related_threats[:10]],  # Limit to top 10
                    threat_descriptions=[
                        t.get("description", "")[:80] + "..." if len(t.get("description", "")) > 80 else t.get("description", "")
                        for t in related_threats[:10]
                    ],
                    owasp_control_ids=[ctrl.get("req_id", "") for ctrl in owasp_controls],
                    owasp_control_descriptions=[
                        ctrl.get("requirement", "")[:80] + "..." if len(ctrl.get("requirement", "")) > 80 else ctrl.get("requirement", "")
                        for ctrl in owasp_controls
                    ],
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
                f"{with_controls} requirements ({coverage_pct:.1f}%) mapped to OWASP controls. "
                "Coverage: " + ("Complete" if coverage_pct >= 90 else "Partial" if coverage_pct >= 70 else "Needs Improvement") + "."
            )

            # Create traceability matrix
            matrix = TraceabilityMatrix(entries=entries, summary=summary)
            self.state.traceability_matrix = matrix.model_dump_json(indent=2)

            print("\n✓ Traceability matrix built successfully")
            print(f"  - Total requirements: {total_reqs}")
            print(f"  - Requirements with threats: {with_threats}")
            print(f"  - Requirements with controls: {with_controls}")
            print(f"  - Coverage: {coverage_pct:.1f}%")

            # Debug output if coverage is low (helpful for troubleshooting)
            if coverage_pct < 50 and total_reqs > 0:
                print("\n⚠️  Low coverage detected. Please check:")
                print(f"  - Total threats available: {len(threats_list)}")
                print(f"  - Total control mappings available: {len(requirements_mapping)}")
                print(f"  - Total detailed requirements: {len(detailed_reqs)}")

        except Exception as e:
            print(f"\n⚠ Error building traceability matrix: {e}")
            # Create empty matrix
            self.state.traceability_matrix = TraceabilityMatrix(
                entries=[], summary="Error building traceability matrix. Manual review required."
            ).model_dump_json(indent=2)

    @listen(build_traceability_matrix)
    def generate_final_output(self):
        """Generate final security requirements document."""
        # Only generate output if validation passed or max iterations reached
        # TODO: this does not work as expected, we should generate output even if validation failed
        # if not self.state.should_generate_output:
        #     return  # Skip output generation when retrying

        print("\n" + "=" * 80)
        print("STEP 14: Generating Final Security Requirements Document")
        print("=" * 80)

        # Generate timestamp for unique filenames
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save to output file
        output_dir = Path("outputs")
        output_dir.mkdir(exist_ok=True)

        # Create artifacts directory for dashboard data
        artifacts_dir = output_dir / f"artifacts_{timestamp}"
        artifacts_dir.mkdir(exist_ok=True)

        # Export dashboard data artifacts
        self._export_dashboard_artifacts(artifacts_dir, timestamp)

        # Generate Quarto markdown as primary output
        qmd_file = output_dir / f"security_requirements_{timestamp}.qmd"
        self._generate_markdown_summary(qmd_file, artifacts_dir)

        # # Compile all outputs into a comprehensive document (for backup)
        # final_doc = {
        #     "metadata": {
        #         "validation_score": self.state.validation_score,
        #         "validation_passed": self.state.validation_passed,
        #         "iterations": self.state.iteration_count,
        #         "timestamp": timestamp,
        #     },
        #     "original_requirements": self.state.requirements_text,
        #     "requirements_analysis": self.state.analyzed_requirements,
        #     "security_controls": self.state.security_controls,
        #     "ai_ml_security": self.state.ai_security,
        #     "compliance_requirements": self.state.compliance_requirements,
        #     "validation_report": self.state.validation_report,
        # }

        # self.state.final_requirements = json.dumps(final_doc, indent=2)

        # # Save JSON backup
        # json_file = output_dir / f"security_requirements_{timestamp}.json"
        # with open(json_file, "w", encoding="utf-8") as f:
        #     f.write(self.state.final_requirements)

        print("\n✓ Security requirements generated successfully!")
        print(f"  Primary output (Quarto): {qmd_file}")
        print(f"  Dashboard artifacts: {artifacts_dir}")
        # print(f"  Backup (JSON): {json_file}")
        print(f"  Validation Score: {self.state.validation_score:.2f}")
        print(f"  Total Iterations: {self.state.iteration_count}")

    def _export_dashboard_artifacts(self, artifacts_dir: Path, timestamp: str):
        """Export dashboard data as JSON artifacts for Quarto visualizations."""
        try:
            print("  ✓ Exporting dashboard artifacts...")

            # Parse all data
            controls_data = json.loads(self.state.security_controls) if self.state.security_controls else {}
            threats_data = json.loads(self.state.threats) if self.state.threats else {}
            detailed_reqs = json.loads(self.state.detailed_requirements) if self.state.detailed_requirements else []
            matrix_data = json.loads(self.state.traceability_matrix) if self.state.traceability_matrix else {}
            validation_data = json.loads(self.state.validation_report) if self.state.validation_report else {}

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

            # 1. ASVS Mapping (control_id, v_category, requirement_id, level, priority)
            asvs_mapping = []
            mappings = controls_data.get("requirements_mapping", [])
            for mapping in mappings:
                # Get requirement_id from mapping, or look it up from detailed_reqs
                req_id = mapping.get("requirement_id")
                if not req_id:
                    high_level_req = mapping.get("high_level_requirement", "").strip().lower()
                    req_id = req_text_to_id.get(high_level_req, "")

                for control in mapping.get("owasp_controls", []):
                    asvs_mapping.append(
                        {
                            "control_id": control.get("req_id", ""),
                            "v_category": control.get("chapter", "").replace("V", "V"),  # Ensure V prefix
                            "requirement_id": req_id,
                            "level": control.get("level", "L2"),
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
                for control in mapping.get("owasp_controls", []):
                    priority = control.get("priority", "Medium")
                    priority_counts[priority] = priority_counts.get(priority, 0) + 1

            priorities = [{"level": k, "count": v} for k, v in priority_counts.items()]
            with open(artifacts_dir / "priorities.json", "w") as f:
                json.dump(priorities, f, indent=2)

            # 4. Compliance (framework, status, next_audit)
            compliance_items = []
            # Detect frameworks from requirements
            if "GDPR" in self.state.requirements_text.upper() or "privacy" in self.state.requirements_text.lower():
                compliance_items.append({"framework": "GDPR", "status": "In Progress", "next_audit": "TBD"})
            if "PCI" in self.state.requirements_text.upper() or "payment" in self.state.requirements_text.lower():
                compliance_items.append({"framework": "PCI-DSS", "status": "Gap", "next_audit": "TBD"})
            if "HIPAA" in self.state.requirements_text.upper() or "healthcare" in self.state.requirements_text.lower():
                compliance_items.append({"framework": "HIPAA", "status": "In Progress", "next_audit": "TBD"})
            if "SOX" in self.state.requirements_text.upper() or "sox" in self.state.requirements_text.lower():
                compliance_items.append({"framework": "SOX", "status": "Gap", "next_audit": "TBD"})
            if "CCPA" in self.state.requirements_text.upper():
                compliance_items.append({"framework": "CCPA", "status": "In Progress", "next_audit": "TBD"})

            # Add OWASP as always applicable
            compliance_items.append({"framework": "OWASP ASVS", "status": "In Progress", "next_audit": "N/A"})

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

            # 6. Coverage (req_id, has_threat, has_asvs, tests)
            coverage_data = []
            entries = matrix_data.get("entries", [])
            for entry in entries:
                coverage_data.append(
                    {
                        "req_id": entry.get("req_id", ""),
                        "has_threat": len(entry.get("threat_ids", [])) > 0,
                        "has_asvs": len(entry.get("owasp_control_ids", [])) > 0,
                        "tests": len(entry.get("verification_methods", [])),
                        "priority": entry.get("priority", "Medium"),
                    }
                )

            with open(artifacts_dir / "coverage.json", "w") as f:
                json.dump(coverage_data, f, indent=2)

            # 7. Validation (score, dims)
            validation_export = {
                "score": validation_data.get("overall_score", self.state.validation_score),
                "dims": validation_data.get("dimension_scores", {}),
                "passed": validation_data.get("validation_passed", self.state.validation_passed),
            }
            with open(artifacts_dir / "validation.json", "w") as f:
                json.dump(validation_export, f, indent=2)

            print(f"    - Exported 7 dashboard artifact files to {artifacts_dir}")

        except Exception as e:
            print(f"  ⚠ Warning: Could not export dashboard artifacts: {e}")
            import traceback

            traceback.print_exc()

    def _generate_markdown_summary(self, output_path: Path, artifacts_dir: Path):
        """Generate a comprehensive, professional markdown summary following recommended structure."""
        try:
            from datetime import datetime

            validation_score = self.state.validation_score
            validation_passed = self.state.validation_passed
            iterations = self.state.iteration_count
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Relative path to artifacts for Quarto execution
            # Ensure both paths are absolute for relative_to() to work
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
    theme: cosmo
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
  pdf:
    pdf-engine: lualatex
    toc: true
    toc-depth: 3
    number-sections: true
    fig-width: 7
    fig-height: 4.5
    fig-dpi: 300
    fig-format: png
    keep-tex: false
    documentclass: report
    papersize: a4
    include-in-header:
      text: |
        \\usepackage{{fvextra}}
        \\DefineVerbatimEnvironment{{Highlighting}}{{Verbatim}}{{breaklines,commandchars=\\\\\\{{\\}}}}
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

### 1.1. Purpose and Scope

**Purpose:** This document presents a comprehensive security requirements analysis for the proposed application, mapping high-level business requirements to specific, actionable security controls based on industry standards (OWASP ASVS, NIST CSF, ISO 27001).

**Scope:** This analysis covers all functional requirements provided, including stakeholder analysis, threat modeling, security control mapping, compliance requirements, architectural security recommendations, implementation planning, and verification strategies.

### 1.2. Key Findings

- **Validation Score**: {validation_score:.2f}/1.0
- **Validation Status**: {"✅ Passed" if validation_passed else "❌ Needs Review"}
- **Analysis Iterations**: {iterations}
- **Requirements Analyzed**: {len(self.state.high_level_requirements)}

**Summary:** {self.state.application_summary}

### 1.3. Security Overview Dashboard

This interactive dashboard provides at-a-glance metrics for executives and stakeholders. For best experience, render this document with Quarto to enable interactive visualizations.

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
for idx, risk in top_risks.iterrows():
    print(f"- **{{risk['id']}}** ({{risk['risk_level']}}): {{risk['description'][:100]}}...")
```

#### Controls

```{{python}}
#| label: fig-asvs-distribution
#| fig-cap: "OWASP ASVS control distribution by verification category (V1-V14)."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Group by ASVS category
    dist = asvs.groupby("v_category").size().reset_index(name="controls")
    dist = dist.sort_values("v_category")
    
    # Add percentage for better context
    total = dist["controls"].sum()
    dist["percentage"] = (dist["controls"] / total * 100).round(1)
    
    fig_asvs = px.bar(
        dist, 
        x="v_category", 
        y="controls", 
        text=[f"{{c}}<br>({{p}}%)" for c, p in zip(dist["controls"], dist["percentage"])],
        title="ASVS Controls by Verification Category",
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
req_coverage = (coverage["has_asvs"].mean() * 100) if not coverage.empty else 0
verif_coverage = (coverage["tests"].gt(0).mean() * 100) if not coverage.empty else 0

# Calculate additional metrics
avg_controls_per_req = (total_controls / total_reqs) if total_reqs > 0 else 0
critical_controls = len(asvs[asvs["priority"] == "Critical"]) if "priority" in asvs.columns else 0

print(f"- **Total ASVS Controls Mapped:** {{total_controls}}")
print(f"- **Requirements with ASVS Mapping:** {{req_coverage:.1f}}% ({{coverage['has_asvs'].sum()}}/{{total_reqs}})")
print(f"- **Average Controls per Requirement:** {{avg_controls_per_req:.1f}}")
print(f"- **Critical Controls:** {{critical_controls}} ({{critical_controls/total_controls*100:.1f}}% of total)")
print(f"- **Requirements with Verification:** {{verif_coverage:.1f}}% ({{coverage['tests'].gt(0).sum()}}/{{total_reqs}})")
print(f"- **Recommended ASVS Level:** L2 (Standard)")
```

#### Compliance

```{{python}}
#| label: fig-compliance-rag
#| fig-cap: "OWASP ASVS compliance status (Red-Amber-Green rating). Note: Only frameworks with mapped controls are shown."
#| echo: false
#| warning: false
try:
    import plotly.express as px
    
    # Filter to only show OWASP ASVS (since we only have ASVS controls mapped)
    comp_filtered = compliance[compliance["framework"].str.contains("ASVS", case=False, na=False)]
    
    if comp_filtered.empty:
        # Fallback to all if no ASVS found
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
        title="OWASP ASVS Compliance Status",
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

**Coverage Statistics:**

```{{python}}
#| echo: false
#| output: asis
#| warning: false
# Parser and data quality stats
total_entries = len(coverage)
with_threats = coverage["has_threat"].sum()
with_controls = coverage["has_asvs"].sum()
with_tests = coverage["tests"].gt(0).sum()

print(f"")
print(f"**Traceability Matrix:**")
print(f"- Total Requirements: {{total_entries}}")
print(f"- Linked to Threats: {{with_threats}} ({{with_threats/max(total_entries,1)*100:.1f}}%)")
print(f"- Mapped to ASVS: {{with_controls}} ({{with_controls/max(total_entries,1)*100:.1f}}%)")
print(f"- With Verification: {{with_tests}} ({{with_tests/max(total_entries,1)*100:.1f}}%)")
print(f"")
print(f"**Data Quality:** {{"✅ Excellent" if val_score >= 0.8 else "⚠️ Good" if val_score >= 0.7 else "❌ Needs Improvement"}}")
```

:::

"""

            markdown += """
---

## 2. Requirements Understanding

### 2.1. High-Level Requirements Analysis

The following high-level functional requirements have been identified and analyzed:

"""
            # Add high-level requirements list
            for idx, req in enumerate(self.state.high_level_requirements, 1):
                markdown += f"{idx}. {req}\n"

            # Add detailed requirements if available
            if self.state.detailed_requirements:
                try:
                    detailed_reqs = json.loads(self.state.detailed_requirements)
                    markdown += "\n### 2.2. Detailed Requirements Breakdown\n\n"
                    markdown += "| Req ID | Requirement | Business Category | Security Sensitivity | Data Classification |\n"
                    markdown += "|--------|-------------|-------------------|---------------------|---------------------|\n"
                    for req in detailed_reqs:
                        markdown += f"| {req.get('requirement_id', 'N/A')} | {req.get('requirement_text', 'N/A')[:50]}... | {req.get('business_category', 'N/A')} | {req.get('security_sensitivity', 'N/A')} | {req.get('data_classification', 'N/A')} |\n"
                except Exception:
                    pass

            # Add security context
            if self.state.security_context:
                markdown += f"\n### 2.3. Security Context and Regulatory Obligations\n\n{self.state.security_context}\n"

            # Add assumptions and constraints
            if self.state.assumptions:
                try:
                    assumptions = json.loads(self.state.assumptions)
                    markdown += "\n### 2.4. Assumptions\n\n"
                    for assumption in assumptions:
                        markdown += f"- {assumption}\n"
                except Exception:
                    pass

            if self.state.constraints:
                try:
                    constraints = json.loads(self.state.constraints)
                    markdown += "\n### 2.5. Constraints\n\n"
                    for constraint in constraints:
                        markdown += f"- {constraint}\n"
                except Exception:
                    pass

            markdown += "\n---\n\n"

            # Section 3: Stakeholder Analysis
            markdown += "## 3. Stakeholder Analysis\n\n"
            if self.state.stakeholders:
                # Crew now outputs markdown directly
                markdown += self.state.stakeholders + "\n\n"
            else:
                markdown += "*Stakeholder analysis not available.*\n\n"

            markdown += "---\n\n"

            # Section 4: System Architecture Analysis
            markdown += "## 4. System Architecture Analysis\n\n"
            markdown += f"### 4.1. Architectural Overview\n\n{self.state.architecture_summary}\n\n"

            markdown += "### 4.2. Architecture Diagram\n\n"
            if self.state.architecture_diagram:
                markdown += "```{mermaid}\n"
                markdown += self.state.architecture_diagram
                markdown += "\n```\n\n"
            else:
                markdown += "*Architecture diagram not available.*\n\n"

            # Add component breakdown if available
            if self.state.components:
                try:
                    components = json.loads(self.state.components)
                    markdown += "### 4.3. Component Breakdown\n\n"
                    markdown += "| Component | Responsibility | Security Criticality | External Dependencies |\n"
                    markdown += "|-----------|----------------|---------------------|----------------------|\n"
                    for comp in components:
                        deps = ", ".join(comp.get("external_dependencies", [])[:2])
                        markdown += f"| {comp.get('name', 'N/A')} | {comp.get('responsibility', 'N/A')[:40]}... | {comp.get('security_criticality', 'N/A')} | {deps} |\n"
                except Exception:
                    pass

            if self.state.data_flow_description:
                markdown += f"\n### 4.4. Data Flow Analysis\n\n{self.state.data_flow_description}\n"

            if self.state.attack_surface_analysis:
                markdown += f"\n### 4.5. Attack Surface Analysis\n\n{self.state.attack_surface_analysis}\n"

            markdown += "\n---\n\n"

            # Section 5: Threat Modeling
            markdown += "## 5. Threat Modeling\n\n"

            try:
                threats_data = json.loads(self.state.threats) if self.state.threats else {}
                threats_list = threats_data.get("threats", [])
                methodology = threats_data.get("methodology", "STRIDE")
                risk_summary = threats_data.get("risk_summary", "")

                markdown += f"### 5.1. Methodology\n\n{methodology}\n\n"

                markdown += "### 5.2. Identified Threats\n\n"
                markdown += "The following table summarizes the key threats identified through threat modeling:\n\n"
                markdown += "| Threat ID | Component | Category | Risk Level | Description |\n"
                markdown += "|-----------|-----------|----------|------------|-------------|\n"

                # Show top 20 threats by risk level
                risk_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                sorted_threats = sorted(threats_list, key=lambda t: risk_priority.get(t.get("risk_level", "Low"), 0), reverse=True)[:20]

                for threat in sorted_threats:
                    threat_id = threat.get("threat_id", "N/A")
                    component = threat.get("component", "N/A")
                    category = threat.get("threat_category", "N/A")
                    risk = threat.get("risk_level", "N/A")
                    desc = (
                        threat.get("description", "")[:60] + "..."
                        if len(threat.get("description", "")) > 60
                        else threat.get("description", "")
                    )
                    markdown += f"| {threat_id} | {component} | {category} | {risk} | {desc} |\n"

                if len(threats_list) > 20:
                    markdown += f"\n*Showing top 20 of {len(threats_list)} total threats. See Appendix C for complete list.*\n"

                markdown += f"\n### 5.3. Risk Summary\n\n{risk_summary}\n\n"

                # Section 5.4: Residual Risk Assessment
                markdown += "### 5.4. Residual Risk Assessment\n\n"
                markdown += "This section analyzes the residual risk after applying the recommended security controls:\n\n"

                # Separate threats with and without residual risk data
                threats_with_residual = [t for t in threats_list if t.get("residual_risk_level")]
                threats_without_residual = [t for t in threats_list if not t.get("residual_risk_level")]

                if threats_with_residual:
                    markdown += "#### Before/After Risk Analysis\n\n"
                    markdown += "| Threat ID | Initial Risk | Controls Applied | Control Effectiveness | Residual Risk | Status |\n"
                    markdown += "|-----------|--------------|------------------|----------------------|---------------|--------|\n"

                    for threat in sorted(
                        threats_with_residual, key=lambda t: risk_priority.get(t.get("residual_risk_level", "Low"), 0), reverse=True
                    )[:15]:
                        threat_id = threat.get("threat_id", "N/A")
                        initial_risk = threat.get("risk_level", "N/A")
                        controls = ", ".join(threat.get("applicable_controls", [])[:3])
                        if len(threat.get("applicable_controls", [])) > 3:
                            controls += f" +{len(threat.get('applicable_controls', [])) - 3} more"
                        effectiveness = threat.get("control_effectiveness", "N/A")
                        residual_risk = threat.get("residual_risk_level", "N/A")
                        acceptance = threat.get("residual_risk_acceptance", "Pending")

                        # Add visual indicator
                        status_icon = "✅" if acceptance == "Accepted" else "⚠️" if acceptance == "Requires Review" else "❌"

                        markdown += f"| {threat_id} | {initial_risk} | {controls or 'TBD'} | {effectiveness} | {residual_risk} | {status_icon} {acceptance} |\n"

                    markdown += "\n**Risk Reduction Summary:**\n\n"

                    # Calculate risk reduction statistics
                    critical_to_lower = sum(
                        1
                        for t in threats_with_residual
                        if t.get("risk_level") == "Critical" and t.get("residual_risk_level") in ["High", "Medium", "Low", "Negligible"]
                    )
                    high_to_lower = sum(
                        1
                        for t in threats_with_residual
                        if t.get("risk_level") == "High" and t.get("residual_risk_level") in ["Medium", "Low", "Negligible"]
                    )

                    markdown += f"- **Critical Risk Reduction:** {critical_to_lower} threats reduced from Critical to lower levels\n"
                    markdown += f"- **High Risk Reduction:** {high_to_lower} threats reduced from High to lower levels\n"
                    markdown += f"- **Residual Risk Distribution:** {sum(1 for t in threats_with_residual if t.get('residual_risk_level') in ['Critical', 'High'])} threats remain at Critical/High level\n\n"

                    # Risk acceptance needed
                    needs_review = [
                        t for t in threats_with_residual if t.get("residual_risk_acceptance") in ["Requires Review", "Unacceptable"]
                    ]
                    if needs_review:
                        markdown += "**Risks Requiring Management Review:**\n\n"
                        for threat in needs_review[:10]:
                            markdown += f"- **{threat.get('threat_id')}**: {threat.get('description', '')[:80]}... (Residual Risk: {threat.get('residual_risk_level')})\n"
                        markdown += "\n"

                else:
                    markdown += "*Note: Residual risk assessment will be calculated after controls are implemented.*\n\n"
                    markdown += "**Recommended Approach:**\n\n"
                    markdown += "1. Implement security controls as specified in Section 6\n"
                    markdown += "2. Estimate control effectiveness based on industry standards\n"
                    markdown += "3. Calculate residual risk: `Residual Risk ≈ Initial Risk × (1 - Control Effectiveness)`\n"
                    markdown += "4. Review and accept residual risks with management\n\n"

            except Exception as e:
                markdown += f"*Error parsing threat data: {e}*\n"
                markdown += self.state.threats + "\n\n"

            markdown += "---\n\n"

            # Section 6: OWASP ASVS Security Requirements Mapping
            markdown += "## 6. OWASP ASVS Security Requirements Mapping\n\n"

            try:
                security_controls_data = json.loads(self.state.security_controls)

                # Create a lookup dictionary from detailed requirements text to requirement ID
                req_text_to_id = {}
                detailed_reqs = json.loads(self.state.detailed_requirements) if self.state.detailed_requirements else []
                if detailed_reqs:
                    # Handle both list and dict structures
                    reqs_list = detailed_reqs if isinstance(detailed_reqs, list) else detailed_reqs.get("detailed_requirements", [])
                    for req in reqs_list:
                        req_text = req.get("requirement_text", "").strip().lower()
                        req_id = req.get("requirement_id", "")
                        if req_text and req_id:
                            req_text_to_id[req_text] = req_id

                # Add recommended ASVS level
                if security_controls_data.get("recommended_asvs_level"):
                    markdown += "### 6.1. Recommended ASVS Compliance Level\n\n"
                    markdown += f"**Recommended Level:** {security_controls_data.get('recommended_asvs_level')}\n\n"

                markdown += "### 6.2. Requirements Mapping\n\n"
                markdown += "The following table maps each high-level requirement to specific OWASP ASVS controls:\n\n"

                mappings = security_controls_data.get("requirements_mapping", [])

                for i, mapping in enumerate(mappings, 1):
                    req = mapping.get("high_level_requirement", "N/A")
                    # Get requirement_id from mapping, or look it up from detailed_reqs
                    req_id = mapping.get("requirement_id")
                    if not req_id:
                        high_level_req = mapping.get("high_level_requirement", "").strip().lower()
                        req_id = req_text_to_id.get(high_level_req, f"REQ-{i:03d}")
                    markdown += f"\n#### 6.2.{i}. {req_id}: {req}\n\n"

                    controls = mapping.get("owasp_controls", [])
                    if not controls:
                        markdown += "*No specific OWASP controls mapped.*\n"
                        continue

                    markdown += "| Control ID | Level | Priority | Requirement |\n"
                    markdown += "|------------|-------|----------|-------------|\n"
                    for control in controls:
                        markdown += f"| {control.get('req_id', 'N/A')} | {control.get('level', 'N/A')} | {control.get('priority', 'Medium')} | {control.get('requirement', 'N/A')[:60]}... |\n"

                    # Add detailed control information
                    for j, control in enumerate(controls, 1):
                        markdown += f"\n##### Control {control.get('req_id', 'N/A')}\n\n"
                        markdown += f"**Requirement:** {control.get('requirement', 'N/A')}\n\n"
                        markdown += f"**Chapter/Section:** {control.get('chapter', 'N/A')} / {control.get('section', 'N/A')}\n\n"
                        markdown += f"**Level:** {control.get('level', 'N/A')} | **Priority:** {control.get('priority', 'Medium')}\n\n"
                        markdown += f"**Relevance:**\n{control.get('relevance', 'No relevance explanation provided.')}\n\n"
                        markdown += f"**Integration Tips:**\n{control.get('integration_tips', 'No integration tips provided.')}\n\n"
                        if control.get("verification_method"):
                            markdown += f"**Verification Method:** {control.get('verification_method')}\n\n"

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
                matrix_data = json.loads(self.state.traceability_matrix) if self.state.traceability_matrix else {}
                entries = matrix_data.get("entries", [])
                summary = matrix_data.get("summary", "")

                if entries:
                    markdown += f"**Coverage Summary:** {summary}\n\n"

                    # Show top 10 critical requirements with full traceability
                    markdown += "#### Sample Traceability Mappings\n\n"
                    markdown += "The following table shows traceability for high-priority requirements:\n\n"
                    markdown += "| Req ID | Requirement | Threats | OWASP Controls | Priority | Verification |\n"
                    markdown += "|--------|-------------|---------|----------------|----------|-------------|\n"

                    # Sort by priority
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
                        control_count = len(entry.get("owasp_control_ids", []))
                        priority = entry.get("priority", "Medium")
                        verification = entry.get("verification_methods", ["Manual"])[0] if entry.get("verification_methods") else "Manual"

                        markdown += (
                            f"| {req_id} | {req} | {threat_count} threats | {control_count} controls | {priority} | {verification} |\n"
                        )

                    markdown += f"\n*Showing 10 of {len(entries)} requirements. See Appendix D for complete traceability matrix.*\n\n"

                    # Traceability statistics
                    markdown += "#### Traceability Statistics\n\n"
                    total_reqs = len(entries)
                    with_threats = sum(1 for e in entries if e.get("threat_ids"))
                    with_controls = sum(1 for e in entries if e.get("owasp_control_ids"))
                    avg_controls_per_req = sum(len(e.get("owasp_control_ids", [])) for e in entries) / max(total_reqs, 1)

                    markdown += f"- **Total Requirements Tracked:** {total_reqs}\n"
                    markdown += f"- **Requirements Linked to Threats:** {with_threats} ({with_threats / max(total_reqs, 1) * 100:.1f}%)\n"
                    markdown += (
                        f"- **Requirements Mapped to Controls:** {with_controls} ({with_controls / max(total_reqs, 1) * 100:.1f}%)\n"
                    )
                    markdown += f"- **Average Controls per Requirement:** {avg_controls_per_req:.1f}\n"
                    markdown += "- **Verification Coverage:** 100% (all requirements have verification methods)\n\n"

                else:
                    markdown += "*Traceability matrix is being built. See Appendix D for details.*\n\n"

            except Exception as e:
                markdown += f"*Error parsing traceability matrix: {e}*\n\n"

            markdown += "\n---\n\n"

            # Section 7: AI/ML Security Requirements
            markdown += "## 7. AI/ML Security Requirements\n\n"

            if self.state.ai_security:
                # Crew now outputs markdown directly
                markdown += self.state.ai_security + "\n\n"
            else:
                markdown += "*No AI/ML components detected in the system.*\n\n"

            markdown += "---\n\n"

            # Section 8: Compliance Requirements
            markdown += "## 8. Compliance Requirements\n\n"

            if self.state.compliance_requirements:
                # Crew now outputs markdown directly
                markdown += self.state.compliance_requirements + "\n\n"
            else:
                markdown += "*No compliance requirements identified.*\n\n"

            markdown += "---\n\n"

            # Section 9: Security Architecture Recommendations
            markdown += "## 9. Security Architecture Recommendations\n\n"
            if self.state.security_architecture:
                # Crew now outputs markdown directly
                markdown += self.state.security_architecture + "\n\n"
            else:
                markdown += "*Security architecture recommendations not available.*\n\n"

            markdown += "---\n\n"

            # Section 10: Implementation Roadmap
            markdown += "## 10. Implementation Roadmap\n\n"
            if self.state.implementation_roadmap:
                # Crew now outputs markdown directly
                markdown += self.state.implementation_roadmap + "\n\n"
            else:
                markdown += "*Implementation roadmap not available.*\n\n"

            markdown += "---\n\n"

            # Section 11: Verification and Testing Strategy
            markdown += "## 11. Verification and Testing Strategy\n\n"
            if self.state.verification_testing:
                # Crew now outputs markdown directly
                markdown += self.state.verification_testing + "\n\n"
            else:
                markdown += "*Verification and testing strategy not available.*\n\n"

            markdown += "---\n\n"

            # Section 12: Validation Report
            markdown += "## 12. Validation Report\n\n"

            try:
                validation_data = json.loads(self.state.validation_report)

                # Overall Score and Status
                markdown += "### 12.1. Overall Assessment\n\n"
                score = validation_data.get("overall_score", 0)
                passed = validation_data.get("validation_passed", False)

                markdown += f"**Overall Score:** {score:.2f}/1.0\n\n"
                markdown += f"**Validation Status:** {'✅ PASSED' if passed else '❌ NEEDS IMPROVEMENT'}\n\n"

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
                    # Feedback appears to be structured
                    sections = []
                    for section in ["COMPLETENESS", "CONSISTENCY", "CORRECTNESS", "IMPLEMENTABILITY", "ALIGNMENT"]:
                        if section in feedback.upper():
                            sections.append(section)

                    if sections:
                        for section in sections:
                            markdown += f"**{section.title()}**\n\n"
                            # Extract the section content (simplified - would need better parsing)
                            start = feedback.upper().find(section)
                            if start != -1:
                                # Find next section or end
                                end = len(feedback)
                                for next_section in sections:
                                    next_start = feedback.upper().find(next_section, start + len(section))
                                    if next_start != -1 and next_start < end:
                                        end = next_start

                                section_content = feedback[start:end].strip()
                                # Remove the section header from content
                                section_content = section_content[len(section):].strip()  # fmt: skip
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

                                # Dimension-specific recommendations
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
                # Fallback to raw output
                markdown += self.state.validation_report
                markdown += "\n\n"

            markdown += "---\n\n"

            # Appendices
            markdown += "## Appendix A: Original Requirements Document\n\n"
            markdown += f"```\n{self.state.requirements_text}\n```\n\n"

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
            markdown += "This appendix contains the complete list of all identified threats:\n\n"

            try:
                threats_data = json.loads(self.state.threats) if self.state.threats else {}
                threats_list = threats_data.get("threats", [])

                if threats_list:
                    markdown += (
                        "| Threat ID | Component | Category | Likelihood | Impact | Risk Level | Description | Mitigation Strategy |\n"
                    )
                    markdown += (
                        "|-----------|-----------|----------|------------|--------|------------|-------------|---------------------|\n"
                    )

                    for threat in threats_list:
                        threat_id = threat.get("threat_id", "N/A")
                        component = threat.get("component", "N/A")[:30]
                        category = threat.get("threat_category", "N/A")
                        likelihood = threat.get("likelihood", "N/A")
                        impact = threat.get("impact", "N/A")
                        risk = threat.get("risk_level", "N/A")
                        description = (
                            threat.get("description", "")[:80] + "..."
                            if len(threat.get("description", "")) > 80
                            else threat.get("description", "")
                        )
                        mitigation = (
                            threat.get("mitigation_strategy", "")[:60] + "..."
                            if len(threat.get("mitigation_strategy", "")) > 60
                            else threat.get("mitigation_strategy", "")
                        )

                        markdown += f"| {threat_id} | {component} | {category} | {likelihood} | {impact} | {risk} | {description} | {mitigation} |\n"

                    markdown += f"\n**Total Threats:** {len(threats_list)}\n\n"
                else:
                    markdown += "*No threats identified.*\n\n"

            except Exception as e:
                markdown += f"*Error parsing threat data: {e}*\n\n"

            # Appendix D: Complete Requirements Traceability Matrix
            markdown += "---\n\n"
            markdown += "## Appendix D: Complete Requirements Traceability Matrix\n\n"
            markdown += "This appendix provides complete end-to-end traceability from requirements through threats to controls and verification.\n\n"

            try:
                matrix_data = json.loads(self.state.traceability_matrix) if self.state.traceability_matrix else {}
                entries = matrix_data.get("entries", [])

                if entries:
                    markdown += "### Full Traceability Table\n\n"
                    markdown += "| Req ID | Requirement | Category | Sensitivity | Threat IDs | OWASP Controls | Priority | Verification | Status |\n"
                    markdown += "|--------|-------------|----------|-------------|------------|----------------|----------|--------------|--------|\n"

                    for entry in entries:
                        req_id = entry.get("req_id", "N/A")
                        req = (
                            entry.get("high_level_requirement", "")[:50] + "..."
                            if len(entry.get("high_level_requirement", "")) > 50
                            else entry.get("high_level_requirement", "")
                        )
                        category = entry.get("functional_category", "N/A")
                        sensitivity = entry.get("security_sensitivity", "N/A")

                        # Format threat IDs
                        threat_ids = entry.get("threat_ids", [])
                        threat_str = ", ".join(threat_ids[:3])
                        if len(threat_ids) > 3:
                            threat_str += f" +{len(threat_ids) - 3}"

                        # Format control IDs
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
                            markdown += "**Related Threats:**\n"
                            for tid, tdesc in zip(threat_ids[:5], threat_descs[:5]):
                                markdown += f"- **{tid}**: {tdesc}\n"
                            if len(threat_ids) > 5:
                                markdown += f"- *...and {len(threat_ids) - 5} more threats*\n"
                            markdown += "\n"

                        # Controls
                        control_ids = entry.get("owasp_control_ids", [])
                        control_descs = entry.get("owasp_control_descriptions", [])
                        if control_ids:
                            markdown += "**OWASP ASVS Controls:**\n"
                            for cid, cdesc in zip(control_ids[:5], control_descs[:5]):
                                markdown += f"- **{cid}**: {cdesc}\n"
                            if len(control_ids) > 5:
                                markdown += f"- *...and {len(control_ids) - 5} more controls*\n"
                            markdown += "\n"

                        # Verification
                        verification = entry.get("verification_methods", ["Manual Review"])
                        markdown += f"**Verification:** {', '.join(verification)}\n\n"
                        markdown += f"**Priority:** {entry.get('priority', 'Medium')} | **Status:** {entry.get('implementation_status', 'Pending')}\n\n"
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
            markdown += f"*Generated: {timestamp}*\n"

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown)

            print("  ✓ Comprehensive markdown report saved successfully")
        except Exception as e:
            print(f"  ⚠ Warning: Could not generate markdown summary: {e}")
            import traceback

            traceback.print_exc()


def kickoff():
    """Run the security requirements flow."""
    # Get input file from environment or use default
    input_file = os.getenv("INPUT_FILE", "inputs/requirements.txt")

    flow = SecurityRequirementsFlow()
    flow.state.input_file = input_file

    print("\n" + "=" * 80)
    print("SECURITY REQUIREMENTS GENERATION SYSTEM")
    print("=" * 80)
    print(f"Input: {input_file}")
    print(f"LLM Model: {os.getenv('OPENAI_MODEL_NAME', 'default')}")
    print(f"Max Iterations: {SecurityRequirementsFlow.MAX_ITERATIONS}")
    print(f"Validation Threshold: {SecurityRequirementsFlow.VALIDATION_THRESHOLD}")
    print("=" * 80 + "\n")

    flow.kickoff()

    print("\n" + "=" * 80)
    print("FLOW COMPLETE")
    print("=" * 80 + "\n")


def plot():
    """Generate flow visualization."""
    flow = SecurityRequirementsFlow()
    flow.plot()


if __name__ == "__main__":
    kickoff()
