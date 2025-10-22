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
    ImplementationRoadmapOutput,
    SecurityArchitectureOutput,
    StakeholderAnalysisOutput,
    ThreatModelingOutput,
    ValidationOutput,
    VerificationTestingOutput,
)

load_dotenv()


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

        stakeholder_output: StakeholderAnalysisOutput = result.tasks_output[0].pydantic  # type: ignore[assignment]
        self.state.stakeholders = stakeholder_output.model_dump_json(indent=2)

        print("\n✓ Stakeholder analysis complete")
        print(f"  - Identified {len(stakeholder_output.stakeholders)} stakeholder roles")

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

        threat_output: ThreatModelingOutput = result.tasks_output[0].pydantic  # type: ignore[assignment]
        self.state.threats = threat_output.model_dump_json(indent=2)

        print("\n✓ Threat modeling complete")
        print(f"  - Identified {len(threat_output.threats)} threats")

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

        arch_output: SecurityArchitectureOutput = result.tasks_output[0].pydantic  # type: ignore[assignment]
        self.state.security_architecture = arch_output.model_dump_json(indent=2)

        print("\n✓ Security architecture design complete")
        print(f"  - Defined {len(arch_output.architectural_principles)} architectural principles")
        print(f"  - Component controls for {len(arch_output.component_controls)} components")

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

        roadmap_output: ImplementationRoadmapOutput = result.tasks_output[0].pydantic  # type: ignore[assignment]
        self.state.implementation_roadmap = roadmap_output.model_dump_json(indent=2)

        print("\n✓ Implementation roadmap created")
        print(f"  - Defined {len(roadmap_output.phases)} implementation phases")

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

        verification_output: VerificationTestingOutput = result.tasks_output[0].pydantic  # type: ignore[assignment]
        self.state.verification_testing = verification_output.model_dump_json(indent=2)

        print("\n✓ Verification strategy designed")
        print(f"  - Defined {len(verification_output.testing_methods)} testing methods")
        print(f"  - Defined {len(verification_output.kpis)} KPIs for monitoring")

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
    def generate_final_output(self):
        """Generate final security requirements document."""
        # Only generate output if validation passed or max iterations reached
        # TODO: this does not work as expected, we should generate output even if validation failed
        # if not self.state.should_generate_output:
        #     return  # Skip output generation when retrying

        print("\n" + "=" * 80)
        print("STEP 13: Generating Final Security Requirements Document")
        print("=" * 80)

        # Generate timestamp for unique filenames
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save to output file
        output_dir = Path("outputs")
        output_dir.mkdir(exist_ok=True)

        # Generate markdown as primary output
        md_file = output_dir / f"security_requirements_{timestamp}.md"
        self._generate_markdown_summary(md_file)

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
        print(f"  Primary output (Markdown): {md_file}")
        # print(f"  Backup (JSON): {json_file}")
        print(f"  Validation Score: {self.state.validation_score:.2f}")
        print(f"  Total Iterations: {self.state.iteration_count}")

    def _generate_markdown_summary(self, output_path: Path):
        """Generate a comprehensive, professional markdown summary following recommended structure."""
        try:
            from datetime import datetime

            validation_score = self.state.validation_score
            validation_passed = self.state.validation_passed
            iterations = self.state.iteration_count
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Start building the comprehensive report
            markdown = f"""# Security Requirements Analysis Report
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
                try:
                    stakeholder_data = json.loads(self.state.stakeholders)
                    markdown += "### 3.1. Identified Stakeholders and User Personas\n\n"
                    markdown += "| Role | Privilege Level | Trust Level | Key Security Concerns |\n"
                    markdown += "|------|-----------------|-------------|----------------------|\n"
                    for stakeholder in stakeholder_data.get("stakeholders", []):
                        concerns = ", ".join(stakeholder.get("security_concerns", [])[:2])
                        markdown += f"| {stakeholder.get('role_name', 'N/A')} | {stakeholder.get('privilege_level', 'N/A')} | {stakeholder.get('trust_level', 'N/A')} | {concerns}... |\n"

                    markdown += f"\n### 3.2. Trust Model\n\n{stakeholder_data.get('trust_model', 'No trust model defined.')}\n"
                except Exception as e:
                    markdown += f"*Error parsing stakeholder data: {e}*\n"
            else:
                markdown += "*Stakeholder analysis not available.*\n"

            markdown += "\n---\n\n"

            # Section 4: System Architecture Analysis
            markdown += "## 4. System Architecture Analysis\n\n"
            markdown += f"### 4.1. Architectural Overview\n\n{self.state.architecture_summary}\n\n"

            markdown += "### 4.2. Architecture Diagram\n\n```mermaid\n"
            markdown += self.state.architecture_diagram
            markdown += "\n```\n\n"

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
            if self.state.threats:
                try:
                    threat_data = json.loads(self.state.threats)
                    markdown += f"### 5.1. Methodology\n\n{threat_data.get('methodology', 'STRIDE')}\n\n"
                    markdown += "### 5.2. Identified Threats\n\n"
                    markdown += "| Threat ID | Component | Category | Risk Level | Description |\n"
                    markdown += "|-----------|-----------|----------|------------|-------------|\n"
                    for threat in threat_data.get("threats", [])[:20]:  # Limit to top 20 threats
                        markdown += f"| {threat.get('threat_id', 'N/A')} | {threat.get('component', 'N/A')} | {threat.get('threat_category', 'N/A')} | {threat.get('risk_level', 'N/A')} | {threat.get('description', 'N/A')[:50]}... |\n"

                    if len(threat_data.get("threats", [])) > 20:
                        markdown += (
                            f"\n*Showing 20 of {len(threat_data.get('threats', []))} total threats. See appendix for complete list.*\n"
                        )

                    markdown += f"\n### 5.3. Risk Summary\n\n{threat_data.get('risk_summary', 'No risk summary available.')}\n"
                except Exception as e:
                    markdown += f"*Error parsing threat data: {e}*\n"
            else:
                markdown += "*Threat modeling not available.*\n"

            markdown += "\n---\n\n"

            # Section 6: OWASP ASVS Security Requirements Mapping
            markdown += "## 6. OWASP ASVS Security Requirements Mapping\n\n"

            try:
                security_controls_data = json.loads(self.state.security_controls)

                # Add recommended ASVS level
                if security_controls_data.get("recommended_asvs_level"):
                    markdown += "### 6.1. Recommended ASVS Compliance Level\n\n"
                    markdown += f"**Recommended Level:** {security_controls_data.get('recommended_asvs_level')}\n\n"

                markdown += "### 6.2. Requirements Mapping\n\n"
                markdown += "The following table maps each high-level requirement to specific OWASP ASVS controls:\n\n"

                mappings = security_controls_data.get("requirements_mapping", [])

                for i, mapping in enumerate(mappings, 1):
                    req = mapping.get("high_level_requirement", "N/A")
                    req_id = mapping.get("requirement_id", f"REQ-{i:03d}")
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
                try:
                    arch_data = json.loads(self.state.security_architecture)

                    markdown += "### 9.1. Architectural Security Principles\n\n"
                    for principle in arch_data.get("architectural_principles", []):
                        markdown += f"- **{principle}**\n"

                    markdown += "\n### 9.2. Component-Level Security Controls\n\n"
                    for comp_control in arch_data.get("component_controls", []):
                        markdown += f"#### {comp_control.get('component_name', 'N/A')}\n\n"
                        markdown += "**Required Controls:**\n"
                        for control in comp_control.get("required_controls", []):
                            markdown += f"- {control}\n"
                        markdown += "\n**Recommended Patterns:**\n"
                        for pattern in comp_control.get("architectural_patterns", []):
                            markdown += f"- {pattern}\n"
                        markdown += "\n"

                    markdown += "### 9.3. Data Protection Strategy\n\n"
                    data_protection = arch_data.get("data_protection_strategy", {})
                    markdown += f"**Data Classification:** {data_protection.get('data_classification_scheme', 'N/A')}\n\n"
                    markdown += f"**Encryption Requirements:** {data_protection.get('encryption_requirements', 'N/A')}\n\n"
                    markdown += f"**Retention Policies:** {data_protection.get('retention_policies', 'N/A')}\n\n"
                    markdown += f"**Handling Procedures:** {data_protection.get('handling_procedures', 'N/A')}\n\n"

                    if arch_data.get("third_party_integrations"):
                        markdown += "### 9.4. Third-Party Integration Security\n\n"
                        for integration in arch_data.get("third_party_integrations", []):
                            markdown += f"**{integration.get('integration_name', 'N/A')}**\n\n"
                            markdown += "*Security Requirements:*\n"
                            for req in integration.get("security_requirements", []):
                                markdown += f"- {req}\n"
                            markdown += f"\n*Risk Assessment:* {integration.get('risk_assessment', 'N/A')}\n\n"

                except Exception as e:
                    markdown += f"*Error parsing security architecture: {e}*\n"
            else:
                markdown += "*Security architecture recommendations not available.*\n"

            markdown += "\n---\n\n"

            # Section 10: Implementation Roadmap
            markdown += "## 10. Implementation Roadmap\n\n"
            if self.state.implementation_roadmap:
                try:
                    roadmap_data = json.loads(self.state.implementation_roadmap)

                    markdown += f"### 10.1. Prioritization Framework\n\n{roadmap_data.get('prioritization_criteria', 'N/A')}\n\n"

                    markdown += "### 10.2. Phased Implementation Plan\n\n"
                    for phase in roadmap_data.get("phases", []):
                        markdown += f"#### Phase: {phase.get('phase_name', 'N/A')}\n\n"
                        markdown += f"**Timeline:** {phase.get('timeline', 'N/A')}\n\n"
                        markdown += f"**Rationale:** {phase.get('rationale', 'N/A')}\n\n"
                        markdown += "**Controls to Implement:**\n"
                        for control in phase.get("controls", []):
                            markdown += f"- {control}\n"
                        if phase.get("dependencies"):
                            markdown += "\n**Dependencies:**\n"
                            for dep in phase.get("dependencies", []):
                                markdown += f"- {dep}\n"
                        markdown += "\n"

                    if roadmap_data.get("resource_requirements"):
                        markdown += f"### 10.3. Resource Requirements\n\n{roadmap_data.get('resource_requirements')}\n\n"

                except Exception as e:
                    markdown += f"*Error parsing implementation roadmap: {e}*\n"
            else:
                markdown += "*Implementation roadmap not available.*\n"

            markdown += "\n---\n\n"

            # Section 11: Verification and Testing Strategy
            markdown += "## 11. Verification and Testing Strategy\n\n"
            if self.state.verification_testing:
                try:
                    verification_data = json.loads(self.state.verification_testing)

                    markdown += f"### 11.1. Testing Approach\n\n{verification_data.get('testing_approach', 'N/A')}\n\n"

                    markdown += "### 11.2. Testing Methods\n\n"
                    markdown += "| Method | Frequency | Tools |\n"
                    markdown += "|--------|-----------|-------|\n"
                    for method in verification_data.get("testing_methods", []):
                        tools = ", ".join(method.get("tools", [])[:3])
                        markdown += f"| {method.get('method_name', 'N/A')} | {method.get('frequency', 'N/A')} | {tools} |\n"

                    markdown += f"\n### 11.3. Compliance Verification\n\n{verification_data.get('compliance_verification', 'N/A')}\n\n"
                    markdown += f"### 11.4. Continuous Monitoring\n\n{verification_data.get('continuous_monitoring', 'N/A')}\n\n"

                    if verification_data.get("kpis"):
                        markdown += "### 11.5. Key Performance Indicators (KPIs)\n\n"
                        for kpi in verification_data.get("kpis", []):
                            markdown += f"- {kpi}\n"

                except Exception as e:
                    markdown += f"*Error parsing verification strategy: {e}*\n"
            else:
                markdown += "*Verification and testing strategy not available.*\n"

            markdown += "\n---\n\n"

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

            markdown += "---\n\n"
            markdown += "## Appendix C: References\n\n"
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
