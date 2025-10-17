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
from security_requirements_system.crews.validation_crew import ValidationCrew

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

    # Analysis outputs
    analyzed_requirements: str = ""
    security_controls: str = ""
    ai_security: str = ""
    compliance_requirements: str = ""

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

        self.state.analyzed_requirements = result.raw
        print("\n✓ Requirements analysis complete")

    @listen(analyze_requirements)
    def map_security_controls(self):
        """Map requirements to security standards using Domain Security Crew."""
        print("\n" + "=" * 80)
        print("STEP 3: Mapping to Security Standards (OWASP, NIST, ISO 27001)")
        print("=" * 80)

        result = DomainSecurityCrew().crew().kickoff(inputs={"analyzed_requirements": self.state.analyzed_requirements})

        self.state.security_controls = result.raw
        print("\n✓ Security controls mapped")

    @listen(map_security_controls)
    def identify_ai_security(self):
        """Identify AI/ML security requirements using LLM Security Crew."""
        print("\n" + "=" * 80)
        print("STEP 4: Identifying AI/ML Security Requirements")
        print("=" * 80)

        result = (
            LLMSecurityCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": self.state.analyzed_requirements,
                }
            )
        )

        self.state.ai_security = result.raw
        print("\n✓ AI/ML security assessment complete")

    @listen(identify_ai_security)
    def assess_compliance(self):
        """Assess compliance requirements using Compliance Crew."""
        print("\n" + "=" * 80)
        print("STEP 5: Assessing Compliance Requirements")
        print("=" * 80)

        result = (
            ComplianceCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": self.state.analyzed_requirements,
                }
            )
        )

        self.state.compliance_requirements = result.raw
        print("\n✓ Compliance assessment complete")

    @listen(assess_compliance)
    def validate_requirements(self):
        """Validate all generated requirements using Validation Crew."""
        print("\n" + "=" * 80)
        print("STEP 6: Validating Security Requirements")
        print("=" * 80)

        result = (
            ValidationCrew()
            .crew()
            .kickoff(
                inputs={
                    "requirements_text": self.state.requirements_text,
                    "analyzed_requirements": self.state.analyzed_requirements,
                    "security_controls": self.state.security_controls,
                    "ai_security": self.state.ai_security,
                    "compliance_requirements": self.state.compliance_requirements,
                }
            )
        )

        self.state.validation_report = result.raw

        # Parse validation result to extract score and pass/fail
        try:
            # Try to parse as JSON
            validation_data = json.loads(result.raw)
            self.state.validation_score = validation_data.get("overall_score", 0.0)
            self.state.validation_passed = validation_data.get("validation_passed", False)
        except json.JSONDecodeError:
            # If not JSON, try to extract score from text
            import re

            score_match = re.search(r"overall_score[\"']?\s*:\s*([0-9.]+)", result.raw)
            passed_match = re.search(r"validation_passed[\"']?\s*:\s*(true|false)", result.raw, re.IGNORECASE)

            if score_match:
                self.state.validation_score = float(score_match.group(1))
            if passed_match:
                self.state.validation_passed = passed_match.group(1).lower() == "true"
            else:
                # Fallback: if score >= threshold, consider passed
                self.state.validation_passed = self.state.validation_score >= self.VALIDATION_THRESHOLD

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
        print("STEP 7: Self-Evaluation Decision")
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
        print("STEP 8: Generating Final Security Requirements Document")
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
        """Generate a human-readable markdown summary."""
        try:
            from datetime import datetime

            # Parse metadata first
            validation_score = self.state.validation_score
            validation_passed = self.state.validation_passed
            iterations = self.state.iteration_count

            markdown = f"""# Security Requirements Report
*Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*

## Metadata
- **Validation Score**: {validation_score:.2f}
- **Validation Passed**: {validation_passed}
- **Iterations**: {iterations}

---

## Original Requirements

{self.state.requirements_text}

---

## Requirements Analysis

"""

            # Parse requirements analysis (remove markdown code blocks if present)
            analysis_text = self.state.analyzed_requirements
            if "```json" in analysis_text:
                start = analysis_text.find("```json") + 7
                end = analysis_text.rfind("```")
                if start > 7 and end > start:
                    analysis_text = analysis_text[start:end].strip()

            markdown += analysis_text + "\n\n---\n\n"

            markdown += "## Security Controls Mapping\n\n"

            # Try to parse and format security controls nicely
            try:
                controls_text = self.state.security_controls
                # Remove markdown code blocks
                if "```" in controls_text:
                    start = controls_text.find("```")
                    if start >= 0:
                        # Find the first { after ```
                        start = controls_text.find("{", start)
                        end = controls_text.rfind("}")
                        if start >= 0 and end > start:
                            controls_text = controls_text[start : end + 1]  # noqa: E203

                security_controls = json.loads(controls_text)

                if "requirements_mapping" in security_controls:
                    for idx, mapping in enumerate(security_controls["requirements_mapping"], 1):
                        markdown += f"### {idx}. {mapping.get('high_level_requirement', 'Security Requirement')}\n\n"
                        markdown += f"**Security Concern:** {mapping.get('security_concern', 'N/A')}\n\n"

                        if "owasp_controls" in mapping and mapping["owasp_controls"]:
                            markdown += "**Corresponding OWASP ASVS Requirements:**\n\n"
                            for owasp in mapping["owasp_controls"]:
                                markdown += f"#### [{owasp.get('req_id', 'N/A')}] - {owasp.get('level', 'N/A')}\n\n"
                                markdown += f"- **Chapter:** {owasp.get('chapter', 'N/A')}\n"
                                markdown += f"- **Section:** {owasp.get('section', 'N/A')}\n"
                                markdown += f"- **Requirement:** {owasp.get('requirement', 'N/A')}\n"
                                markdown += f"- **Relevance:** {owasp.get('relevance', 'N/A')}\n\n"
                        else:
                            markdown += "*No OWASP controls mapped.*\n\n"

                        markdown += "---\n\n"
                else:
                    # Fallback to raw text
                    markdown += self.state.security_controls + "\n\n---\n\n"
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                # Fallback to raw text if parsing fails
                print(f"  Note: Could not parse security controls as JSON: {e}")
                markdown += self.state.security_controls + "\n\n---\n\n"

            # Add remaining sections
            markdown += "\n## AI/ML Security Requirements\n\n"
            markdown += self.state.ai_security + "\n\n---\n\n"

            markdown += "## Compliance Requirements\n\n"
            markdown += self.state.compliance_requirements + "\n\n---\n\n"

            markdown += "## Validation Report\n\n"
            markdown += self.state.validation_report + "\n"

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown)

            print("  ✓ Markdown report saved successfully")
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
