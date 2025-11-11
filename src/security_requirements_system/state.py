"""State model for security requirements generation."""

from typing import Optional

from pydantic import BaseModel


class SecurityRequirementsState(BaseModel):
    """State for the security requirements generation workflow."""

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

