from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# ============================================================================
# Requirements Analysis Models
# ============================================================================


class RequirementDetail(BaseModel):
    """Detailed analysis of a single requirement."""

    requirement_id: str = Field(..., description="Unique identifier for the requirement (e.g., REQ-001)")
    requirement_text: str = Field(..., description="The high-level requirement text")
    business_category: str = Field(..., description="Business category (e.g., Authentication, Data Management)")
    security_sensitivity: str = Field(..., description="Security sensitivity level (High, Medium, Low)")
    data_classification: str = Field(..., description="Data classification (Public, Internal, Confidential, Restricted)")
    rationale: str = Field(..., description="Why this requirement exists and its business value")


class AnalysisOutput(BaseModel):
    """Model for the output of the requirements analysis task."""

    application_summary: str = Field(..., description="A brief, one-paragraph summary of the application's purpose.")
    high_level_requirements: List[str] = Field(..., description="A list of specific, high-level functional requirements.")
    detailed_requirements: Optional[List[RequirementDetail]] = Field(
        default=None, description="Detailed breakdown of each requirement with metadata"
    )
    security_context: Optional[str] = Field(
        default=None, description="Overview of regulatory and compliance obligations relevant to the domain"
    )
    assumptions: Optional[List[str]] = Field(default=None, description="Key assumptions about the system")
    constraints: Optional[List[str]] = Field(default=None, description="Technical and operational constraints")


# ============================================================================
# Architecture Models
# ============================================================================


class Component(BaseModel):
    """Detailed information about a system component."""

    name: str = Field(..., description="Component name")
    responsibility: str = Field(..., description="What this component does")
    security_criticality: str = Field(..., description="Security criticality (Critical, High, Medium, Low)")
    external_dependencies: List[str] = Field(default=[], description="External systems/APIs this component depends on")
    data_handled: List[str] = Field(default=[], description="Types of data this component handles")


class TrustBoundary(BaseModel):
    """Trust boundary definition."""

    name: str = Field(..., description="Trust boundary name")
    components: List[str] = Field(..., description="Components within this boundary")
    boundary_type: str = Field(..., description="Type of boundary (e.g., Network, Process, User)")
    security_controls: List[str] = Field(..., description="Security controls protecting this boundary")


class ArchitectureOutput(BaseModel):
    """Model for the output of the system architecture analysis task."""

    architecture_summary: str = Field(..., description="A brief, one-paragraph summary of the proposed system architecture.")
    architecture_diagram: str = Field(..., description="A valid Mermaid diagram string using `graph TD` syntax.")
    components: Optional[List[Component]] = Field(default=None, description="Detailed component breakdown")
    data_flow_description: Optional[str] = Field(default=None, description="Description of how data flows through the system")
    trust_boundaries: Optional[List[TrustBoundary]] = Field(default=None, description="Trust boundaries in the system")
    attack_surface_analysis: Optional[str] = Field(default=None, description="Analysis of the system's attack surface")


# ============================================================================
# Stakeholder Models
# ============================================================================


class Stakeholder(BaseModel):
    """Stakeholder or user persona."""

    role_name: str = Field(..., description="Name of the role/persona")
    description: str = Field(..., description="Description of the role")
    privilege_level: str = Field(..., description="Privilege level (Admin, User, Guest, etc.)")
    security_concerns: List[str] = Field(..., description="Key security concerns for this role")
    trust_level: str = Field(..., description="Trust level (Trusted, Partially Trusted, Untrusted)")


class StakeholderAnalysisOutput(BaseModel):
    """Model for stakeholder analysis output."""

    stakeholders: List[Stakeholder] = Field(..., description="List of identified stakeholders and personas")
    trust_model: str = Field(..., description="Description of the trust model and trust boundaries")


# ============================================================================
# Threat Modeling Models
# ============================================================================


class Threat(BaseModel):
    """A single threat identified during threat modeling."""

    threat_id: str = Field(..., description="Unique threat identifier (e.g., THR-001)")
    component: str = Field(..., description="Component or requirement this threat applies to")
    threat_category: str = Field(..., description="STRIDE category (Spoofing, Tampering, Repudiation, etc.)")
    description: str = Field(..., description="Description of the threat")
    likelihood: str = Field(..., description="Likelihood (High, Medium, Low)")
    impact: str = Field(..., description="Impact (High, Medium, Low)")
    risk_level: str = Field(..., description="Overall risk level (Critical, High, Medium, Low)")
    mitigation_strategy: str = Field(..., description="Recommended mitigation approach")


class ThreatModelingOutput(BaseModel):
    """Model for threat modeling output."""

    methodology: str = Field(..., description="Threat modeling methodology used (e.g., STRIDE)")
    threats: List[Threat] = Field(..., description="Identified threats")
    risk_summary: str = Field(..., description="Summary of key risks and priorities")


# ============================================================================
# Security Control Models
# ============================================================================


class OwaspControl(BaseModel):
    """Model for a single OWASP ASVS security control."""

    req_id: str = Field(..., description="The exact requirement ID from the tool output (e.g., V2.2.1).")
    chapter: str = Field(..., description="The exact chapter from the tool output.")
    section: str = Field(..., description="The exact section from the tool output.")
    level: str = Field(..., description="The exact level from the tool output (e.g., L1, L2, L3).")
    requirement: str = Field(..., description="The exact requirement text from the tool output.")
    relevance: str = Field(..., description="Detailed explanation of how this control applies to the high-level requirement.")
    integration_tips: str = Field(..., description="Actionable advice for developers on how to implement this control.")
    priority: Optional[str] = Field(default="Medium", description="Implementation priority (Critical, High, Medium, Low)")
    verification_method: Optional[str] = Field(default=None, description="How to verify this control is properly implemented")


class RequirementMapping(BaseModel):
    """Model for mapping a high-level requirement to its OWASP controls."""

    high_level_requirement: str = Field(..., description="A single high-level requirement from the input list.")
    requirement_id: Optional[str] = Field(default=None, description="Unique identifier for this requirement")
    owasp_controls: List[OwaspControl] = Field(..., description="A list of relevant OWASP controls for the requirement.")


class CrossFunctionalControl(BaseModel):
    """Security controls that apply across the entire system."""

    control_name: str = Field(..., description="Name of the control")
    description: str = Field(..., description="Description of what the control does")
    applies_to: List[str] = Field(..., description="Components or areas this applies to")
    implementation_guidance: str = Field(..., description="How to implement this control")


class DomainSecurityOutput(BaseModel):
    """Model for the output of the domain security crew's mapping task."""

    requirements_mapping: List[RequirementMapping] = Field(..., description="A list of mappings, one for each high-level requirement.")
    cross_functional_controls: Optional[List[CrossFunctionalControl]] = Field(
        default=None, description="Security controls that apply globally across the system"
    )
    recommended_asvs_level: Optional[str] = Field(default=None, description="Recommended ASVS compliance level (L1, L2, L3)")


# ============================================================================
# Security Architecture Models
# ============================================================================


class ComponentSecurityControl(BaseModel):
    """Security controls for a specific component."""

    component_name: str = Field(..., description="Name of the component")
    required_controls: List[str] = Field(..., description="List of required security controls")
    architectural_patterns: List[str] = Field(..., description="Recommended security patterns (e.g., Zero Trust)")


class DataProtectionStrategy(BaseModel):
    """Data protection strategy details."""

    data_classification_scheme: str = Field(..., description="Data classification approach")
    encryption_requirements: str = Field(..., description="Encryption requirements for data at rest and in transit")
    retention_policies: str = Field(..., description="Data retention policies")
    handling_procedures: str = Field(..., description="Data handling procedures")


class ThirdPartyIntegrationSecurity(BaseModel):
    """Security requirements for third-party integrations."""

    integration_name: str = Field(..., description="Name of the integration")
    security_requirements: List[str] = Field(..., description="Security requirements for this integration")
    risk_assessment: str = Field(..., description="Risk assessment for this integration")


class SecurityArchitectureOutput(BaseModel):
    """Model for security architecture recommendations."""

    architectural_principles: List[str] = Field(..., description="Core security principles (e.g., Zero Trust, Defense in Depth)")
    component_controls: List[ComponentSecurityControl] = Field(..., description="Security controls by component")
    data_protection_strategy: DataProtectionStrategy = Field(..., description="Data protection strategy")
    third_party_integrations: Optional[List[ThirdPartyIntegrationSecurity]] = Field(
        default=None, description="Security for third-party integrations"
    )


# ============================================================================
# Implementation Roadmap Models
# ============================================================================


class ImplementationPhase(BaseModel):
    """A phase in the implementation roadmap."""

    phase_name: str = Field(..., description="Name of the phase (e.g., Immediate, Short-term)")
    timeline: str = Field(..., description="Timeline for this phase")
    controls: List[str] = Field(..., description="Security controls to implement in this phase")
    rationale: str = Field(..., description="Why these controls are prioritized for this phase")
    dependencies: List[str] = Field(default=[], description="Dependencies on other phases or controls")


class ImplementationRoadmapOutput(BaseModel):
    """Model for implementation roadmap."""

    prioritization_criteria: str = Field(..., description="Criteria used for prioritization (risk, compliance, etc.)")
    phases: List[ImplementationPhase] = Field(..., description="Implementation phases")
    resource_requirements: Optional[str] = Field(default=None, description="Required resources, skills, and tools")


# ============================================================================
# Testing Strategy Models
# ============================================================================


class TestingMethod(BaseModel):
    """A testing method for security verification."""

    method_name: str = Field(..., description="Name of the testing method (e.g., SAST, DAST, Penetration Testing)")
    description: str = Field(..., description="Description of the method")
    applicable_controls: List[str] = Field(..., description="Which controls this method tests")
    frequency: str = Field(..., description="How often this should be performed")
    tools: List[str] = Field(default=[], description="Recommended tools for this method")


class VerificationTestingOutput(BaseModel):
    """Model for verification and testing strategy."""

    testing_approach: str = Field(..., description="Overall testing approach")
    testing_methods: List[TestingMethod] = Field(..., description="Specific testing methods")
    compliance_verification: str = Field(..., description="How compliance will be verified")
    continuous_monitoring: str = Field(..., description="Continuous monitoring and improvement strategy")
    kpis: List[str] = Field(default=[], description="Key performance indicators for security")


# ============================================================================
# Validation Models
# ============================================================================


class ValidationOutput(BaseModel):
    """Model for the output of the validation task."""

    overall_score: float = Field(..., description="The overall validation score, between 0.0 and 1.0.")
    validation_passed: bool = Field(..., description="Whether the validation passed based on the score threshold.")
    feedback: str = Field(..., description="Detailed feedback on what was good and what needs improvement.")
    dimension_scores: Optional[Dict[str, float]] = Field(
        default=None, description="Scores for each validation dimension (completeness, consistency, etc.)"
    )
