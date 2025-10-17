from typing import List

from pydantic import BaseModel, Field


class AnalysisOutput(BaseModel):
    """Model for the output of the requirements analysis task."""

    application_summary: str = Field(..., description="A brief, one-paragraph summary of the application's purpose.")
    high_level_requirements: List[str] = Field(..., description="A list of specific, high-level functional requirements.")


class ArchitectureOutput(BaseModel):
    """Model for the output of the system architecture analysis task."""

    architecture_summary: str = Field(..., description="A brief, one-paragraph summary of the proposed system architecture.")
    architecture_diagram: str = Field(..., description="A valid Mermaid diagram string using `graph TD` syntax.")


class OwaspControl(BaseModel):
    """Model for a single OWASP ASVS security control."""

    req_id: str = Field(..., description="The exact requirement ID from the tool output (e.g., V2.2.1).")
    chapter: str = Field(..., description="The exact chapter from the tool output.")
    section: str = Field(..., description="The exact section from the tool output.")
    level: str = Field(..., description="The exact level from the tool output (e.g., L1, L2, L3).")
    requirement: str = Field(..., description="The exact requirement text from the tool output.")
    relevance: str = Field(..., description="Detailed explanation of how this control applies to the high-level requirement.")
    integration_tips: str = Field(..., description="Actionable advice for developers on how to implement this control.")


class RequirementMapping(BaseModel):
    """Model for mapping a high-level requirement to its OWASP controls."""

    high_level_requirement: str = Field(..., description="A single high-level requirement from the input list.")
    owasp_controls: List[OwaspControl] = Field(..., description="A list of relevant OWASP controls for the requirement.")


class DomainSecurityOutput(BaseModel):
    """Model for the output of the domain security crew's mapping task."""

    requirements_mapping: List[RequirementMapping] = Field(..., description="A list of mappings, one for each high-level requirement.")


class ValidationOutput(BaseModel):
    """Model for the output of the validation task."""

    overall_score: float = Field(..., description="The overall validation score, between 0.0 and 1.0.")
    validation_passed: bool = Field(..., description="Whether the validation passed based on the score threshold.")
    feedback: str = Field(..., description="Detailed feedback on what was good and what needs improvement.")
