"""Unified Security Requirements Crew."""

from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import (
    AnalysisOutput,
    ArchitectureOutput,
    DomainSecurityOutput,
    ThreatModelingOutput,
    ValidationOutput,
)
from security_requirements_system.tools.weaviate_tool import WeaviateQueryTool

# ====================
# LLM MODEL DEFINITIONS
# ====================
GPT_5_NANO = LLM(model="openai/gpt-5-nano")
GPT_5_MINI = LLM(model="openai/gpt-5-mini")
GPT_5 = LLM(model="openai/gpt-5")  # Full GPT-5 for most critical/complex tasks


@CrewBase
class SecurityRequirementsCrew:
    """
    Unified crew for comprehensive security requirements generation.

    This crew consolidates all security analysis workflows into a single,
    sequential process with 8 agents and 9 tasks.
    """

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    # ====================
    # AGENT DEFINITIONS
    # ====================

    @agent
    def requirements_analyst(self) -> Agent:
        """Requirements Analyst - Parses and analyzes PM requirements."""
        return Agent(
            config=self.agents_config["requirements_analyst"],
            llm=GPT_5_MINI,
            verbose=True,
        )

    @agent
    def system_architect(self) -> Agent:
        """System Architect - Creates architecture diagrams and analysis."""
        return Agent(
            config=self.agents_config["system_architect"],
            llm=GPT_5,  # Upgraded: Better Mermaid syntax precision + architectural reasoning
            verbose=True,
        )

    @agent
    def domain_security_expert(self) -> Agent:
        """Domain Security Expert - Maps requirements to security controls via database."""
        return Agent(
            config=self.agents_config["domain_security_expert"],
            tools=[WeaviateQueryTool()],
            llm=GPT_5,  # Upgraded: Complex tool usage + semantic matching
            verbose=True,
        )

    @agent
    def threat_modeling_expert(self) -> Agent:
        """Threat Modeling Expert - Performs STRIDE-based threat analysis."""
        return Agent(
            config=self.agents_config["threat_modeling_expert"],
            llm=GPT_5,  # Upgraded: Requires creative attack vector thinking + deep security knowledge
            verbose=True,
        )

    @agent
    def security_architect(self) -> Agent:
        """Security Architect - Designs comprehensive security architecture."""
        return Agent(
            config=self.agents_config["security_architect"],
            llm=GPT_5_MINI,
            verbose=True,
        )

    @agent
    def validation_expert(self) -> Agent:
        """Validation Expert - Validates security requirements for quality."""
        return Agent(
            config=self.agents_config["validation_expert"],
            llm=GPT_5,  # Upgraded: CRITICAL quality gate - synthesizes ALL outputs, identifies gaps
            verbose=True,
        )

    @agent
    def compliance_and_regulatory_analyst(self) -> Agent:
        """Compliance & Regulatory Analyst - Handles stakeholder and compliance analysis."""
        return Agent(
            config=self.agents_config["compliance_and_regulatory_analyst"],
            llm=GPT_5_MINI,  # Upgraded from NANO: Dual analysis (stakeholders + compliance) requires more reasoning
            verbose=True,
        )

    @agent
    def specialized_security_analyst(self) -> Agent:
        """Specialized Security Analyst - Handles AI/ML security and additional stakeholder concerns."""
        return Agent(
            config=self.agents_config["specialized_security_analyst"],
            llm=GPT_5,  # Upgraded: Cutting-edge AI/ML security knowledge + emerging threats
            verbose=True,
        )

    @agent
    def implementation_and_testing_specialist(self) -> Agent:
        """Implementation & Testing Specialist - Creates roadmap and testing strategy."""
        return Agent(
            config=self.agents_config["implementation_and_testing_specialist"],
            llm=GPT_5_NANO,
            verbose=True,
        )

    # ====================
    # TASK DEFINITIONS
    # ====================

    @task
    def analyze_requirements(self) -> Task:
        """Task 1: Analyze requirements."""
        return Task(
            name="analyze_requirements",
            config=self.tasks_config["analyze_requirements"],
            output_pydantic=AnalysisOutput,
        )

    @task
    def analyze_architecture(self) -> Task:
        """Task 2: Analyze architecture."""
        return Task(
            name="analyze_architecture",
            config=self.tasks_config["analyze_architecture"],
            output_pydantic=ArchitectureOutput,
        )

    @task
    def analyze_stakeholders_and_compliance(self) -> Task:
        """Task 3: Analyze stakeholders and compliance (merged)."""
        return Task(
            name="analyze_stakeholders_and_compliance",
            config=self.tasks_config["analyze_stakeholders_and_compliance"],
        )

    @task
    def perform_threat_modeling(self) -> Task:
        """Task 4: Perform threat modeling."""
        return Task(
            name="perform_threat_modeling",
            config=self.tasks_config["perform_threat_modeling"],
            output_pydantic=ThreatModelingOutput,
        )

    @task
    def map_security_controls(self) -> Task:
        """Task 5: Map security controls."""
        return Task(
            name="map_security_controls",
            config=self.tasks_config["map_security_controls"],
            output_pydantic=DomainSecurityOutput,
        )

    @task
    def identify_ai_security_requirements(self) -> Task:
        """Task 6: Identify AI/ML security requirements."""
        return Task(
            name="identify_ai_security_requirements",
            config=self.tasks_config["identify_ai_security_requirements"],
        )

    @task
    def design_security_architecture(self) -> Task:
        """Task 7: Design security architecture."""
        return Task(
            name="design_security_architecture",
            config=self.tasks_config["design_security_architecture"],
        )

    @task
    def create_implementation_and_testing_plan(self) -> Task:
        """Task 8: Create implementation roadmap and testing strategy (merged)."""
        return Task(
            name="create_implementation_and_testing_plan",
            config=self.tasks_config["create_implementation_and_testing_plan"],
        )

    @task
    def validate_security_requirements(self) -> Task:
        """Task 9: Validate security requirements."""
        return Task(
            name="validate_security_requirements",
            config=self.tasks_config["validate_security_requirements"],
            output_pydantic=ValidationOutput,
        )

    # ====================
    # CREW DEFINITION
    # ====================

    @crew
    def crew(self) -> Crew:
        """Creates the unified Security Requirements Crew."""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
