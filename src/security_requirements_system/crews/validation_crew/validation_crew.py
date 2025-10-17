from typing import List

from crewai import Agent, Crew, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import ValidationOutput


@CrewBase
class ValidationCrew:
    """Validation Crew - Validates security requirements for quality and completeness"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def validation_expert(self) -> Agent:
        return Agent(
            config=self.agents_config["validation_expert"],
            verbose=True,
        )

    @task
    def validate_security_requirements(self) -> Task:
        return Task(
            name="validate_security_requirements",
            config=self.tasks_config["validate_security_requirements"],
            output_pydantic=ValidationOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Validation crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            verbose=True,
        )
