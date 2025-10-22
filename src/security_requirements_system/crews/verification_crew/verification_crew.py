from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import VerificationTestingOutput


@CrewBase
class VerificationCrew:
    """Verification and Testing Crew - Designs security testing strategy"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def security_testing_expert(self) -> Agent:
        return Agent(
            config=self.agents_config["security_testing_expert"],
            verbose=True,
        )

    @task
    def design_verification_strategy(self) -> Task:
        return Task(
            name="design_verification_strategy",
            config=self.tasks_config["design_verification_strategy"],
            output_pydantic=VerificationTestingOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Verification and Testing Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
