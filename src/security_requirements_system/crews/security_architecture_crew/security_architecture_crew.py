from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import SecurityArchitectureOutput


@CrewBase
class SecurityArchitectureCrew:
    """Security Architecture Crew - Designs comprehensive security architecture"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def security_architect(self) -> Agent:
        return Agent(
            config=self.agents_config["security_architect"],
            verbose=True,
        )

    @task
    def design_security_architecture(self) -> Task:
        return Task(
            name="design_security_architecture",
            config=self.tasks_config["design_security_architecture"],
            output_pydantic=SecurityArchitectureOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Security Architecture Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
