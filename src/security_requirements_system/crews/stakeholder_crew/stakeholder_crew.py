from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import StakeholderAnalysisOutput


@CrewBase
class StakeholderCrew:
    """Stakeholder Analysis Crew - Identifies user personas and trust boundaries"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def stakeholder_analyst(self) -> Agent:
        return Agent(
            config=self.agents_config["stakeholder_analyst"],
            verbose=True,
        )

    @task
    def analyze_stakeholders(self) -> Task:
        return Task(
            name="analyze_stakeholders",
            config=self.tasks_config["analyze_stakeholders"],
            output_pydantic=StakeholderAnalysisOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Stakeholder Analysis Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
