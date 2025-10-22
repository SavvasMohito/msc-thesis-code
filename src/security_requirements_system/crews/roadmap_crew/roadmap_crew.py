from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import ImplementationRoadmapOutput


@CrewBase
class RoadmapCrew:
    """Implementation Roadmap Crew - Creates prioritized implementation plan"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def implementation_planner(self) -> Agent:
        return Agent(
            config=self.agents_config["implementation_planner"],
            verbose=True,
        )

    @task
    def create_implementation_roadmap(self) -> Task:
        return Task(
            name="create_implementation_roadmap",
            config=self.tasks_config["create_implementation_roadmap"],
            output_pydantic=ImplementationRoadmapOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Implementation Roadmap Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
