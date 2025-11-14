from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class RoadmapCrew:
    """Implementation Roadmap Crew - Creates prioritized implementation plan"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def implementation_planner(self) -> Agent:
        # Using GPT-4o for moderate-high complexity roadmap creation
        # Requires prioritization logic and balancing multiple factors (risk, compliance, dependencies)
        # Moderate-high complexity warrants better than gpt-4o-mini
        # Runs in parallel with verification crew
        llm = LLM(model="openai/gpt-4o", temperature=0.7)
        return Agent(
            config=self.agents_config["implementation_planner"],
            llm=llm,
            verbose=True,
        )

    @task
    def create_implementation_roadmap(self) -> Task:
        return Task(
            name="create_implementation_roadmap",
            config=self.tasks_config["create_implementation_roadmap"],
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
