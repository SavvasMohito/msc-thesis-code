from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class StakeholderCrew:
    """Stakeholder Analysis Crew - Identifies user personas and trust boundaries"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def stakeholder_analyst(self) -> Agent:
        # Using GPT-4o-mini for moderate complexity stakeholder analysis
        # Straightforward analysis task, runs in parallel with other crews
        # Cost-effective choice for this level of complexity
        llm = LLM(model="openai/gpt-4o-mini", temperature=0.7)
        return Agent(
            config=self.agents_config["stakeholder_analyst"],
            llm=llm,
            verbose=True,
        )

    @task
    def analyze_stakeholders(self) -> Task:
        return Task(
            name="analyze_stakeholders",
            config=self.tasks_config["analyze_stakeholders"],
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
