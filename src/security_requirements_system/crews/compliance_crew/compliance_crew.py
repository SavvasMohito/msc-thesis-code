from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class ComplianceCrew:
    """Compliance Crew - Identifies regulatory requirements and ensures compliance"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def compliance_expert(self) -> Agent:
        # Using GPT-4o-mini for moderate complexity compliance assessment
        # Well-defined regulations with clear triggers (pattern matching)
        # Runs in parallel with AI security crew - cost-effective choice
        llm = LLM(model="openai/gpt-4o-mini", temperature=0.7)
        return Agent(
            config=self.agents_config["compliance_expert"],
            llm=llm,
            verbose=True,
        )

    @task
    def assess_compliance_requirements(self) -> Task:
        return Task(
            config=self.tasks_config["assess_compliance_requirements"],
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Compliance Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
