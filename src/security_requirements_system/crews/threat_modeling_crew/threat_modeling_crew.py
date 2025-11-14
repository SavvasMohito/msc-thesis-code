from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from ...data_models import ThreatModelingOutput


@CrewBase
class ThreatModelingCrew:
    """Threat Modeling Crew - Performs STRIDE-based threat analysis"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def threat_modeling_expert(self) -> Agent:
        # Using GPT-5 for very high-complexity threat modeling
        # Requires sophisticated STRIDE analysis, risk assessment, and residual risk calculations
        # Complex multi-step reasoning (likelihood × impact → risk level)
        llm = LLM(model="openai/gpt-5")
        return Agent(
            config=self.agents_config["threat_modeling_expert"],
            llm=llm,
            verbose=True,
        )

    @task
    def perform_threat_modeling(self) -> Task:
        return Task(
            name="perform_threat_modeling",
            config=self.tasks_config["perform_threat_modeling"],
            output_pydantic=ThreatModelingOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Threat Modeling Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
