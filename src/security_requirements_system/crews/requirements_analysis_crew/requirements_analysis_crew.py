from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import AnalysisOutput, ArchitectureOutput


@CrewBase
class RequirementsAnalysisCrew:
    """Requirements Analysis Crew - Parses and analyzes PM requirements"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def requirements_analyst(self) -> Agent:
        # Using GPT-5 for high-complexity requirements analysis
        # This is a foundation crew requiring deep understanding and complex reasoning
        llm = LLM(model="openai/gpt-5")
        return Agent(
            config=self.agents_config["requirements_analyst"],
            llm=llm,
            verbose=True,
        )

    @agent
    def system_architect(self) -> Agent:
        # Using GPT-5 for high-complexity architecture analysis
        # Must maintain consistency across multiple outputs and generate structured data
        llm = LLM(model="openai/gpt-5")
        return Agent(
            config=self.agents_config["system_architect"],
            llm=llm,
            verbose=True,
        )

    @task
    def analyze_requirements(self) -> Task:
        return Task(
            name="analyze_requirements",
            config=self.tasks_config["analyze_requirements"],
            output_pydantic=AnalysisOutput,
        )

    @task
    def analyze_architecture(self) -> Task:
        return Task(
            name="analyze_architecture",
            config=self.tasks_config["analyze_architecture"],
            output_pydantic=ArchitectureOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Requirements Analysis Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
