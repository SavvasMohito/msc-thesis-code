from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class LLMSecurityCrew:
    """LLM Security Crew - Identifies and addresses AI/ML security concerns"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def llm_security_specialist(self) -> Agent:
        # Using GPT-4o-mini for moderate complexity AI/ML security analysis
        # Mainly pattern recognition to detect AI components
        # Runs in parallel with compliance crew - cost-effective choice
        llm = LLM(model="openai/gpt-4o-mini", temperature=0.7)
        return Agent(
            config=self.agents_config["llm_security_specialist"],
            llm=llm,
            verbose=True,
        )

    @task
    def identify_ai_security_requirements(self) -> Task:
        return Task(
            config=self.tasks_config["identify_ai_security_requirements"],
        )

    @crew
    def crew(self) -> Crew:
        """Creates the LLM Security Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
