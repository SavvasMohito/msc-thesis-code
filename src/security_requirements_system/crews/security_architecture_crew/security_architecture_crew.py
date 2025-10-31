from typing import List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task


@CrewBase
class SecurityArchitectureCrew:
    """Security Architecture Crew - Designs comprehensive security architecture"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def security_architect(self) -> Agent:
        # Using GPT-5-mini for high-complexity security architecture design
        # Requires holistic architectural thinking but well-defined structure
        # GPT-5-mini provides good balance of quality and cost for this ⭐⭐⭐⭐ complexity level
        llm = LLM(model="openai/gpt-5-mini")
        return Agent(
            config=self.agents_config["security_architect"],
            llm=llm,
            verbose=True,
        )

    @task
    def design_security_architecture(self) -> Task:
        return Task(
            name="design_security_architecture",
            config=self.tasks_config["design_security_architecture"],
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
