from typing import List

from crewai import LLM, Agent, Crew, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from security_requirements_system.data_models import DomainSecurityOutput
from security_requirements_system.tools.weaviate_tool import WeaviateQueryTool


@CrewBase
class DomainSecurityCrew:
    """Domain Security Crew - Maps requirements to security standards"""

    agents: List[BaseAgent]
    tasks: List[Task]

    agents_config = "config/agents.yaml"
    tasks_config = "config/tasks.yaml"

    @agent
    def domain_security_expert(self) -> Agent:
        # Using GPT-5 for very high-complexity security control mapping
        # Requires robust tool/function calling for Weaviate database queries
        # Complex multi-step task: analyze → query → map → explain
        # Must ensure completeness (no skipped requirements)
        llm = LLM(model="openai/gpt-5")
        return Agent(
            config=self.agents_config["domain_security_expert"],
            tools=[WeaviateQueryTool()],
            llm=llm,
            verbose=True,
        )

    @task
    def map_security_controls(self) -> Task:
        return Task(
            name="map_security_controls",
            config=self.tasks_config["map_security_controls"],
            output_pydantic=DomainSecurityOutput,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Domain Security Crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            verbose=True,
        )
