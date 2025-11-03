"""Weaviate tool for querying security standards."""

import os
from typing import Optional, Type

import weaviate
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from weaviate.classes.query import Filter


class WeaviateQueryInput(BaseModel):
    """Input schema for WeaviateQueryTool."""

    query: str = Field(..., description="The search query to find relevant security controls")
    limit: int = Field(default=5, description="Number of results to return")
    standard_filter: Optional[str] = Field(
        default=None, description="Filter by specific standard (e.g., 'OWASP', 'NIST', 'ISO27001'). If None, searches all standards."
    )


class WeaviateQueryTool(BaseTool):
    """Tool to query Weaviate for security standards and controls."""

    name: str = "Query Security Standards Database"
    description: str = (
        "Use this tool to search the security standards database containing controls from "
        "OWASP ASVS, NIST SP 800-53, and ISO 27001. Provide a semantic query describing "
        "the security concern (e.g., 'authentication', 'encryption', 'access control'). "
        "The tool searches across all standards and returns the best matching controls. "
        "Returns controls with their exact IDs, descriptions, chapters, sections, and standard. "
        "You MUST use this tool to find controls - copy the data exactly from tool results."
    )
    args_schema: Type[BaseModel] = WeaviateQueryInput

    def _run(
        self,
        query: str,
        limit: int = 5,
        standard_filter: Optional[str] = None,
    ) -> str:
        """Execute the query against Weaviate."""
        try:
            # Connect to Weaviate
            client = weaviate.connect_to_local(
                host=os.getenv("WEAVIATE_HOST", "localhost"),
                port=int(os.getenv("WEAVIATE_PORT", "8080")),
                grpc_port=int(os.getenv("WEAVIATE_GRPC_PORT", "50051")),
            )

            try:
                collection = client.collections.get("SecurityControl")

                # Build query with optional filter
                query_kwargs = {
                    "query": query,
                    "limit": limit,
                }

                if standard_filter:
                    # Normalize standard filter to match data values
                    standard_map = {
                        "OWASP": "OWASP",
                        "NIST": "NIST",
                        "ISO27001": "ISO27001",
                        "ISO": "ISO27001",  # Allow ISO as shorthand
                    }
                    normalized_filter = standard_map.get(standard_filter.upper(), standard_filter)
                    response = collection.query.near_text(
                        query=query, limit=limit, filters=Filter.by_property("standard").equal(normalized_filter)
                    )
                else:
                    response = collection.query.near_text(**query_kwargs)

                # Format results
                if not response.objects:
                    return "No relevant security controls found."

                results = []
                for i, obj in enumerate(response.objects, 1):
                    props = obj.properties
                    result = (
                        f"{i}. [{props.get('standard', 'Unknown')}] {props.get('req_id', 'N/A')}\n"
                        f"   Chapter: {props.get('chapter_id', '')} - {props.get('chapter_name', '')}\n"
                        f"   Section: {props.get('section_id', '')} - {props.get('section_name', '')}\n"
                        f"   Level: {props.get('level', 'N/A')}\n"
                        f"   Requirement: {props.get('req_description', 'No description')}\n"
                    )
                    results.append(result)

                return "\n".join(results)

            finally:
                client.close()

        except Exception as e:
            return f"Error querying security standards database: {str(e)}"
