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
    standard_filter: Optional[str] = Field(default=None, description="Filter by specific standard (e.g., 'OWASP', 'NIST', 'ISO27001')")


class WeaviateQueryTool(BaseTool):
    """Tool to query Weaviate for security standards and controls."""

    name: str = "Query Security Standards Database"
    description: str = (
        "Searches the security standards database (OWASP, NIST, ISO 27001) "
        "for relevant controls and requirements based on a semantic query. "
        "Returns the most relevant security controls with their descriptions."
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
                    response = collection.query.near_text(
                        query=query, limit=limit, filters=Filter().by_property("standard").equal(standard_filter)
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
                        f"{i}. [{props.get('standard', 'Unknown')}] "
                        f"{props.get('control_id', 'N/A')}: {props.get('title', 'No title')}\n"
                        f"   Description: {props.get('description', 'No description')}\n"
                        f"   Category: {props.get('category', 'Uncategorized')}\n"
                    )
                    results.append(result)

                return "\n".join(results)

            finally:
                client.close()

        except Exception as e:
            return f"Error querying security standards database: {str(e)}"
