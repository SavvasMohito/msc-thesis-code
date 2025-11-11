"""Weaviate tool for querying security standards."""

import os
from typing import Optional, Type

import weaviate
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from weaviate.classes.query import Filter


class WeaviateQueryInput(BaseModel):
    """Input schema for WeaviateQueryTool.

    IMPORTANT: Pass arguments as a dictionary with keys: query, limit (optional), standard_filter (optional).
    Example: {"query": "authentication", "limit": 10}
    """

    query: str = Field(
        ...,
        description="The search query string describing the security concern. Examples: 'authentication', 'encryption', 'access control', 'role-based access control'. This is a REQUIRED string parameter.",
        examples=["authentication", "encryption", "access control"],
    )
    limit: int = Field(
        default=5,
        description="Number of results to return. Default is 5. This is an OPTIONAL integer parameter.",
        examples=[5, 10, 20],
    )
    standard_filter: Optional[str] = Field(
        default=None,
        description="Optional filter by specific standard. Valid values: 'OWASP', 'NIST', or 'ISO27001'. If not provided or None, searches all standards. This is an OPTIONAL string parameter.",
        examples=["OWASP", "NIST", "ISO27001"],
    )


class WeaviateQueryTool(BaseTool):
    """Tool to query Weaviate for security standards and controls."""

    name: str = "Query Security Standards Database"
    description: str = (
        "Search the security standards database for controls from OWASP ASVS, NIST SP 800-53, and ISO 27001. "
        "Call this tool with a dictionary containing: 'query' (required string), 'limit' (optional int, default 5), "
        "and 'standard_filter' (optional string: 'OWASP', 'NIST', or 'ISO27001'). "
        "Example: Call with {'query': 'authentication multi-factor', 'limit': 10} "
        "or {'query': 'encryption', 'limit': 5, 'standard_filter': 'OWASP'}. "
        "The tool returns matching controls with their exact IDs, descriptions, chapters, sections, and standard. "
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
        # Validate inputs
        if not isinstance(query, str) or not query.strip():
            return "Error: 'query' parameter must be a non-empty string."

        if not isinstance(limit, int) or limit < 1:
            limit = 5  # Default to 5 if invalid

        if standard_filter is not None and not isinstance(standard_filter, str):
            standard_filter = None  # Ignore invalid filter

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
