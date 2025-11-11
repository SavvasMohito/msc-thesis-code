#!/usr/bin/env python
"""
Main entry point for the Security Requirements System.

This system orchestrates a unified crew of security agents to transform high-level
product requirements into comprehensive, standards-aligned security requirements
with automated validation.
"""

import os

from dotenv import load_dotenv

from security_requirements_system.orchestrator import run_security_requirements_generation

load_dotenv()


def kickoff():
    """Run the security requirements generation system."""
    # Get input file from environment or use default
    input_file = os.getenv("INPUT_FILE", "inputs/sample_taskmgmt.txt")

    # Run the generation with validation loop
    run_security_requirements_generation(input_file)


if __name__ == "__main__":
    kickoff()
