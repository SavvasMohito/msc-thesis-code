"""Quick test of domain_security_crew with multi-standard queries."""
import os
import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from security_requirements_system.crews.domain_security_crew.domain_security_crew import DomainSecurityCrew

# Create a minimal test requirement
test_requirement = {
    "req_id": "REQ-001",
    "requirement": "The system must implement secure user authentication with password hashing and multi-factor authentication support.",
    "category": "Authentication & Access Control",
    "priority": "High"
}

print("Testing Domain Security Crew with multi-standard queries...")
print(f"Requirement: {test_requirement['requirement']}\n")

crew = DomainSecurityCrew()
result = crew.crew().kickoff(inputs={
    "high_level_requirements": json.dumps([test_requirement], indent=2)
})

print("\n=== Domain Security Crew Result ===")
print(f"Output type: {type(result)}")
if hasattr(result, 'tasks_output') and result.tasks_output:
    task_output = result.tasks_output[0]
    print(f"Task output type: {type(task_output)}")
    if hasattr(task_output, 'pydantic'):
        output_data = task_output.pydantic.model_dump()
        print(f"Output keys: {list(output_data.keys())}")
        mappings = output_data.get('requirements_mapping', [])
    else:
        print(f"Task output: {str(task_output)[:500]}...")
        mappings = []
elif hasattr(result, 'requirements_mapping'):
    mappings = result.requirements_mapping
else:
    mappings = []
    print(f"Result: {str(result)[:500]}...")

print(f"\nFound {len(mappings)} requirement mappings")
if mappings:
    first_mapping = mappings[0]
    print(f"\nFirst mapping keys: {list(first_mapping.keys())}")
    
    # Check for multi-standard controls
    security_controls = first_mapping.get('security_controls', [])
    owasp_controls = first_mapping.get('owasp_controls', [])
    
    print(f"\nSecurity controls (multi-standard): {len(security_controls)}")
    print(f"OWASP controls (backward compat): {len(owasp_controls)}")
    
    if security_controls:
        print("\nStandards found in security_controls:")
        standards = {}
        for ctrl in security_controls:
            std = ctrl.get('standard', 'UNKNOWN')
            standards[std] = standards.get(std, 0) + 1
        for std, count in standards.items():
            print(f"  - {std}: {count} controls")
        
        print("\nSample controls:")
        for i, ctrl in enumerate(security_controls[:3], 1):
            print(f"\n  {i}. [{ctrl.get('standard', 'N/A')}] {ctrl.get('req_id', 'N/A')}")
            print(f"     Relevance: {ctrl.get('relevance', 'N/A')[:100]}...")

