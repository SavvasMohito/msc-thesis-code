"""Orchestrator for security requirements generation with validation loop."""

import json
from datetime import datetime
from pathlib import Path

from security_requirements_system.crew import SecurityRequirementsCrew
from security_requirements_system.data_models import AnalysisOutput, ArchitectureOutput, ValidationOutput
from security_requirements_system.output_generator import _export_dashboard_artifacts, generate_quarto_report
from security_requirements_system.state import SecurityRequirementsState
from security_requirements_system.traceability import build_traceability_matrix

# Configuration
MAX_ITERATIONS = 3
VALIDATION_THRESHOLD = 0.7


def run_security_requirements_generation(
    input_file: str,
    max_iterations: int = MAX_ITERATIONS,
    validation_threshold: float = VALIDATION_THRESHOLD,
) -> SecurityRequirementsState:
    """
    Run security requirements generation with validation loop.

    Args:
        input_file: Path to input requirements file
        max_iterations: Maximum number of refinement iterations
        validation_threshold: Minimum validation score to pass

    Returns:
        Final state with all generated requirements
    """
    print("\n" + "=" * 80)
    print("SECURITY REQUIREMENTS GENERATION SYSTEM")
    print("=" * 80)
    print(f"Input: {input_file}")
    print(f"Max Iterations: {max_iterations}")
    print(f"Validation Threshold: {validation_threshold}")
    print("=" * 80 + "\n")

    # Initialize state
    state = SecurityRequirementsState(input_file=input_file)

    # Load requirements from file
    state = _load_requirements(state)

    # Create crew instance
    crew = SecurityRequirementsCrew().crew()

    # Validation loop
    for iteration in range(1, max_iterations + 1):
        print("\n" + "=" * 80)
        print(f"ITERATION {iteration}/{max_iterations}")
        print("=" * 80)

        # Run crew with current state
        state = _run_crew(crew, state, iteration)

        # Check validation
        if state.validation_passed:
            print(f"\n✓ VALIDATION PASSED (Score: {state.validation_score:.2f})")
            print("  Proceeding to generate final output...")
            break
        elif iteration < max_iterations:
            print(f"\n✗ VALIDATION FAILED (Score: {state.validation_score:.2f})")
            print(f"  Iteration {iteration}/{max_iterations}")
            print("  Re-running analysis with validation feedback...")
        else:
            print(f"\n⚠ MAX ITERATIONS REACHED ({max_iterations})")
            print(f"  Final Score: {state.validation_score:.2f}")
            print("  Generating output with current requirements (may need manual review)...")

    # Build traceability matrix
    state.traceability_matrix = build_traceability_matrix(
        state.detailed_requirements,
        state.threats,
        state.security_controls,
    )

    # Generate final output
    _generate_output(state)

    print("\n" + "=" * 80)
    print("GENERATION COMPLETE")
    print("=" * 80 + "\n")

    return state


def _load_requirements(state: SecurityRequirementsState) -> SecurityRequirementsState:
    """Load requirements from input file."""
    print("\n" + "=" * 80)
    print("Loading Requirements")
    print("=" * 80)

    input_path = Path(state.input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {state.input_file}")

    with open(input_path, "r", encoding="utf-8") as f:
        state.requirements_text = f.read()

    print(f"✓ Loaded requirements from {state.input_file}")
    print(f"  Length: {len(state.requirements_text)} characters")

    return state


def _run_crew(crew, state: SecurityRequirementsState, iteration: int) -> SecurityRequirementsState:
    """Run crew and parse results."""
    print("\n" + "=" * 80)
    print("Executing Security Requirements Crew")
    print("=" * 80)

    # Prepare inputs for crew
    crew_inputs = {
        "requirements_text": state.requirements_text,
        "validation_feedback": state.validation_report if iteration > 1 else "",
        "iteration": iteration,
    }

    # Run crew
    result = crew.kickoff(inputs=crew_inputs)

    # Parse results from task outputs
    state = _parse_crew_results(result, state, iteration)

    return state


def _parse_crew_results(result, state: SecurityRequirementsState, iteration: int) -> SecurityRequirementsState:
    """Parse crew task outputs and update state."""
    print("\n" + "=" * 80)
    print("Parsing Crew Results")
    print("=" * 80)

    # Update iteration count
    state.iteration_count = iteration

    # Parse task outputs by index
    task_outputs = result.tasks_output

    # Task 0: analyze_requirements
    if len(task_outputs) > 0:
        analysis_output: AnalysisOutput = task_outputs[0].pydantic  # type: ignore
        if analysis_output:
            state.application_summary = analysis_output.application_summary or ""
            state.high_level_requirements = analysis_output.high_level_requirements or []
            state.security_context = analysis_output.security_context or ""
            state.assumptions = json.dumps(analysis_output.assumptions or [], indent=2)
            state.constraints = json.dumps(analysis_output.constraints or [], indent=2)
            if analysis_output.detailed_requirements:
                state.detailed_requirements = json.dumps([req.model_dump() for req in analysis_output.detailed_requirements], indent=2)
            print("✓ Requirements analysis parsed")

    # Task 1: analyze_architecture
    if len(task_outputs) > 1:
        architecture_output: ArchitectureOutput = task_outputs[1].pydantic  # type: ignore
        if architecture_output:
            state.architecture_summary = architecture_output.architecture_summary or ""
            state.architecture_diagram = architecture_output.architecture_diagram or ""
            state.data_flow_description = architecture_output.data_flow_description or ""
            state.attack_surface_analysis = architecture_output.attack_surface_analysis or ""
            if architecture_output.components:
                state.components = json.dumps([c.model_dump() for c in architecture_output.components], indent=2)
            if architecture_output.trust_boundaries:
                state.trust_boundaries = json.dumps([t.model_dump() for t in architecture_output.trust_boundaries], indent=2)
            print("✓ Architecture analysis parsed")

    # Task 2: analyze_stakeholders_and_compliance
    if len(task_outputs) > 2:
        state.stakeholders = task_outputs[2].raw
        # Also extract compliance from this merged task
        state.compliance_requirements = task_outputs[2].raw
        print("✓ Stakeholder and compliance analysis parsed")

    # Task 3: perform_threat_modeling
    if len(task_outputs) > 3:
        threat_output = task_outputs[3].pydantic
        if threat_output:
            state.threats = threat_output.model_dump_json(indent=2)
            print("✓ Threat modeling parsed")

    # Task 4: map_security_controls
    if len(task_outputs) > 4:
        controls_output = task_outputs[4].pydantic
        if controls_output:
            state.security_controls = controls_output.model_dump_json(indent=2)
            print("✓ Security controls parsed")

    # Task 5: identify_ai_security_requirements
    if len(task_outputs) > 5:
        state.ai_security = task_outputs[5].raw
        print("✓ AI/ML security parsed")

    # Task 6: design_security_architecture
    if len(task_outputs) > 6:
        state.security_architecture = task_outputs[6].raw
        print("✓ Security architecture parsed")

    # Task 7: create_implementation_and_testing_plan
    if len(task_outputs) > 7:
        state.implementation_roadmap = task_outputs[7].raw
        # Also extract verification from this merged task
        state.verification_testing = task_outputs[7].raw
        print("✓ Implementation and testing plan parsed")

    # Task 8: validate_security_requirements
    if len(task_outputs) > 8:
        validation_output: ValidationOutput = task_outputs[8].pydantic  # type: ignore
        if validation_output:
            state.validation_report = validation_output.model_dump_json(indent=2)
            state.validation_score = validation_output.overall_score
            state.validation_passed = validation_output.validation_passed
            print(f"✓ Validation parsed (Score: {state.validation_score:.2f}, Passed: {state.validation_passed})")

    return state


def _generate_output(state: SecurityRequirementsState):
    """Generate output files."""
    print("\n" + "=" * 80)
    print("Generating Output")
    print("=" * 80)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    # Create artifacts directory
    artifacts_dir = output_dir / f"artifacts_{timestamp}"
    artifacts_dir.mkdir(exist_ok=True)

    # Export dashboard artifacts
    _export_dashboard_artifacts(state, artifacts_dir, timestamp)

    # Generate Quarto markdown report
    qmd_file = output_dir / f"security_requirements_{timestamp}.qmd"
    generate_quarto_report(state, qmd_file, artifacts_dir)

    print("\n✓ Output generated successfully")
    print(f"  Primary output (Quarto): {qmd_file}")
    print(f"  Dashboard artifacts: {artifacts_dir}")
    print(f"  Validation Score: {state.validation_score:.2f}")
    print(f"  Total Iterations: {state.iteration_count}")
