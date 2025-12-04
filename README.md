# Multi-Agent System for Security Requirements Engineering (MAS-SRE)

## 📖 Overview

This repository contains the reference implementation for the Master's Thesis: **"A Multi-Agent Approach for a Security-Aware Translation of Software Business Requirements."**

The system is a Multi-Agent System (MAS) powered by Large Language Models (LLMs) designed to bridge the "translation gap" in software development. It automates the complex process of translating high-level business requirements into detailed, security-compliant technical specifications. By leveraging a fleet of specialized AI agents, the system simulates a team of security experts—including threat modelers, compliance officers, and security architects—to analyze input requirements, identify risks using the STRIDE methodology, and map actionable security controls from industry standards.

The goal of this project is to enable "Shift Left" security by making rigorous Security Requirements Engineering (SRE) faster, consistent, and accessible to development teams without deep security expertise.

## 🏗️ System Architecture

The system utilizes **CrewAI** for agent orchestration and **Weaviate** for Retrieval-Augmented Generation (RAG). It operates via a four-stage pipeline:

1. **Requirements Analysis:** Extraction of architectural components and system boundaries.

2. **Parallel Security Analysis:** Concurrent execution of Threat Modeling (STRIDE), Stakeholder Analysis, and Compliance checking.

3. **Synthesis & Planning:** Aggregation of findings into a unified security architecture and implementation roadmap.

4. **Validation:** Self-correction loops to ensure quality and completeness.

![Multi-Agent System Flow Diagram](thesis-results-analysis/flow-diagram.png "Multi-Agent System Flow Diagram")
*Figure 1: The Multi-Agent System Architecture featuring ten specialized agents.*

### Key Features

* **Automated Threat Modeling:** Systematically identifies threats using the STRIDE methodology.

* **Standards Compliance:** Uses RAG to map requirements to **OWASP ASVS**, **NIST SP 800-53**, and **ISO 27001**.

* **Traceability:** Generates a full traceability matrix linking Business Requirement $\to$ Threat $\to$ Security Control $\to$ Verification Test.

* **Iterative Quality Assurance:** Includes a Validation Agent that critiques and refines the output before final generation.

## 🚀 Getting Started

Follow these instructions to clone the project and run the analysis on your local machine using **uv** for fast dependency management.

### Prerequisites

* **Python 3.12+**

* **uv** (High-performance Python package manager)

* **Docker** (for running the local Weaviate vector database)

* **OpenAI API Key** (or compatible LLM API key)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/SavvasMohito/msc-thesis-code.git
   cd msc-thesis-code
   ```

2. **Set up the Virtual Environment**
   Initialize a virtual environment using `uv`. By default, this creates a `.venv` directory.

   ```bash
   uv venv
   ```

3. **Install Dependencies**
   Use `uv` to install the required packages efficiently.

   ```bash
   uv sync
   ```

4. **Configure Environment Variables**
   Create a `.env` file in the root directory and add your keys, just like the `.env.template` file:

   ```bash
   cp .env.template .env
   ```

5. **Start the Knowledge Base (Weaviate)**
   Use Docker to spin up the vector database which houses the security standards (NIST, ISO, OWASP).

   ```bash
   docker-compose up -d
   ```

6. **Import Security Controls to Weaviate**
   After starting the vector database, you need to embed and instert the security controls.

   ```bash
   uv run src/security_requirements_system/tools/weaviate_setup.py
   ```

## 💻 Usage

1. **Prepare your Input:**
   Place your high-level requirements document (MD format) in the `generations/{GENERATION-NAME}/{GENERATION-NAME.md}` folder, similar to the other generation directories.

2. **Set your generation name in .env:**
   For example, if you made a `test.md` under `generations/test/test.md`, then set `PARTICIPANT_NAME=test` in the `.env file.

3. **Run the System (~15 mins):**

   ```bash
   uv run src/security_requirements_system/main.py
   ```

4. **View Results:**
   The system will generate a comprehensive report in the `generations/{GENERATION-NAME}/outputs/` directory, including:

   * `{GENERATION-NAME}_security_report_{DATETIME}.qmd`
   * A `crews` directory with the raw results of each agent.

5. **Render the final HTML report:**
   Browse in your `outputs` folder and use the generated qmd file to render the report in HTML format.

   ```bash
   cd generations/{GENERATION-NAME}/outputs
   quarto render {YOUR-QMD-FILE.qmd} --to html --output-dir .
   ```

> **\[Placeholder: Insert Figure 5.2 from Thesis here - Example Mermaid Diagram\]**
> *Figure 2: Example of an automatically generated architectural diagram based on input requirements.*

## 📄 License

This project is licensed under the **MIT License**. This means you are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, provided that the original copyright notice is included. See the [LICENSE](LICENSE) file for details.

## 📚 Citation

If you use this code or methodology in your research, please cite the Master's Thesis:

```bibtex
@mastersthesis{mantzouranidis2026massre,
  title={A Multi-Agent Approach for a Security-Aware Translation of Software Business Requirements},
  author={Mantzouranidis, Savvas},
  school={Blekinge Institute of Technology},
  year={2026},
  month={01},
  type = {Master's thesis}
}
