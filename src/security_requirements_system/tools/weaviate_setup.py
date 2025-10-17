"""Weaviate schema setup and data ingestion utilities."""

import json
import os
from pathlib import Path

import weaviate
import weaviate.classes as wvc
from dotenv import load_dotenv

load_dotenv()


def setup_weaviate_schema():
    """Initialize Weaviate schema for security controls."""
    client = weaviate.connect_to_local(
        host=os.getenv("WEAVIATE_HOST", "localhost"),
        port=int(os.getenv("WEAVIATE_PORT", "8080")),
        grpc_port=int(os.getenv("WEAVIATE_GRPC_PORT", "50051")),
    )

    try:
        # Delete collection if it exists
        if client.collections.exists("SecurityControl"):
            client.collections.delete("SecurityControl")
            print("Deleted existing SecurityControl collection")

        # Create collection with schema
        client.collections.create(
            name="SecurityControl",
            vectorizer_config=wvc.config.Configure.Vectorizer.text2vec_openai(model="text-embedding-3-small"),
            properties=[
                wvc.config.Property(
                    name="standard",
                    data_type=wvc.config.DataType.TEXT,
                    description="The security standard (e.g., OWASP, NIST, ISO27001)",
                ),
                wvc.config.Property(
                    name="req_id",
                    data_type=wvc.config.DataType.TEXT,
                    description="Unique requirement identifier",
                ),
                wvc.config.Property(
                    name="req_description",
                    data_type=wvc.config.DataType.TEXT,
                    description="Detailed description of the requirement",
                ),
                wvc.config.Property(
                    name="chapter_id",
                    data_type=wvc.config.DataType.TEXT,
                    description="Chapter identifier (e.g., V1)",
                ),
                wvc.config.Property(
                    name="chapter_name",
                    data_type=wvc.config.DataType.TEXT,
                    description="Chapter name/title",
                ),
                wvc.config.Property(
                    name="section_id",
                    data_type=wvc.config.DataType.TEXT,
                    description="Section identifier (e.g., V1.1)",
                ),
                wvc.config.Property(
                    name="section_name",
                    data_type=wvc.config.DataType.TEXT,
                    description="Section name/title",
                ),
                wvc.config.Property(
                    name="level",
                    data_type=wvc.config.DataType.TEXT,
                    description="Requirement level (e.g., L1, L2, L3)",
                ),
                wvc.config.Property(
                    name="full_text",
                    data_type=wvc.config.DataType.TEXT,
                    description="Complete text for vectorization",
                ),
            ],
        )

        print("SecurityControl collection created successfully")

    finally:
        client.close()


def ingest_security_standards(data_dir: str = "src/security_requirements_system/data/prepared"):
    """Ingest security standards from JSON files into Weaviate."""
    client = weaviate.connect_to_local(
        host=os.getenv("WEAVIATE_HOST", "localhost"),
        port=int(os.getenv("WEAVIATE_PORT", "8080")),
        grpc_port=int(os.getenv("WEAVIATE_GRPC_PORT", "50051")),
    )

    try:
        collection = client.collections.get("SecurityControl")

        # Find all JSON files in the prepared data directory
        data_path = Path(data_dir)
        json_files = list(data_path.glob("*.json"))

        if not json_files:
            print(f"No JSON files found in {data_dir}")
            return

        total_imported = 0

        for json_file in json_files:
            print(f"Processing {json_file.name}...")

            with open(json_file, "r", encoding="utf-8") as f:
                controls = json.load(f)

            # Prepare batch import
            objects_to_insert = []
            for control in controls:
                # Combine fields for better vectorization
                full_text = (
                    f"{control.get('chapter_name', '')} "
                    f"{control.get('section_name', '')} "
                    f"{control.get('req_id', '')}: "
                    f"{control.get('req_description', '')}"
                )

                obj = {
                    "standard": control.get("standard", "Unknown"),
                    "req_id": control.get("req_id", ""),
                    "req_description": control.get("req_description", ""),
                    "chapter_id": control.get("chapter_id", ""),
                    "chapter_name": control.get("chapter_name", ""),
                    "section_id": control.get("section_id", ""),
                    "section_name": control.get("section_name", ""),
                    "level": control.get("level", ""),
                    "full_text": full_text,
                }
                objects_to_insert.append(obj)

            # Batch insert
            if objects_to_insert:
                collection.data.insert_many(objects_to_insert)
                total_imported += len(objects_to_insert)
                print(f"  Imported {len(objects_to_insert)} controls from {json_file.name}")

        print(f"\nTotal controls imported: {total_imported}")

    finally:
        client.close()


if __name__ == "__main__":
    print("Setting up Weaviate schema...")
    setup_weaviate_schema()

    print("\nIngesting security standards data...")
    ingest_security_standards()
