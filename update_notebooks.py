"""
Notebook updater for the Endpoint–Artifact Forensic Analysis project.

Purpose
-------
This script creates updated copies of the project's Jupyter notebooks.

The original notebooks are never overwritten. The generated notebooks use
the "_updated" suffix so that the existing working versions remain available
for comparison and rollback.

The update adds explicit malicious-security evidence to the existing
Endpoint -> Artifact graph model.

Graph relationship model after the update:

    (:Endpoint)-[:OBSERVED {
        record_count,
        first_event,
        last_event,
        malicious_detected,
        malicious_detection_count,
        malicious_file_names,
        first_malicious_detection,
        last_malicious_detection,
        first_quarantine_time,
        last_quarantine_time
    }]->(:Artifact)

Important
---------
The script modifies notebook source code only. It does not execute any
notebook cells and therefore does not modify Neo4j by itself.
"""

from pathlib import Path
import copy
import json
import uuid


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

# Resolve the project root from the location of this script.
# This avoids hard-coded machine-specific paths such as /mnt/data.
PROJECT_ROOT = Path(__file__).resolve().parent

# All source and generated notebooks live in the project's notebook folder.
NOTEBOOK_DIR = PROJECT_ROOT / "notebook"

# Updated notebooks are written beside the original notebooks.
OUTPUT_DIR = NOTEBOOK_DIR


# ---------------------------------------------------------------------------
# Source notebook paths
# ---------------------------------------------------------------------------

# These filenames match the notebooks currently present in the local project.
PROFILING_PATH = NOTEBOOK_DIR / "01_data_profiling.ipynb"
ARTIFACT_PATH = NOTEBOOK_DIR / "artifact_level_table.ipynb"
NEO4J_PATH = NOTEBOOK_DIR / "03_neo4j_import.ipynb"
INVESTIGATION_PATH = NOTEBOOK_DIR / "04_investigation.ipynb"


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def read_notebook(path):
    """
    Load a Jupyter notebook from disk.

    A clear error is raised if the expected notebook does not exist so that
    the user does not accidentally generate incomplete notebooks.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"\nNotebook not found:\n{path}\n\n"
            f"Expected project structure:\n"
            f"{NOTEBOOK_DIR}\\\n"
            f"    01_data_profiling.ipynb\n"
            f"    artifact_level_table.ipynb\n"
            f"    03_neo4j_import.ipynb\n"
            f"    04_investigation.ipynb\n"
        )

    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_notebook(notebook, filename):
    """
    Write an updated notebook to the project notebook directory.

    The filename is supplied separately so that callers cannot accidentally
    write over the original notebook.
    """
    output_path = OUTPUT_DIR / filename

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(
            notebook,
            handle,
            indent=1,
            ensure_ascii=False
        )

    return output_path


def source_text(cell):
    """
    Return a notebook cell's source as one string.

    Jupyter stores source code as a list of strings, so normalizing it here
    makes the cell-search logic easier to read and maintain.
    """
    source = cell.get("source", [])

    if isinstance(source, list):
        return "".join(source)

    return str(source)


def set_source(cell, source):
    """
    Replace a notebook cell's source while preserving the cell metadata.

    Outputs are cleared because the source code has changed and previous
    execution results may no longer represent the current code.
    """
    cell["source"] = source.splitlines(keepends=True)

    if cell.get("cell_type") == "code":
        cell["outputs"] = []
        cell["execution_count"] = None


def create_markdown_cell(source):
    """
    Create a new Markdown notebook cell with a unique cell ID.
    """
    return {
        "cell_type": "markdown",
        "id": uuid.uuid4().hex[:8],
        "metadata": {},
        "source": source.splitlines(keepends=True),
    }


def create_code_cell(source):
    """
    Create a new code notebook cell with a unique cell ID.

    New cells start without execution output because the updater only changes
    notebook source and does not execute the notebook.
    """
    return {
        "cell_type": "code",
        "execution_count": None,
        "id": uuid.uuid4().hex[:8],
        "metadata": {},
        "outputs": [],
        "source": source.splitlines(keepends=True),
    }


def find_cell(notebook, marker, description):
    """
    Locate exactly one notebook cell containing the requested marker.

    Requiring exactly one match prevents accidental modification of an
    unrelated duplicate or experimental cell.
    """
    matches = []

    for index, cell in enumerate(notebook.get("cells", [])):
        if marker in source_text(cell):
            matches.append((index, cell))

    if len(matches) == 0:
        raise RuntimeError(
            f"Could not find the expected section in the notebook.\n"
            f"Notebook section: {description}\n"
            f"Search marker: {marker!r}"
        )

    if len(matches) > 1:
        raise RuntimeError(
            f"Found multiple matching cells for the expected section.\n"
            f"Notebook section: {description}\n"
            f"Search marker: {marker!r}\n"
            f"Matching cell indexes: {[index for index, _ in matches]}"
        )

    return matches[0]


def append_cells(notebook, cells):
    """
    Append new cells to the notebook in the supplied order.
    """
    notebook.setdefault("cells", []).extend(cells)


# ---------------------------------------------------------------------------
# 01 - Data profiling notebook
# ---------------------------------------------------------------------------

def update_profiling_notebook(notebook):
    """
    Add a focused malicious-telemetry profiling section.

    The original profiling workflow is preserved. This section provides a
    reproducible count and sample of records explicitly classified by the
    endpoint-security telemetry as malicious.
    """
    markdown = create_markdown_cell(
        """
## Malicious Security Telemetry

The endpoint-security dataset contains explicit security detections marked
`FileType: Malicious`. This section profiles those records before they are
represented in the endpoint–artifact graph.

This is detection evidence from the source telemetry. It should not by itself
be interpreted as proof that an endpoint was compromised or that a malicious
artifact was executed.
"""
    )

    code = create_code_cell(
        '''
# Load the endpoint-security source data independently so this profiling
# section remains reproducible even if earlier notebook cells are reordered.
from pathlib import Path
import pandas as pd

project_root = Path.cwd().parent
security_path = project_root / "data" / "endpoint_security.csv"

security_df = pd.read_csv(security_path)

# Restrict the analysis to records explicitly classified as malicious by the
# source security telemetry rather than inferring maliciousness from filenames.
malicious_security_df = security_df[
    security_df["message"]
    .fillna("")
    .str.contains(
        "FileType: Malicious",
        case=False,
        na=False
    )
].copy()

print(f"Security records: {len(security_df):,}")
print(f"Explicit malicious records: {len(malicious_security_df):,}")
print(
    "Endpoints with explicit malicious telemetry:",
    malicious_security_df["endpoint_id"].nunique()
)

display(
    malicious_security_df[
        [
            "endpoint_id",
            "event_time",
            "message"
        ]
    ].head(10)
)
'''
    )

    append_cells(notebook, [markdown, code])

    return notebook


# ---------------------------------------------------------------------------
# Artifact-level table notebook
# ---------------------------------------------------------------------------

def update_artifact_notebook(notebook):
    """
    Replace the endpoint-artifact aggregation with an enriched version.

    The current project methodology already scopes this notebook to records
    containing `FileType: Malicious`. We preserve that methodology and add
    explicit malicious-detection metadata to each endpoint-artifact edge.
    """
    marker = "endpoint_artifact_edges = ("

    index, cell = find_cell(
        notebook,
        marker,
        "endpoint-artifact relationship aggregation"
    )

    new_source = '''
# Group malicious security observations by endpoint and SHA256.
#
# The current notebook scope contains only records explicitly marked
# `FileType: Malicious`, so each generated endpoint-artifact relationship
# represents source telemetry with an explicit malicious classification.
endpoint_artifact_edges = (
    scope
    .groupby(
        ["endpoint_id", "sha256"],
        as_index=False
    )
    .agg(
        file_names=(
            "file_name",
            lambda values: sorted(set(values.dropna()))
        ),
        record_count=(
            "sha256",
            "size"
        ),
        first_event=(
            "event_time",
            "min"
        ),
        last_event=(
            "event_time",
            "max"
        ),
        malicious_detection_count=(
            "sha256",
            "size"
        ),
        malicious_file_names=(
            "file_name",
            lambda values: sorted(set(values.dropna()))
        ),
        first_malicious_detection=(
            "event_time",
            "min"
        ),
        last_malicious_detection=(
            "event_time",
            "max"
        ),
    )
)

# Mark the relationship as malicious only because the source scope was
# explicitly restricted to `FileType: Malicious` records.
endpoint_artifact_edges["malicious_detected"] = True

# Extract the quarantine timestamp from the security message where available.
# Missing or malformed values are represented as NaT rather than invented.
scope["quarantined_at"] = pd.to_datetime(
    scope["message"]
    .fillna("")
    .str.extract(
        r"Quarantined At:\\s*([^|]+)",
        expand=False
    ),
    errors="coerce"
)

# Calculate endpoint-artifact-specific quarantine timing.
quarantine_summary = (
    scope
    .groupby(
        ["endpoint_id", "sha256"],
        as_index=False
    )
    .agg(
        first_quarantine_time=(
            "quarantined_at",
            "min"
        ),
        last_quarantine_time=(
            "quarantined_at",
            "max"
        )
    )
)

# Add quarantine information without changing the number of graph edges.
endpoint_artifact_edges = endpoint_artifact_edges.merge(
    quarantine_summary,
    on=["endpoint_id", "sha256"],
    how="left"
)

# Store the number of distinct filenames associated with each edge.
endpoint_artifact_edges["file_name_count"] = (
    endpoint_artifact_edges["file_names"].apply(len)
)

# Confirm the enriched relationship table before exporting it.
print(
    "Endpoint-artifact edges:",
    len(endpoint_artifact_edges)
)

print(
    "Malicious relationships:",
    endpoint_artifact_edges["malicious_detected"].sum()
)

display(endpoint_artifact_edges.head())
'''

    set_source(cell, new_source)

    # Add a validation section after the existing aggregation/export logic.
    validation_markdown = create_markdown_cell(
        """
## Malicious Evidence Validation

Each endpoint–artifact edge generated by this notebook is backed by a source
security observation explicitly containing `FileType: Malicious`.

The graph stores this evidence on the `OBSERVED` relationship because the
security classification belongs to the endpoint-specific observation context,
not globally to the SHA256 artifact.
"""
    )

    validation_code = create_code_cell(
        '''
# Verify that every generated edge contains the malicious-evidence fields
# required by the Neo4j relationship model.
required_columns = [
    "endpoint_id",
    "sha256",
    "malicious_detected",
    "malicious_detection_count",
    "malicious_file_names",
    "first_malicious_detection",
    "last_malicious_detection",
    "first_quarantine_time",
    "last_quarantine_time",
]

missing_columns = [
    column
    for column in required_columns
    if column not in endpoint_artifact_edges.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required malicious-evidence columns: {missing_columns}"
    )

print("Malicious evidence schema validation passed.")
'''
    )

    append_cells(
        notebook,
        [
            validation_markdown,
            validation_code
        ]
    )

    return notebook


# ---------------------------------------------------------------------------
# 03 - Neo4j import notebook
# ---------------------------------------------------------------------------

def update_neo4j_notebook(notebook):
    """
    Replace the OBSERVED relationship import with the enriched model.

    Endpoint and Artifact nodes remain unchanged. Malicious evidence is
    stored on the endpoint-specific OBSERVED relationship.
    """
    marker = "MERGE (e)-[r:OBSERVED]->(a)"

    index, cell = find_cell(
        notebook,
        marker,
        "Neo4j OBSERVED relationship import"
    )

    new_source = '''
# Convert the validated edge table into Python dictionaries for parameterized
# Neo4j import.
edge_records = endpoint_artifact_edges.to_dict("records")


def split_pipe_list(value):
    """
    Convert pipe-delimited CSV values back into Python lists.

    This is required because CSV serialization converts list-valued fields
    into strings before they are reloaded by pandas.
    """
    if pd.isna(value):
        return []

    value = str(value).strip()

    if not value:
        return []

    return [
        item.strip()
        for item in value.split("|")
        if item.strip()
    ]


# Restore list-valued fields before sending records to Neo4j.
for column in [
    "file_names",
    "malicious_file_names",
]:
    if column in endpoint_artifact_edges.columns:
        endpoint_artifact_edges[column] = (
            endpoint_artifact_edges[column]
            .apply(split_pipe_list)
        )


# Convert pandas missing values to Python None so Neo4j can represent them
# as absent properties instead of receiving pandas-specific NaN/NaT objects.
for column in [
    "first_quarantine_time",
    "last_quarantine_time",
]:
    if column in endpoint_artifact_edges.columns:
        endpoint_artifact_edges[column] = (
            endpoint_artifact_edges[column]
            .where(
                endpoint_artifact_edges[column].notna(),
                None
            )
        )


edge_records = endpoint_artifact_edges.to_dict("records")


query = """
UNWIND $edges AS row

MATCH (e:Endpoint {endpoint_id: row.endpoint_id})
MATCH (a:Artifact {sha256: row.sha256})

MERGE (e)-[r:OBSERVED]->(a)

SET
    r.record_count = row.record_count,
    r.first_event = row.first_event,
    r.last_event = row.last_event,

    // Security classification is stored on the endpoint-specific
    // observation relationship rather than globally on the artifact.
    r.malicious_detected = row.malicious_detected,
    r.malicious_detection_count = row.malicious_detection_count,
    r.malicious_file_names = row.malicious_file_names,
    r.first_malicious_detection = row.first_malicious_detection,
    r.last_malicious_detection = row.last_malicious_detection,
    r.first_quarantine_time = row.first_quarantine_time,
    r.last_quarantine_time = row.last_quarantine_time
"""

driver.execute_query(
    query,
    edges=edge_records,
    database_=DATABASE
)

print("OBSERVED relationships imported with malicious evidence.")
'''

    set_source(cell, new_source)

    # Add a post-import verification section.
    markdown = create_markdown_cell(
        """
## Malicious Evidence Graph Validation

The following query verifies that malicious detection metadata was stored on
the endpoint-specific `OBSERVED` relationships.
"""
    )

    code = create_code_cell(
        '''
# Verify that the graph contains endpoint-artifact relationships carrying
# explicit malicious security evidence.
result = driver.execute_query(
    """
    MATCH (e:Endpoint)-[r:OBSERVED]->(a:Artifact)
    WHERE r.malicious_detected = true

    RETURN
        e.endpoint_id AS endpoint,
        a.sha256 AS sha256,
        a.file_names AS file_names,
        r.malicious_detection_count AS detection_count,
        r.malicious_file_names AS malicious_file_names,
        r.first_malicious_detection AS first_detection,
        r.last_malicious_detection AS last_detection,
        r.first_quarantine_time AS first_quarantine,
        r.last_quarantine_time AS last_quarantine

    ORDER BY r.first_malicious_detection
    """,
    database_=DATABASE
)

malicious_graph_df = pd.DataFrame(
    [dict(record) for record in result.records]
)

print(
    "Graph relationships with explicit malicious evidence:",
    len(malicious_graph_df)
)

display(malicious_graph_df.head(20))
'''
    )

    append_cells(notebook, [markdown, code])

    return notebook


# ---------------------------------------------------------------------------
# 04 - Investigation notebook
# ---------------------------------------------------------------------------

def update_investigation_notebook(notebook):
    """
    Add focused investigation queries for malicious endpoint-artifact
    relationships.

    Existing investigation functions and queries are preserved. The new
    section provides explicit security-evidence queries that can later feed
    the dashboard.
    """
    markdown = create_markdown_cell(
        """
# Malicious Evidence Investigation

This section separates explicit security detections from heuristic activity
indicators.

`malicious_detected = true` means the source endpoint-security telemetry
explicitly classified the observation as malicious.

It does **not** by itself prove execution, persistence, lateral movement, or
complete endpoint compromise.
"""
    )

    code = create_code_cell(
        '''
# Retrieve endpoint-artifact relationships with explicit malicious evidence.
malicious_result = driver.execute_query(
    """
    MATCH (e:Endpoint)-[r:OBSERVED]->(a:Artifact)
    WHERE r.malicious_detected = true

    RETURN
        e.endpoint_id AS endpoint,
        a.sha256 AS sha256,
        a.file_names AS file_names,
        r.record_count AS record_count,
        r.malicious_detection_count AS detection_count,
        r.malicious_file_names AS malicious_file_names,
        r.first_malicious_detection AS first_detection,
        r.last_malicious_detection AS last_detection,
        r.first_quarantine_time AS first_quarantine,
        r.last_quarantine_time AS last_quarantine

    ORDER BY r.first_malicious_detection
    """,
    database_=DATABASE
)

malicious_evidence = pd.DataFrame(
    [dict(record) for record in malicious_result.records]
)

display(malicious_evidence)
'''
    )

    endpoint_summary_code = create_code_cell(
        '''
# Summarize explicit malicious detections by endpoint.
endpoint_malicious_result = driver.execute_query(
    """
    MATCH (e:Endpoint)-[r:OBSERVED]->(a:Artifact)
    WHERE r.malicious_detected = true

    RETURN
        e.endpoint_id AS endpoint,
        count(DISTINCT a) AS malicious_artifacts,
        sum(r.malicious_detection_count) AS malicious_detections,
        min(r.first_malicious_detection) AS first_malicious_detection,
        max(r.last_malicious_detection) AS last_malicious_detection,
        min(r.first_quarantine_time) AS first_quarantine_time,
        max(r.last_quarantine_time) AS last_quarantine_time

    ORDER BY malicious_artifacts DESC
    """,
    database_=DATABASE
)

endpoint_malicious_summary = pd.DataFrame(
    [dict(record) for record in endpoint_malicious_result.records]
)

display(endpoint_malicious_summary)
'''
    )

    targeted_code = create_code_cell(
        '''
# Investigate the endpoint that previously showed the highest artifact
# concentration while keeping malicious evidence explicitly visible.
target_endpoint = "EP4YIFHV"

targeted_result = driver.execute_query(
    """
    MATCH (e:Endpoint {endpoint_id: $endpoint_id})
          -[r:OBSERVED]->
          (a:Artifact)

    RETURN
        e.endpoint_id AS endpoint,
        a.sha256 AS sha256,
        a.file_names AS file_names,
        r.record_count AS record_count,
        r.malicious_detected AS malicious_detected,
        r.malicious_detection_count AS detection_count,
        r.malicious_file_names AS malicious_file_names,
        r.first_event AS first_event,
        r.last_event AS last_event,
        r.first_malicious_detection AS first_malicious_detection,
        r.last_malicious_detection AS last_malicious_detection,
        r.first_quarantine_time AS first_quarantine_time,
        r.last_quarantine_time AS last_quarantine_time

    ORDER BY r.first_event
    """,
    endpoint_id=target_endpoint,
    database_=DATABASE
)

targeted_evidence = pd.DataFrame(
    [dict(record) for record in targeted_result.records]
)

display(targeted_evidence)
'''
    )

    append_cells(
        notebook,
        [
            markdown,
            code,
            endpoint_summary_code,
            targeted_code
        ]
    )

    return notebook


# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

def main():
    """
    Load the four source notebooks, apply the updates, and write four
    separate updated notebook files.
    """
    print("=" * 70)
    print("Endpoint–Artifact Forensic Notebook Updater")
    print("=" * 70)

    print(f"\nProject root:")
    print(f"  {PROJECT_ROOT}")

    print(f"\nNotebook directory:")
    print(f"  {NOTEBOOK_DIR}")

    # Confirm that all required source notebooks exist before modifying
    # anything. This prevents a partially generated notebook set.
    source_paths = [
        PROFILING_PATH,
        ARTIFACT_PATH,
        NEO4J_PATH,
        INVESTIGATION_PATH,
    ]

    print("\nChecking source notebooks...")

    for path in source_paths:
        if not path.exists():
            raise FileNotFoundError(
                f"\nRequired notebook does not exist:\n{path}"
            )

        print(f"  OK: {path.name}")

    # Load each original notebook independently.
    print("\nLoading notebooks...")

    profiling = read_notebook(PROFILING_PATH)
    artifact = read_notebook(ARTIFACT_PATH)
    neo4j = read_notebook(NEO4J_PATH)
    investigation = read_notebook(INVESTIGATION_PATH)

    print("  All notebooks loaded successfully.")

    # Work on deep copies so the in-memory source objects remain independent
    # and the original files are never modified.
    profiling_updated = copy.deepcopy(profiling)
    artifact_updated = copy.deepcopy(artifact)
    neo4j_updated = copy.deepcopy(neo4j)
    investigation_updated = copy.deepcopy(investigation)

    print("\nApplying notebook updates...")

    # Update each notebook according to its specific responsibility.
    update_profiling_notebook(profiling_updated)
    print("  OK: 01_data_profiling")

    update_artifact_notebook(artifact_updated)
    print("  OK: artifact_level_table")

    update_neo4j_notebook(neo4j_updated)
    print("  OK: 03_neo4j_import")

    update_investigation_notebook(investigation_updated)
    print("  OK: 04_investigation")

    # Write separate output files rather than overwriting the originals.
    output_files = [
        write_notebook(
            profiling_updated,
            "01_data_profiling_updated.ipynb"
        ),
        write_notebook(
            artifact_updated,
            "artifact_level_table_updated.ipynb"
        ),
        write_notebook(
            neo4j_updated,
            "03_neo4j_import_updated.ipynb"
        ),
        write_notebook(
            investigation_updated,
            "04_investigation_updated.ipynb"
        ),
    ]

    print("\n" + "=" * 70)
    print("Updated notebooks created successfully.")
    print("=" * 70)

    for path in output_files:
        print(f"\n{path}")

    print("\nThe original notebooks were not overwritten.")
    print("The updated notebooks have NOT been executed.")


if __name__ == "__main__":
    main()