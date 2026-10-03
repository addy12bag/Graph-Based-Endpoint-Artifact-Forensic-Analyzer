# ============================================================
# Endpoint–Artifact Forensic Analyzer
# Optimized Streamlit dashboard for forensic investigation
# ============================================================

import streamlit as st
import pandas as pd
import plotly.express as px
from neo4j import GraphDatabase


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Endpoint–Artifact Forensic Analyzer",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
DATABASE = "indianarmygraph"


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    /* Reduce unnecessary whitespace and keep the dashboard compact. */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    /* Keep metric cards compact and readable. */
    [data-testid="stMetric"] {
        padding: 0.25rem 0;
    }

    [data-testid="stMetricLabel"] {
        font-size: 0.85rem;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.65rem;
    }

    /* Reduce excessive spacing around headings. */
    h1 {
        margin-bottom: 0.15rem;
    }

    h2 {
        margin-top: 0.5rem;
        margin-bottom: 0.5rem;
    }

    h3 {
        margin-top: 0.25rem;
        margin-bottom: 0.4rem;
    }

    /* Keep dataframe components visually compact. */
    [data-testid="stDataFrame"] {
        border-radius: 6px;
    }

    /* Keep horizontal separators subtle. */
    hr {
        margin: 1.25rem 0;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# NEO4J CONNECTION
# ============================================================

@st.cache_resource
def get_driver():
    """
    Create and cache the Neo4j driver.

    Caching prevents Streamlit from opening a new database connection
    every time the user changes the selected endpoint.
    """

    password = st.secrets["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(
        URI,
        auth=(USERNAME, password),
    )

    # Verify connectivity when the driver is initialized.
    driver.verify_connectivity()

    return driver


def run_query(query, parameters=None):
    """
    Execute a Cypher query and return Neo4j records as dictionaries.

    Keeping database execution in one function makes the dashboard
    queries easier to maintain and keeps the UI independent of the
    Neo4j driver implementation.
    """

    driver = get_driver()

    result = driver.execute_query(
        query,
        parameters or {},
        database_=DATABASE,
    )

    return [dict(record) for record in result.records]


# ============================================================
# TEMPORAL VALUE HELPERS
# ============================================================

def parse_datetime(value):
    """
    Convert Neo4j temporal values into pandas timestamps.

    Converting through str() first ensures Neo4j temporal objects are
    handled consistently by pandas.
    """

    if value is None:
        return pd.NaT

    try:
        return pd.to_datetime(
            str(value),
            errors="coerce",
        )
    except Exception:
        return pd.NaT

def format_datetime(value):
    """
    Format Neo4j timestamps while preserving sub-second forensic precision.

    Trailing zeroes are removed so timestamps remain readable without
    discarding meaningful milliseconds or microseconds.
    """

    timestamp = parse_datetime(value)

    if pd.isna(timestamp):
        return "N/A"

    # Keep microsecond precision when it exists in the source timestamp.
    formatted = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Remove insignificant trailing zeroes while preserving real precision.
    formatted = formatted.rstrip("0").rstrip(".")

    return formatted


def format_duration(start, end):
    """
    Calculate and format the elapsed time between two observations.
    """

    start_time = parse_datetime(start)
    end_time = parse_datetime(end)

    if pd.isna(start_time) or pd.isna(end_time):
        return "N/A"

    duration = end_time - start_time

    # Microseconds add unnecessary visual noise to the investigation view.
    return str(duration).split(".")[0]


def shorten_sha256(value):
    """
    Shorten SHA256 values for compact dashboard tables while retaining
    enough characters for visual identification.
    """

    if not value:
        return ""

    value = str(value)

    if len(value) <= 20:
        return value

    return f"{value[:12]}...{value[-8:]}"


def format_file_names(value):
    """
    Convert Neo4j filename lists into compact readable text.
    """

    if value is None:
        return ""

    if isinstance(value, list):
        return ", ".join(str(item) for item in value)

    return str(value)


# ============================================================
# GRAPH-WIDE METRICS
# ============================================================

@st.cache_data(ttl=30)
def get_graph_metrics():
    """
    Calculate graph-wide structural and security metrics.

    Independent subqueries prevent Cypher variable-scope problems
    while keeping all graph metrics in one database request.
    """

    query = """
    CALL {
        MATCH (e:Endpoint)
        RETURN count(e) AS endpoint_count
    }

    CALL {
        MATCH (e:Endpoint)-[:OBSERVED]->(:Artifact)
        RETURN count(DISTINCT e) AS connected_endpoint_count
    }

    CALL {
        MATCH (a:Artifact)
        RETURN count(a) AS artifact_count
    }

    CALL {
        MATCH ()-[r:OBSERVED]->()
        RETURN count(r) AS observed_relationship_count
    }

    CALL {
        MATCH (e:Endpoint)-[r:OBSERVED]->(:Artifact)
        WHERE r.malicious_detected = true
        RETURN count(DISTINCT e) AS malicious_endpoint_count
    }

    CALL {
        MATCH (:Endpoint)-[r:OBSERVED]->(a:Artifact)
        WHERE r.malicious_detected = true
        RETURN count(DISTINCT a) AS malicious_artifact_count
    }

    CALL {
        MATCH ()-[r:OBSERVED]->()
        WHERE r.malicious_detected = true
        RETURN count(r) AS malicious_relationship_count
    }

    RETURN
        endpoint_count,
        connected_endpoint_count,
        artifact_count,
        observed_relationship_count,
        malicious_endpoint_count,
        malicious_artifact_count,
        malicious_relationship_count
    """

    records = run_query(query)

    if not records:
        return {
            "endpoint_count": 0,
            "connected_endpoint_count": 0,
            "artifact_count": 0,
            "observed_relationship_count": 0,
            "malicious_endpoint_count": 0,
            "malicious_artifact_count": 0,
            "malicious_relationship_count": 0,
        }

    return records[0]


# ============================================================
# ENDPOINT LIST
# ============================================================

@st.cache_data(ttl=30)
def get_endpoints():
    """
    Return endpoint-level artifact and malicious-evidence counts.

    Endpoints with malicious evidence appear first, followed by other
    connected endpoints and finally endpoints without artifact evidence.
    """

    query = """
    MATCH (e:Endpoint)

    OPTIONAL MATCH (e)-[r:OBSERVED]->(a:Artifact)

    WITH
        e.endpoint_id AS endpoint,
        count(DISTINCT a) AS artifact_count,
        count(
            DISTINCT CASE
                WHEN r.malicious_detected = true
                THEN a
            END
        ) AS malicious_artifact_count

    RETURN
        endpoint,
        artifact_count,
        malicious_artifact_count

    ORDER BY
        CASE
            WHEN endpoint = "EPVSWBNA" THEN 0
            WHEN malicious_artifact_count > 0 THEN 1
            WHEN artifact_count > 0 THEN 2
            ELSE 3
        END,
        artifact_count DESC,
        endpoint
    """

    return run_query(query)


# ============================================================
# ENDPOINT SUMMARY
# ============================================================

def get_endpoint_summary(endpoint_id):
    """
    Return the high-level forensic summary for a selected endpoint.
    """

    query = """
    MATCH (e:Endpoint {endpoint_id: $endpoint_id})
          -[r:OBSERVED]->
          (a:Artifact)

    RETURN
        e.endpoint_id AS endpoint,
        count(DISTINCT a) AS unique_artifacts,
        sum(r.record_count) AS total_observations,

        count(
            DISTINCT CASE
                WHEN r.malicious_detected = true
                THEN a
            END
        ) AS malicious_artifacts,

        sum(
            CASE
                WHEN r.malicious_detected = true
                THEN r.malicious_detection_count
                ELSE 0
            END
        ) AS malicious_detections,

        min(r.first_event) AS first_observation,
        max(r.last_event) AS last_observation
    """

    records = run_query(
        query,
        {"endpoint_id": endpoint_id},
    )

    if not records:
        return None

    return records[0]


# ============================================================
# ENDPOINT ARTIFACT EVIDENCE
# ============================================================

def get_endpoint_artifacts(endpoint_id):
    """
    Retrieve artifact relationships and their security evidence.

    Malicious detection properties remain relationship-level because
    detection state can differ for the same artifact across endpoints.
    """

    query = """
    MATCH (e:Endpoint {endpoint_id: $endpoint_id})
          -[r:OBSERVED]->
          (a:Artifact)

    RETURN
        a.sha256 AS sha256,
        a.file_names AS file_names,
        r.record_count AS record_count,
        r.first_event AS first_event,
        r.last_event AS last_event,

        r.malicious_detected AS malicious_detected,
        r.malicious_detection_count AS malicious_detection_count,
        r.malicious_file_names AS malicious_file_names,

        r.first_malicious_detection AS first_malicious_detection,
        r.last_malicious_detection AS last_malicious_detection,

        r.first_quarantine_time AS first_quarantine_time,
        r.last_quarantine_time AS last_quarantine_time

    ORDER BY
        r.malicious_detected DESC,
        r.first_event
    """

    return run_query(
        query,
        {"endpoint_id": endpoint_id},
    )


# ============================================================
# CROSS-ENDPOINT ARTIFACT CORRELATION
# ============================================================

@st.cache_data(ttl=30)
def get_shared_artifacts():
    """
    Find artifacts observed on more than one endpoint.

    Shared artifacts provide the primary cross-endpoint correlation
    capability of the graph model.
    """

    query = """
    MATCH (e:Endpoint)-[:OBSERVED]->(a:Artifact)

    WITH
        a,
        collect(DISTINCT e.endpoint_id) AS endpoints

    WHERE size(endpoints) > 1

    RETURN
        a.sha256 AS sha256,
        a.file_names AS file_names,
        endpoints,
        size(endpoints) AS endpoint_count

    ORDER BY endpoint_count DESC
    """

    return run_query(query)


# ============================================================
# GRAPH-WIDE ENDPOINT ACTIVITY
# ============================================================

@st.cache_data(ttl=30)
def get_endpoint_activity_overview():
    """
    Return endpoint-level activity statistics for the optional
    graph-wide activity section.
    """

    query = """
    MATCH (e:Endpoint)

    OPTIONAL MATCH (e)-[r:OBSERVED]->(a:Artifact)

    RETURN
        e.endpoint_id AS endpoint,
        count(DISTINCT a) AS unique_artifacts,
        coalesce(sum(r.record_count), 0) AS total_observations,

        count(
            DISTINCT CASE
                WHEN r.malicious_detected = true
                THEN a
            END
        ) AS malicious_artifacts,

        coalesce(
            sum(
                CASE
                    WHEN r.malicious_detected = true
                    THEN r.malicious_detection_count
                    ELSE 0
                END
            ),
            0
        ) AS malicious_detections,

        min(r.first_event) AS first_observation,
        max(r.last_event) AS last_observation

    ORDER BY total_observations DESC
    """

    return run_query(query)


# ============================================================
# HEADER
# ============================================================

st.title("Endpoint–Artifact Forensic Analyzer")

st.caption(
    "Neo4j-based forensic investigation of endpoint–artifact relationships."
)


# ============================================================
# GRAPH OVERVIEW
# ============================================================

metrics = get_graph_metrics()

# Calculate the number of endpoints that are present in telemetry but
# do not currently have an Endpoint-to-Artifact relationship.
unconnected_endpoint_count = (
    metrics["endpoint_count"]
    - metrics["connected_endpoint_count"]
)

# Calculate graph coverage as the percentage of endpoints represented
# by at least one artifact relationship.
artifact_coverage = (
    (
        metrics["connected_endpoint_count"]
        / metrics["endpoint_count"]
        * 100
    )
    if metrics["endpoint_count"] > 0
    else 0
)

st.header("Graph Overview")

# Present structural graph coverage in a compact four-column row.
coverage_col1, coverage_col2, coverage_col3, coverage_col4 = st.columns(4)

with coverage_col1:
    st.metric(
        "Total Endpoints",
        metrics["endpoint_count"],
    )

with coverage_col2:
    st.metric(
        "Connected Endpoints",
        metrics["connected_endpoint_count"],
    )

with coverage_col3:
    st.metric(
        "Artifacts",
        metrics["artifact_count"],
    )

with coverage_col4:
    st.metric(
        "OBSERVED Relationships",
        metrics["observed_relationship_count"],
    )


# Explicitly expose the endpoint population that currently has no
# artifact relationship instead of forcing investigators to calculate it.
coverage_gap_col1, coverage_gap_col2 = st.columns([1, 2])

with coverage_gap_col1:
    st.metric(
        "Endpoints Without Artifacts",
        unconnected_endpoint_count,
    )

with coverage_gap_col2:
    st.write("Artifact Relationship Coverage")

    # The progress bar represents graph coverage, not security status.
    st.progress(
        min(artifact_coverage / 100, 1.0)
    )

    st.caption(
        f"{metrics['connected_endpoint_count']} of "
        f"{metrics['endpoint_count']} endpoints have at least one "
        f"artifact relationship ({artifact_coverage:.1f}% coverage). "
        f"{unconnected_endpoint_count} endpoints currently have no "
        "artifact relationship in the graph."
    )


st.subheader("Security Evidence")

security_col1, security_col2, security_col3 = st.columns(3)

with security_col1:
    st.metric(
        "Malicious Endpoints",
        metrics["malicious_endpoint_count"],
    )

with security_col2:
    st.metric(
        "Malicious Artifacts",
        metrics["malicious_artifact_count"],
    )

with security_col3:
    st.metric(
        "Malicious Relationships",
        metrics["malicious_relationship_count"],
    )


st.divider()


# ============================================================
# ENDPOINT INVESTIGATION
# ============================================================

st.header("Endpoint Investigation")

endpoint_records = get_endpoints()

if not endpoint_records:
    st.warning("No endpoints were found in the Neo4j graph.")
    st.stop()


endpoint_lookup = {
    record["endpoint"]: record
    for record in endpoint_records
}

endpoint_ids = [
    record["endpoint"]
    for record in endpoint_records
]


def format_endpoint(endpoint_id):
    """
    Create a concise endpoint selector label with evidence status.
    """

    record = endpoint_lookup[endpoint_id]

    if record["malicious_artifact_count"] > 0:
        status = "MALICIOUS EVIDENCE"
    elif record["artifact_count"] > 0:
        status = "ARTIFACT EVIDENCE"
    else:
        status = "NO ARTIFACTS"

    return (
        f"{endpoint_id}  •  "
        f"{record['artifact_count']} artifacts  •  "
        f"{status}"
    )


# Prefer the known demonstration endpoint so the dashboard opens on
# a useful forensic case rather than an endpoint with no artifacts.
default_endpoint = (
    "EPVSWBNA"
    if "EPVSWBNA" in endpoint_ids
    else next(
        (
            endpoint
            for endpoint in endpoint_ids
            if endpoint_lookup[endpoint]["artifact_count"] > 0
        ),
        endpoint_ids[0],
    )
)

selected_endpoint = st.selectbox(
    "Endpoint",
    endpoint_ids,
    index=endpoint_ids.index(default_endpoint),
    format_func=format_endpoint,
)


# ============================================================
# SELECTED ENDPOINT DATA
# ============================================================

summary = get_endpoint_summary(selected_endpoint)
artifact_records = get_endpoint_artifacts(selected_endpoint)


# ============================================================
# NO ARTIFACT STATE
# ============================================================

if summary is None or not artifact_records:

    st.info(
        f"""
        **No artifact evidence is currently linked to `{selected_endpoint}`.**

        The endpoint exists in the telemetry dataset, but the current
        graph contains no parseable `Endpoint → OBSERVED → Artifact`
        relationship for this endpoint.

        This is a graph-coverage result, not a security verdict.
        """
    )

    st.stop()


# ============================================================
# ENDPOINT SUMMARY
# ============================================================

summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)

with summary_col1:
    st.metric(
        "Artifacts",
        summary["unique_artifacts"],
    )

with summary_col2:
    st.metric(
        "Observations",
        summary["total_observations"],
    )

with summary_col3:
    st.metric(
        "Malicious Artifacts",
        summary["malicious_artifacts"],
    )

with summary_col4:
    st.metric(
        "Detections",
        summary["malicious_detections"],
    )


# ============================================================
# SECURITY STATUS AND ACTIVITY WINDOW
# ============================================================

security_col, activity_col = st.columns([1, 1.4])

with security_col:

    st.subheader("Security Status")

    if summary["malicious_artifacts"] > 0:

        st.error(
            "Explicit malicious security evidence detected."
        )

        st.caption(
            f"{summary['malicious_artifacts']} artifact(s) have "
            "relationship-level malicious detection evidence."
        )

        st.caption(
            "Detection evidence alone does not establish compromise, "
            "execution, persistence, or attribution."
        )

    else:

        st.success(
            "No explicit malicious security evidence detected."
        )

        st.caption(
            "No malicious detection evidence is present in the "
            "modeled relationships."
        )


with activity_col:

    st.subheader("Activity Window")

    activity_col1, activity_col2 = st.columns(2)

    with activity_col1:
        st.caption("First observation")
        st.write(
            format_datetime(
                summary["first_observation"]
            )
        )

    with activity_col2:
        st.caption("Last observation")
        st.write(
            format_datetime(
                summary["last_observation"]
            )
        )

    st.caption("Duration")

    st.write(
        format_duration(
            summary["first_observation"],
            summary["last_observation"],
        )
    )


# ============================================================
# INVESTIGATION PRIORITY
# ============================================================

st.subheader("Investigation Priority")

if summary["malicious_artifacts"] > 0:

    priority = "High"

    reason = (
        "Explicit malicious detection evidence is present. "
        "Review the associated artifacts, timestamps, and "
        "security telemetry."
    )

elif summary["unique_artifacts"] >= 10:

    priority = "High"

    reason = (
        "High artifact activity volume warrants further investigation. "
        "This is a triage signal rather than proof of compromise."
    )

elif summary["unique_artifacts"] > 0:

    priority = "Moderate"

    reason = (
        "Artifact relationships are present but activity volume "
        "is comparatively limited."
    )

else:

    priority = "Low"

    reason = (
        "No artifact relationships are currently available."
    )


priority_col1, priority_col2 = st.columns([1, 4])

with priority_col1:
    st.metric("Priority", priority)

with priority_col2:
    st.info(reason)


st.divider()


# ============================================================
# EVIDENCE
# ============================================================

st.header("Evidence")

evidence_tab1, evidence_tab2, evidence_tab3 = st.tabs(
    [
        "Malicious Evidence",
        "Activity Timeline",
        "All Artifacts",
    ]
)


# ============================================================
# MALICIOUS EVIDENCE TAB
# ============================================================

with evidence_tab1:

    malicious_records = [
        record
        for record in artifact_records
        if record.get("malicious_detected") is True
    ]

    if not malicious_records:

        st.success(
            "No explicit malicious artifact detections are associated "
            "with this endpoint."
        )

    else:

        malicious_rows = []

        for record in malicious_records:

            malicious_rows.append(
                {
                    "SHA256": shorten_sha256(record["sha256"]),
                    "File": format_file_names(
                        record["malicious_file_names"]
                        or record["file_names"]
                    ),
                    "Detections": record[
                        "malicious_detection_count"
                    ],
                    "First Detection": format_datetime(
                        record["first_malicious_detection"]
                    ),
                    "Last Detection": format_datetime(
                        record["last_malicious_detection"]
                    ),
                    "Quarantine": format_datetime(
                        record["first_quarantine_time"]
                    ),
                }
            )

        malicious_df = pd.DataFrame(malicious_rows)

        st.dataframe(
            malicious_df,
            width="stretch",
            hide_index=True,
        )

        st.caption(
            "SHA256 values are shortened for readability. "
            "Complete hashes are available in the All Artifacts view."
        )
# ============================================================
# ACTIVITY TIMELINE TAB
# ============================================================

with evidence_tab2:

    timeline_rows = []

    for record in artifact_records:

        first_event = parse_datetime(record["first_event"])
        last_event = parse_datetime(record["last_event"])

        if pd.isna(first_event) or pd.isna(last_event):
            continue

        timeline_rows.append(
            {
                "sha256": record["sha256"],
                "first_event": first_event,
                "last_event": last_event,
                "Evidence": (
                    "Malicious detection"
                    if record["malicious_detected"]
                    else "Observed artifact"
                ),
                "File": format_file_names(
                    record["file_names"]
                ),
                "Observations": record["record_count"],
                "Detections": record["malicious_detection_count"],
            }
        )

    timeline_df = pd.DataFrame(timeline_rows)

    if timeline_df.empty:

        st.info(
            "No valid temporal information is available for this endpoint."
        )

    else:

        # Use filenames as the visible artifact labels and retain SHA256
        # values in the hover information for forensic identification.
        timeline_df["Artifact"] = timeline_df.apply(
            lambda row: (
                row["File"]
                if row["File"]
                else shorten_sha256(row["sha256"])
            ),
            axis=1,
        )

        time_min = timeline_df["first_event"].min()
        time_max = timeline_df["last_event"].max()

        # Calculate the real temporal span of the selected endpoint.
        total_span = time_max - time_min

        # Plotly cannot visibly render a zero-duration event as a bar.
        # Give instantaneous events a small visual duration while keeping
        # their original timestamps unchanged in the underlying data.
        minimum_visual_duration = pd.Timedelta(milliseconds=100)

        timeline_df["plot_end"] = timeline_df.apply(
            lambda row: (
                row["last_event"]
                if row["last_event"] > row["first_event"]
                else row["first_event"] + minimum_visual_duration
            ),
            axis=1,
        )

        # Give very short investigations enough horizontal space to make
        # individual events visually distinguishable.
        minimum_axis_window = pd.Timedelta(seconds=10)

        if total_span < minimum_axis_window:

            center_time = time_min + (
                total_span / 2
            )

            axis_start = (
                center_time
                - minimum_axis_window / 2
            )

            axis_end = (
                center_time
                + minimum_axis_window / 2
            )

        else:

            axis_start = time_min
            axis_end = time_max

        timeline_plot = px.timeline(
            timeline_df,
            x_start="first_event",
            x_end="plot_end",
            y="Artifact",
            color="Evidence",
            hover_data={
                "File": True,
                "Observations": True,
                "Detections": True,
                "sha256": True,
                "first_event": True,
                "last_event": True,
                "plot_end": False,
            },
            labels={
                "Artifact": "Artifact",
                "first_event": "First Event",
                "last_event": "Last Event",
            },
        )

        # Preserve chronological ordering from top to bottom.
        timeline_plot.update_yaxes(
            autorange="reversed",
            title=None,
        )

        # Display a clean second-level axis while preserving exact
        # forensic timestamps in the table below the visualization.
        timeline_plot.update_xaxes(
            range=[
                axis_start,
                axis_end,
            ],
            title="Event Time",
            tickformat="%H:%M:%S",
        )

        timeline_plot.update_layout(
            height=max(
                300,
                min(
                    500,
                    170 + len(timeline_df) * 45,
                ),
            ),
            margin=dict(
                l=20,
                r=20,
                t=20,
                b=20,
            ),
            legend_title="Evidence",
            hoverlabel=dict(
                namelength=-1,
            ),
        )

        st.plotly_chart(
            timeline_plot,
            width="stretch",
        )

        # Display exact timestamps separately so visual padding used for
        # instantaneous events never changes the forensic evidence itself.
        timeline_details = timeline_df[
            [
                "Artifact",
                "first_event",
                "last_event",
                "Evidence",
            ]
        ].copy()

        timeline_details["First Event"] = (
            timeline_details["first_event"]
            .dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            .str.rstrip("0")
            .str.rstrip(".")
        )

        timeline_details["Last Event"] = (
            timeline_details["last_event"]
            .dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            .str.rstrip("0")
            .str.rstrip(".")
        )

        timeline_details = timeline_details[
            [
                "Artifact",
                "First Event",
                "Last Event",
                "Evidence",
            ]
        ]

        st.dataframe(
            timeline_details,
            width="stretch",
            hide_index=True,
        )
# ============================================================
# ALL ARTIFACTS TAB
# ============================================================

with evidence_tab3:

    artifact_rows = []

    for record in artifact_records:

        artifact_rows.append(
            {
                "SHA256": record["sha256"],
                "File": format_file_names(
                    record["file_names"]
                ),
                "Observations": record["record_count"],
                "First Event": format_datetime(
                    record["first_event"]
                ),
                "Last Event": format_datetime(
                    record["last_event"]
                ),
                "Malicious": (
                    "Yes"
                    if record["malicious_detected"]
                    else "No"
                ),
                "Detections": record[
                    "malicious_detection_count"
                ],
            }
        )

    artifact_df = pd.DataFrame(artifact_rows)

    st.dataframe(
        artifact_df,
        width="stretch",
        hide_index=True,
    )


# ============================================================
# CROSS-ENDPOINT CORRELATION
# ============================================================

st.divider()

with st.expander(
    "Cross-Endpoint Artifact Correlation",
    expanded=False,
):

    shared_artifacts = get_shared_artifacts()

    if not shared_artifacts:

        st.info(
            "No artifacts are currently shared across multiple endpoints."
        )

    else:

        shared_rows = []

        for record in shared_artifacts:

            shared_rows.append(
                {
                    "SHA256": shorten_sha256(
                        record["sha256"]
                    ),
                    "File": format_file_names(
                        record["file_names"]
                    ),
                    "Endpoint Count": record[
                        "endpoint_count"
                    ],
                    "Endpoints": ", ".join(
                        record["endpoints"]
                    ),
                }
            )

        shared_df = pd.DataFrame(shared_rows)

        st.caption(
            "Shared artifacts provide cross-endpoint correlation points."
        )

        st.dataframe(
            shared_df,
            width="stretch",
            hide_index=True,
        )


# ============================================================
# GRAPH-WIDE ENDPOINT ACTIVITY
# ============================================================

with st.expander(
    "Graph-Wide Endpoint Activity",
    expanded=False,
):

    activity_records = get_endpoint_activity_overview()

    if activity_records:

        activity_rows = []

        for record in activity_records:

            activity_rows.append(
                {
                    "Endpoint": record["endpoint"],
                    "Artifacts": record["unique_artifacts"],
                    "Observations": record["total_observations"],
                    "Malicious Artifacts": record[
                        "malicious_artifacts"
                    ],
                    "Detections": record[
                        "malicious_detections"
                    ],
                    "First Observation": format_datetime(
                        record["first_observation"]
                    ),
                    "Last Observation": format_datetime(
                        record["last_observation"]
                    ),
                }
            )

        activity_df = pd.DataFrame(activity_rows)

        st.dataframe(
            activity_df,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No endpoint activity data is available."
        )


# ============================================================
# INVESTIGATOR INTERPRETATION
# ============================================================

with st.expander(
    "Investigator Interpretation Framework",
    expanded=False,
):

    st.markdown(
        """
        **Interpretation framework**

        - **Explicit malicious detection** represents security telemetry
          indicating that an observed artifact was detected as malicious.

        - **Artifact activity** represents endpoint–artifact relationships
          reconstructed from the available telemetry.

        - **High activity volume** is a triage signal and does not by
          itself prove compromise.

        - **Cross-endpoint artifact reuse** provides a correlation
          mechanism for identifying artifacts appearing across multiple
          endpoints.

        - Endpoint compromise, execution, persistence, or attribution
          should not be inferred solely from the presence of an artifact
          or a malicious detection.
        """
    )