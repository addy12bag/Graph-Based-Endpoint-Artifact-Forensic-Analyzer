# ============================================================
# Endpoint–Artifact Forensic Investigation Dashboard
# Neo4j + Streamlit
# ============================================================

import streamlit as st
import pandas as pd
import plotly.express as px
from neo4j import GraphDatabase


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Endpoint–Artifact Forensic Investigation Dashboard",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM STYLING
# ============================================================

st.markdown(
    """
    <style>

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1650px;
    }

    [data-testid="stMetric"] {
        padding: 0.2rem 0;
    }

    [data-testid="stMetricLabel"] {
        font-size: 0.85rem;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.65rem;
    }

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

    [data-testid="stDataFrame"] {
        border-radius: 6px;
    }

    hr {
        margin: 1.25rem 0;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

URI = "neo4j://127.0.0.1:7687"
USERNAME = "neo4j"
DATABASE = "indianarmygraph"


# ============================================================
# NEO4J CONNECTION
# ============================================================

@st.cache_resource
def get_driver():
    """
    Create and cache the Neo4j driver.
    """

    password = st.secrets["NEO4J_PASSWORD"]

    driver = GraphDatabase.driver(
        URI,
        auth=(USERNAME, password),
    )

    driver.verify_connectivity()

    return driver


def run_query(query, parameters=None):
    """
    Execute a Cypher query and return records as dictionaries.
    """

    driver = get_driver()

    result = driver.execute_query(
        query,
        parameters or {},
        database_=DATABASE,
    )

    return [dict(record) for record in result.records]


# ============================================================
# TEMPORAL / DISPLAY HELPERS
# ============================================================

def parse_datetime(value):
    """
    Convert Neo4j temporal values into pandas timestamps.
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
    Format timestamps for forensic readability.
    """

    timestamp = parse_datetime(value)

    if pd.isna(timestamp):
        return "N/A"

    formatted = timestamp.strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )

    return formatted.rstrip("0").rstrip(".")


def format_duration(start, end):
    """
    Calculate elapsed time between two observations.
    """

    start_time = parse_datetime(start)
    end_time = parse_datetime(end)

    if pd.isna(start_time) or pd.isna(end_time):
        return "N/A"

    duration = end_time - start_time

    return str(duration).split(".")[0]


def shorten_sha256(value):
    """
    Shorten SHA256 values for compact dashboard tables.
    """

    if not value:
        return ""

    value = str(value)

    if len(value) <= 20:
        return value

    return f"{value[:12]}...{value[-8:]}"


def format_file_names(value):
    """
    Convert filename lists into readable text.
    """

    if value is None:
        return ""

    if isinstance(value, list):
        return ", ".join(str(item) for item in value)

    return str(value)


# ============================================================
# GRAPH-WIDE SECURITY METRICS
# ============================================================

@st.cache_data(ttl=30)
def get_graph_metrics():

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
        malicious_artifact_count DESC,
        artifact_count DESC,
        endpoint
    """

    return run_query(query)


# ============================================================
# ENDPOINT RISK RANKING
# ============================================================

@st.cache_data(ttl=30)
def get_endpoint_risk_ranking():

    query = """
    MATCH (e:Endpoint)-[r:OBSERVED]->(a:Artifact)

    WITH
        e.endpoint_id AS endpoint,

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
                    THEN coalesce(r.malicious_detection_count, 0)
                    ELSE 0
                END
            ),
            0
        ) AS total_detections,

        min(
            CASE
                WHEN r.malicious_detected = true
                THEN r.first_malicious_detection
            END
        ) AS first_detection,

        max(
            CASE
                WHEN r.malicious_detected = true
                THEN r.last_malicious_detection
            END
        ) AS last_detection

    WHERE malicious_artifacts > 0

    RETURN
        endpoint,
        malicious_artifacts,
        total_detections,
        first_detection,
        last_detection

    ORDER BY
        malicious_artifacts DESC,
        total_detections DESC,
        endpoint ASC
    """

    return run_query(query)


def calculate_risk(malicious_artifacts, detections):

    malicious_artifacts = int(
        malicious_artifacts or 0
    )

    detections = int(
        detections or 0
    )

    if malicious_artifacts >= 10 or detections >= 30:
        return "CRITICAL"

    if malicious_artifacts >= 1 and detections >= 5:
        return "HIGH"

    if malicious_artifacts >= 1:
        return "MEDIUM"

    return "LOW"


# ============================================================
# HIGHEST-RISK ENDPOINT
# ============================================================

def get_highest_risk_endpoint():

    records = get_endpoint_risk_ranking()

    if not records:
        return None

    return records[0]


# ============================================================
# ENDPOINT SUMMARY
# ============================================================

def get_endpoint_summary(endpoint_id):

    query = """
    MATCH (e:Endpoint {endpoint_id: $endpoint_id})
          -[r:OBSERVED]->
          (a:Artifact)

    RETURN
        e.endpoint_id AS endpoint,

        count(DISTINCT a) AS unique_artifacts,

        coalesce(
            sum(r.record_count),
            0
        ) AS total_observations,

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
                    THEN coalesce(
                        r.malicious_detection_count,
                        0
                    )
                    ELSE 0
                END
            ),
            0
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

        r.malicious_detection_count
            AS malicious_detection_count,

        r.malicious_file_names
            AS malicious_file_names,

        r.first_malicious_detection
            AS first_malicious_detection,

        r.last_malicious_detection
            AS last_malicious_detection,

        r.first_quarantine_time
            AS first_quarantine_time,

        r.last_quarantine_time
            AS last_quarantine_time

    ORDER BY
        r.malicious_detected DESC,
        r.malicious_detection_count DESC,
        r.first_event
    """

    return run_query(
        query,
        {"endpoint_id": endpoint_id},
    )


# ============================================================
# SHARED MALICIOUS ARTIFACT CORRELATION
# ============================================================

@st.cache_data(ttl=30)
def get_shared_malicious_artifacts():

    query = """
    MATCH (e:Endpoint)-[r:OBSERVED]->(a:Artifact)

    WHERE r.malicious_detected = true

    WITH
        a,
        collect(DISTINCT e.endpoint_id) AS endpoints

    WHERE size(endpoints) > 1

    RETURN
        a.sha256 AS sha256,
        a.file_names AS file_names,
        endpoints,
        size(endpoints) AS endpoint_count

    ORDER BY
        endpoint_count DESC
    """

    return run_query(query)


# ============================================================
# GRAPH-WIDE ENDPOINT ACTIVITY
# ============================================================

@st.cache_data(ttl=30)
def get_endpoint_activity_overview():

    query = """
    MATCH (e:Endpoint)

    OPTIONAL MATCH (e)-[r:OBSERVED]->(a:Artifact)

    RETURN
        e.endpoint_id AS endpoint,

        count(DISTINCT a) AS unique_artifacts,

        coalesce(
            sum(r.record_count),
            0
        ) AS total_observations,

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
                    THEN coalesce(
                        r.malicious_detection_count,
                        0
                    )
                    ELSE 0
                END
            ),
            0
        ) AS malicious_detections,

        min(r.first_event) AS first_observation,

        max(r.last_event) AS last_observation

    ORDER BY
        malicious_artifacts DESC,
        malicious_detections DESC,
        total_observations DESC
    """

    return run_query(query)


# ============================================================
# HEADER
# ============================================================

st.title(
    "Endpoint–Artifact Forensic Investigation Dashboard"
)

st.caption(
    "Neo4j graph-based investigation of endpoint compromise "
    "indicators, malicious artifacts, cross-endpoint IOCs, "
    "timelines, and remediation priorities."
)


# ============================================================
# GRAPH-WIDE SECURITY OVERVIEW
# ============================================================

metrics = get_graph_metrics()

highest_risk = get_highest_risk_endpoint()

unconnected_endpoint_count = (
    metrics["endpoint_count"]
    - metrics["connected_endpoint_count"]
)

artifact_coverage = (
    (
        metrics["connected_endpoint_count"]
        / metrics["endpoint_count"]
        * 100
    )
    if metrics["endpoint_count"] > 0
    else 0
)


st.header("Security Investigation Overview")

st.caption(
    "Graph-wide security posture derived from explicit malicious "
    "detection evidence in Endpoint → OBSERVED → Artifact relationships."
)


overview_col1, overview_col2, overview_col3, overview_col4, overview_col5 = (
    st.columns(5)
)


with overview_col1:
    st.metric(
        "Total Endpoints",
        metrics["endpoint_count"],
    )


with overview_col2:
    st.metric(
        "Malicious Endpoints",
        metrics["malicious_endpoint_count"],
    )


with overview_col3:
    st.metric(
        "Malicious Artifacts",
        metrics["malicious_artifact_count"],
    )


with overview_col4:
    st.metric(
        "Malicious Relationships",
        metrics["malicious_relationship_count"],
    )


with overview_col5:

    if highest_risk:

        st.metric(
            "Highest-Risk Endpoint",
            highest_risk["endpoint"],
            delta=f"{highest_risk['malicious_artifacts']} malicious artifacts",
        )

    else:

        st.metric(
            "Highest-Risk Endpoint",
            "None",
        )


coverage_col1, coverage_col2 = st.columns(
    [1, 3]
)


with coverage_col1:

    st.metric(
        "Endpoints Without Artifacts",
        unconnected_endpoint_count,
    )


with coverage_col2:

    st.write(
        "Artifact Relationship Coverage"
    )

    st.progress(
        min(
            artifact_coverage / 100,
            1.0,
        )
    )

    st.caption(
        f"{metrics['connected_endpoint_count']} of "
        f"{metrics['endpoint_count']} endpoints have at least one "
        f"artifact relationship ({artifact_coverage:.1f}% coverage)."
    )


# ============================================================
# ENDPOINT RISK RANKING
# ============================================================

st.divider()

st.header("Endpoint Risk Ranking")

risk_records = get_endpoint_risk_ranking()

if not risk_records:

    st.info(
        "No endpoints with explicit malicious evidence were found."
    )

else:

    risk_rows = []

    for record in risk_records:

        risk = calculate_risk(
            record["malicious_artifacts"],
            record["total_detections"],
        )

        risk_rows.append(
            {
                "Risk": risk,
                "Endpoint": record["endpoint"],
                "Malicious Artifacts": record[
                    "malicious_artifacts"
                ],
                "Detections": record[
                    "total_detections"
                ],
                "First Detection": format_datetime(
                    record["first_detection"]
                ),
                "Last Detection": format_datetime(
                    record["last_detection"]
                ),
            }
        )

    risk_df = pd.DataFrame(
        risk_rows
    )

    st.dataframe(
        risk_df,
        width="stretch",
        hide_index=True,
    )

    st.caption(
        "Risk classification represents investigation priority "
        "based on explicit malicious detection evidence. It does "
        "not independently establish execution, persistence, "
        "or attribution."
    )


# ============================================================
# SHARED MALICIOUS IOC CORRELATION
# ============================================================

st.divider()

st.header(
    "Shared Malicious IOC Correlation"
)

shared_artifacts = get_shared_malicious_artifacts()

if not shared_artifacts:

    st.info(
        "No malicious artifacts are currently shared across "
        "multiple endpoints."
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

                "Affected Endpoints": record[
                    "endpoint_count"
                ],

                "Endpoints": ", ".join(
                    record["endpoints"]
                ),
            }
        )

    shared_df = pd.DataFrame(
        shared_rows
    )

    st.dataframe(
        shared_df,
        width="stretch",
        hide_index=True,
    )

    st.caption(
        "Malicious artifacts observed across multiple endpoints "
        "are high-value IOC correlation and threat-hunting targets."
    )


# ============================================================
# ENDPOINT INVESTIGATION
# ============================================================

st.divider()

st.header("Endpoint Investigation")

endpoint_records = get_endpoints()

if not endpoint_records:

    st.warning(
        "No endpoints were found in the Neo4j graph."
    )

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

    record = endpoint_lookup[
        endpoint_id
    ]

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


# Prefer highest-risk endpoint.
default_endpoint = (
    highest_risk["endpoint"]
    if highest_risk
    and highest_risk["endpoint"] in endpoint_ids
    else endpoint_ids[0]
)


selected_endpoint = st.selectbox(
    "Endpoint",
    endpoint_ids,
    index=endpoint_ids.index(
        default_endpoint
    ),
    format_func=format_endpoint,
)


# ============================================================
# SELECTED ENDPOINT DATA
# ============================================================

summary = get_endpoint_summary(
    selected_endpoint
)

artifact_records = get_endpoint_artifacts(
    selected_endpoint
)


# ============================================================
# NO ARTIFACT STATE
# ============================================================

if summary is None or not artifact_records:

    st.info(
        f"""
        **No artifact evidence is currently linked to
        `{selected_endpoint}`.**

        The endpoint exists in the telemetry dataset, but the
        current graph contains no parseable
        `Endpoint → OBSERVED → Artifact` relationship.

        This is a graph-coverage result, not a security verdict.
        """
    )

    st.stop()


# ============================================================
# ENDPOINT SUMMARY
# ============================================================

summary_col1, summary_col2, summary_col3, summary_col4 = (
    st.columns(4)
)


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
# ENDPOINT FINDINGS
# ============================================================

st.header(
    "Endpoint Investigation Findings"
)


if summary["malicious_artifacts"] > 0:

    st.error(
        f"Malicious evidence identified on endpoint "
        f"{selected_endpoint}."
    )

else:

    st.success(
        f"No explicit malicious detection evidence identified "
        f"on endpoint {selected_endpoint}."
    )


# ============================================================
# SECURITY STATUS + ACTIVITY WINDOW
# ============================================================

security_col, activity_col = st.columns(
    [1, 1.4]
)


with security_col:

    st.subheader(
        "Evidence Assessment"
    )

    if summary["malicious_artifacts"] > 0:

        st.error(
            "Explicit malicious detection evidence detected."
        )

        st.write(
            f"{summary['malicious_artifacts']} artifact(s) "
            f"have malicious detection evidence, producing "
            f"{summary['malicious_detections']} detection(s)."
        )

    else:

        st.success(
            "No explicit malicious detection evidence detected."
        )


with activity_col:

    st.subheader(
        "Activity Window"
    )

    activity_col1, activity_col2 = st.columns(2)

    with activity_col1:

        st.caption(
            "First observation"
        )

        st.write(
            format_datetime(
                summary["first_observation"]
            )
        )

    with activity_col2:

        st.caption(
            "Last observation"
        )

        st.write(
            format_datetime(
                summary["last_observation"]
            )
        )

    st.caption(
        "Duration"
    )

    st.write(
        format_duration(
            summary["first_observation"],
            summary["last_observation"],
        )
    )


# ============================================================
# INVESTIGATION PRIORITY
# ============================================================

st.subheader(
    "Investigation Priority"
)


priority = calculate_risk(
    summary["malicious_artifacts"],
    summary["malicious_detections"],
)


if priority == "CRITICAL":

    reason = (
        "Critical triage target: the endpoint contains a large "
        "cluster of maliciously detected artifacts and should "
        "receive immediate containment and forensic attention."
    )

elif priority == "HIGH":

    reason = (
        "High-priority investigation target based on explicit "
        "malicious detection evidence and repeated detections."
    )

elif priority == "MEDIUM":

    reason = (
        "Medium-priority investigation target based on explicit "
        "malicious artifact evidence."
    )

else:

    reason = (
        "No significant malicious detection evidence is currently "
        "associated with this endpoint."
    )


priority_col1, priority_col2 = st.columns(
    [1, 4]
)


with priority_col1:

    st.metric(
        "Priority",
        priority,
    )


with priority_col2:

    st.info(
        reason
    )


# ============================================================
# HOW THE ENDPOINT IS IMPLICATED
# ============================================================

st.divider()

st.header(
    "How the Endpoint Is Implicated"
)


malicious_records = [
    record
    for record in artifact_records
    if record.get("malicious_detected") is True
]


if not malicious_records:

    st.success(
        f"No explicit malicious artifact evidence is associated "
        f"with endpoint `{selected_endpoint}`."
    )

else:

    st.markdown(
        f"""
        Endpoint `{selected_endpoint}` is linked through
        **Endpoint → OBSERVED → Artifact** relationships to
        **{len(malicious_records)} maliciously detected artifacts**,
        producing **{summary["malicious_detections"]} detections**.

        These relationships establish explicit malicious detection
        evidence. They do not, by themselves, prove execution,
        persistence, or attribution.
        """
    )

    # --------------------------------------------------------
    # COMPACT EVIDENCE METRICS
    # --------------------------------------------------------

    implication_col1, implication_col2, implication_col3 = (
        st.columns(3)
    )


    unique_malicious_files = {
        filename
        for record in malicious_records
        for filename in (
            record.get("malicious_file_names")
            or record.get("file_names")
            or []
        )
    }


    with implication_col1:

        st.metric(
            "Malicious Artifacts",
            len(malicious_records),
        )


    with implication_col2:

        st.metric(
            "Malicious Detections",
            summary["malicious_detections"],
        )


    with implication_col3:

        st.metric(
            "Affected File Types",
            len(unique_malicious_files),
        )


    # --------------------------------------------------------
    # COMPACT MALICIOUS EVIDENCE TABLE
    # --------------------------------------------------------

    implication_rows = []


    for record in malicious_records:

        files = (
            record.get("malicious_file_names")
            or record.get("file_names")
            or []
        )

        implication_rows.append(
            {
                "SHA256": shorten_sha256(
                    record["sha256"]
                ),

                "Malicious File": format_file_names(
                    files
                ),

                "Detections": record.get(
                    "malicious_detection_count",
                    0,
                ),

                "First Detection": format_datetime(
                    record.get(
                        "first_malicious_detection"
                    )
                ),

                "Last Detection": format_datetime(
                    record.get(
                        "last_malicious_detection"
                    )
                ),
            }
        )


    implication_df = pd.DataFrame(
        implication_rows
    )


    implication_df = implication_df.sort_values(
        by="Detections",
        ascending=False,
    )


    # --------------------------------------------------------
    # SHOW TOP EVIDENCE
    # --------------------------------------------------------

    visible_records = implication_df.head(8)


    st.dataframe(
        visible_records,
        width="stretch",
        hide_index=True,
    )


    # --------------------------------------------------------
    # FULL EVIDENCE
    # --------------------------------------------------------

    if len(implication_df) > 8:

        with st.expander(
            f"View all {len(implication_df)} malicious artifacts",
            expanded=False,
        ):

            st.dataframe(
                implication_df,
                width="stretch",
                hide_index=True,
            )


    st.caption(
        "SHA256 values are shortened for readability. "
        "Complete hashes are available in the All Artifacts view."
    )


# ============================================================
# EVIDENCE TABS
# ============================================================

st.divider()

st.header(
    "Evidence"
)


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

    if not malicious_records:

        st.success(
            "No explicit malicious artifact detections are "
            "associated with this endpoint."
        )

    else:

        malicious_rows = []


        for record in malicious_records:

            malicious_rows.append(
                {
                    "SHA256": shorten_sha256(
                        record["sha256"]
                    ),

                    "File": format_file_names(
                        record.get(
                            "malicious_file_names"
                        )
                        or record.get(
                            "file_names"
                        )
                    ),

                    "Detections": record.get(
                        "malicious_detection_count",
                        0,
                    ),

                    "First Detection": format_datetime(
                        record.get(
                            "first_malicious_detection"
                        )
                    ),

                    "Last Detection": format_datetime(
                        record.get(
                            "last_malicious_detection"
                        )
                    ),

                    "Quarantine": format_datetime(
                        record.get(
                            "first_quarantine_time"
                        )
                    ),
                }
            )


        malicious_df = pd.DataFrame(
            malicious_rows
        )


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
# ACTIVITY TIMELINE
# ============================================================

with evidence_tab2:

    timeline_rows = []


    for record in artifact_records:

        first_event = parse_datetime(
            record["first_event"]
        )

        last_event = parse_datetime(
            record["last_event"]
        )


        if (
            pd.isna(first_event)
            or pd.isna(last_event)
        ):
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

                "Observations": record[
                    "record_count"
                ],

                "Detections": record[
                    "malicious_detection_count"
                ],
            }
        )


    timeline_df = pd.DataFrame(
        timeline_rows
    )


    if timeline_df.empty:

        st.info(
            "No valid temporal information is available "
            "for this endpoint."
        )

    else:

        timeline_df["Artifact"] = timeline_df.apply(
            lambda row: (
                row["File"]
                if row["File"]
                else shorten_sha256(
                    row["sha256"]
                )
            ),
            axis=1,
        )


        time_min = timeline_df[
            "first_event"
        ].min()

        time_max = timeline_df[
            "last_event"
        ].max()


        total_span = (
            time_max
            - time_min
        )


        minimum_visual_duration = (
            pd.Timedelta(
                milliseconds=100
            )
        )


        timeline_df["plot_end"] = timeline_df.apply(
            lambda row: (
                row["last_event"]
                if row["last_event"]
                > row["first_event"]
                else row["first_event"]
                + minimum_visual_duration
            ),
            axis=1,
        )


        minimum_axis_window = (
            pd.Timedelta(
                seconds=10
            )
        )


        if total_span < minimum_axis_window:

            center_time = (
                time_min
                + total_span / 2
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


        timeline_plot.update_yaxes(
            autorange="reversed",
            title=None,
        )


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
                    170
                    + len(timeline_df)
                    * 45,
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


        timeline_details = timeline_df[
            [
                "Artifact",
                "first_event",
                "last_event",
                "Evidence",
            ]
        ].copy()


        timeline_details[
            "First Event"
        ] = (
            timeline_details[
                "first_event"
            ]
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
            .str.rstrip("0")
            .str.rstrip(".")
        )


        timeline_details[
            "Last Event"
        ] = (
            timeline_details[
                "last_event"
            ]
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
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
# ALL ARTIFACTS
# ============================================================

with evidence_tab3:

    artifact_rows = []


    for record in artifact_records:

        artifact_rows.append(
            {
                "SHA256": record[
                    "sha256"
                ],

                "File": format_file_names(
                    record[
                        "file_names"
                    ]
                ),

                "Observations": record[
                    "record_count"
                ],

                "First Event": format_datetime(
                    record[
                        "first_event"
                    ]
                ),

                "Last Event": format_datetime(
                    record[
                        "last_event"
                    ]
                ),

                "Malicious": (
                    "Yes"
                    if record[
                        "malicious_detected"
                    ]
                    else "No"
                ),

                "Detections": record[
                    "malicious_detection_count"
                ],
            }
        )


    artifact_df = pd.DataFrame(
        artifact_rows
    )


    st.dataframe(
        artifact_df,
        width="stretch",
        hide_index=True,
    )


# ============================================================
# GRAPH-WIDE ENDPOINT ACTIVITY
# ============================================================

st.divider()

with st.expander(
    "Graph-Wide Endpoint Activity",
    expanded=False,
):

    activity_records = (
        get_endpoint_activity_overview()
    )


    if activity_records:

        activity_rows = []


        for record in activity_records:

            activity_rows.append(
                {
                    "Endpoint": record[
                        "endpoint"
                    ],

                    "Artifacts": record[
                        "unique_artifacts"
                    ],

                    "Observations": record[
                        "total_observations"
                    ],

                    "Malicious Artifacts": record[
                        "malicious_artifacts"
                    ],

                    "Detections": record[
                        "malicious_detections"
                    ],

                    "First Observation": format_datetime(
                        record[
                            "first_observation"
                        ]
                    ),

                    "Last Observation": format_datetime(
                        record[
                            "last_observation"
                        ]
                    ),
                }
            )


        activity_df = pd.DataFrame(
            activity_rows
        )


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
# REMEDIATION / RESPONSE RECOMMENDATIONS
# ============================================================

st.divider()

st.header(
    "Recommended Remedial Measures"
)


if summary["malicious_artifacts"] > 0:

    remediation_col1, remediation_col2 = st.columns(2)


    with remediation_col1:

        st.markdown(
            """
            **Immediate containment**

            1. Isolate the endpoint from the network.
            2. Preserve volatile and forensic evidence before cleanup.
            3. Quarantine confirmed malicious artifacts.
            4. Perform an enterprise-wide SHA256 IOC sweep.
            5. Check other endpoints for the same filenames/artifacts.
            """
        )


    with remediation_col2:

        st.markdown(
            """
            **Further investigation**

            1. Investigate whether the detected artifacts executed.
            2. Review process, command-line and parent-child telemetry.
            3. Check persistence locations and scheduled tasks.
            4. Investigate network connections and lateral movement.
            5. Reset credentials if credential exposure is suspected.
            6. Reimage the endpoint if system integrity cannot be established.
            """

        )

else:

    st.info(
        "No explicit malicious evidence is currently present. "
        "Continue monitoring and perform IOC correlation if "
        "new detections appear."
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
        ### Interpretation framework

        **Explicit malicious detection**

        Security telemetry indicating that an observed artifact
        was detected as malicious.

        **Endpoint implication**

        An endpoint with malicious artifact relationships should
        be treated as an investigation and containment target.

        **Compromise assessment**

        Malicious artifact detection alone does not independently
        prove execution, persistence, successful exploitation,
        lateral movement, or attribution.

        **Cross-endpoint correlation**

        An artifact appearing on multiple endpoints provides a
        high-value IOC correlation point and should be investigated
        across the environment.

        **Risk ranking**

        Risk represents investigation priority derived from the
        available malicious artifact and detection evidence.

        **Forensic principle**

        Preserve evidence before remediation whenever practical,
        then use the identified hashes, filenames and timestamps
        for enterprise-wide threat hunting.
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Endpoint–Artifact Forensic Investigation Dashboard • "
    "Evidence derived from the Neo4j investigation graph."
)