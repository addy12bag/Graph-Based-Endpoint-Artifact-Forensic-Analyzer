# Endpoint–Artifact Forensic Investigation Dashboard

A Neo4j and Streamlit based forensic investigation system for analyzing endpoint–artifact relationships, identifying malicious artifacts, correlating indicators across endpoints, reconstructing detection timelines, and prioritizing endpoints for investigation.

The project converts endpoint telemetry into a graph-based forensic model and provides an interactive dashboard for security investigation and triage.

---

## 1. Project Overview

Traditional tabular analysis makes it difficult to investigate relationships between:

- endpoints
- files and artifacts
- SHA256 hashes
- malicious detections
- detection timestamps
- repeated observations
- artifacts shared across multiple endpoints

This project models these relationships using a **Neo4j property graph**.

The core relationship is:

```text
Endpoint ──[:OBSERVED]──> Artifact
