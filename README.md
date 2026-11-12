# CloudDoctor

> **See the risk. Understand the exposure. Secure your cloud.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6.svg)](https://www.typescriptlang.org/)

**CloudDoctor** is a local-first AWS IAM policy document analyser designed for developers, DevOps engineers, and security reviewers. It parses policy JSON documents without executing them, applies deterministic security rules, and returns evidence-backed findings with a transparent prioritisation risk score (0–100).

It is a portfolio engineering project built for security review workflows. It runs strictly offline on your local machine and does not connect to AWS accounts, scan live infrastructure, or store policy payloads.

---

## Why It Matters

AWS Identity and Access Management (IAM) policies are deceptively compact. A wildcard action, broad `iam:PassRole`, or unsafe policy version combination can grant unintended privilege escalation paths. 

**CloudDoctor** turns those complex permission patterns into readable evidence, risk severity breakdowns, and actionable remediation guidelines before policies are deployed to production.

---

## Key Features

- **Strict IAM Document Parser:** Handles IAM policy structure, single strings vs. arrays for `Action` and `Resource`, `NotAction`, `NotResource`, `Condition` blocks, and `Effect` (`Allow` vs. `Deny`).
- **10 Explainable Rule Engines:** Identifies privilege escalations with matched action/resource evidence, statement IDs (`Sid`), remediation steps, and heuristic confidence tags.
- **Deterministic Risk Scoring:** Scores each policy deterministically from 0 to 100 with clear severity thresholds (Low, Moderate, High, Critical).
- **Local-First & Privacy Preserving:** No AWS API keys, no external network calls, no cloud telemetry, and zero raw-policy persistence.
- **Interactive Security Dashboard:** Modern React + TypeScript interface featuring scan history, sample policy library, severity visualizer, and policy inspector.
- **Audit Reports:** Export scan results to JSON or formatted printable summaries.

---

## Architecture

```mermaid
flowchart TD
    subgraph UI ["CloudDoctor Frontend (React + TypeScript)"]
        A[JSON Policy Input] --> B[Sample Policy Library]
        B --> C[Local API Client]
        C --> D[Risk Severity Chart & Findings]
        D --> E[Scan History & Export]
    end

    subgraph Server ["CloudDoctor Backend (FastAPI + SQLite)"]
        F["POST /api/analyze"] --> G[Strict Policy Parser]
        G --> H["Rule Engine (IAM-001 to IAM-010)"]
        H --> I[Deterministic Risk Scorer]
        I --> J[(SQLite Metadata Store)]
        I --> K[JSON Analysis Response]
    end

    C <-->|HTTP / JSON| F
```

---

## Detection Rules

| Rule | Detection Target | Default Severity | Description |
| :--- | :--- | :---: | :--- |
| **IAM-001** | Full Administrative Wildcard (`*`) | **Critical** | Flags `Action: "*"` combined with `Resource: "*"`. |
| **IAM-002** | Sensitive Actions on Broad Resources | **High / Critical** | Detects high-privilege IAM mutations on unconstrained targets. |
| **IAM-003** | Broad `iam:PassRole` | **Critical** | Catches `iam:PassRole` without restrictive resource ARNs. |
| **IAM-004** | Policy Version Creation & Activation | **Critical** | Detects permission to create and set new default policy versions. |
| **IAM-005** | Role Policy Attachment & Mutation | **High** | Identifies permission to attach inline policies to existing roles. |
| **IAM-006** | Access Key Creation | **High** | Flags unauthorized generation of user credentials. |
| **IAM-007** | Sensitive Actions Missing Condition Blocks | **Medium** | Flags administrative privileges lacking MFA or IP restrictions. |
| **IAM-008** | Service Wildcards (e.g., `s3:*`, `iam:*`) | **High** | Surfaces broad wildcard grants within specific cloud services. |
| **IAM-009** | `NotAction` / `NotResource` in Allow Statements | **Medium** | Highlights dangerous inverted permission logic. |
| **IAM-010** | Unparseable / Non-standard Constructs | **Informational** | Flags syntax or structures requiring manual human review. |

---

## Risk Methodology

Findings contribute deterministically to a cumulative risk score capped at **100**:
- **Critical:** +30 points
- **High:** +20 points
- **Medium:** +10 points
- **Low:** +5 points
- **Informational:** +0 points

| Score Range | Risk Level | Action Required |
| :---: | :---: | :--- |
| **0 – 19** | **Low** | Routine review; standard least-privilege alignment. |
| **20 – 39** | **Moderate** | Minor tightening recommended before deployment. |
| **40 – 69** | **High** | Review required; reduce wildcards and constrain resource ARNs. |
| **70 – 100** | **Critical** | Block deployment; privilege escalation or admin wildcard detected. |

---

## Getting Started Locally

### Prerequisites
- Python 3.11+
- Node.js 20+ and pnpm (or npm)

### 1. Backend Setup
```bash
cd backend
python -m venv .venv

# On Windows:
.\.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
FastAPI Swagger documentation will be available at: `http://127.0.0.1:8000/docs`

### 2. Frontend Setup
In a separate terminal:
```bash
cd frontend
pnpm install
pnpm dev
```
Open `http://localhost:5173` to launch the **CloudDoctor** dashboard.

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Healthcheck and engine status |
| `POST` | `/api/analyze` | Evaluates IAM policy JSON and returns structured findings |
| `GET` | `/api/rules` | Retrieves descriptions and severities for rules IAM-001–010 |
| `GET` | `/api/samples` | Lists pre-loaded safe, moderate, and critical test policies |
| `GET` | `/api/scans` | Returns metadata list of previous local scans |
| `DELETE` | `/api/scans/{id}` | Removes a specific scan record from local history |

*Note: Policy payload maximum limit is 256 KB. Raw policy text is never stored in SQLite; only finding metadata and scores are retained.*

---

## Testing & Quality

Run backend unit and security tests:
```bash
cd backend
pytest -v
```

Run frontend type checks and production build:
```bash
cd frontend
pnpm run build
```

---

## Limitations & Roadmap

- **CloudDoctor** focuses on static IAM policy analysis and does not resolve live AWS SCPs, resource-based policies, or runtime permission boundaries.
- **Planned Roadmap:**
  - [ ] SARIF report export for GitHub Actions CI/CD pipelines
  - [ ] AWS IAM Access Analyzer cross-verification adapter
  - [ ] Side-by-side policy diff and permission regression analyzer
  - [ ] Rule customization via local YAML configuration

---

## License

Distributed under the **MIT License**. See `LICENSE` for details.
