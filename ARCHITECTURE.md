# Architecture and Builder's Guide

This document outlines the complete stack architecture for the AI Agent Guardian platform, including components, data flow, and extension points for builders.

## High-Level Architecture
- **Frontend (Future)**: React/Vue app for dashboard (not in v1; add via separate repo or integrate).
- **Backend**: FastAPI for RESTful API, handling monitoring and verification.
- **Core Components**:
  - **Agent Simulator**: Mock AI agent that performs actions and maintains "memory" (simple dict).
  - **Guardian Monitor**: Watches for anomalies (e.g., hash mismatches in context).
  - **Decentralized Verifier**: Uses cryptographic proofs (SHA-256 hashes chained like a merkle tree) to verify actions without a central authority. In v1, it's in-memory; extend to blockchain for persistence.
- **Database (Future)**: PostgreSQL or MongoDB for logging anomalies (v1 uses in-memory).
- **Cloud Integration**: Deploy as serverless (e.g., AWS Lambda) or containerized (Docker/Kubernetes).
- **Security**: API keys for access; extend with OAuth.

## Data Flow
1. AI Agent performs an action → Sends to Guardian API.
2. Guardian hashes the action/context → Checks against previous proofs.
3. If anomaly (e.g., hash mismatch), flags and logs.
4. Returns verification proof.

## Builder's Guide for Complete Stack
- **Extend Monitoring**: Add rules in `guardian.py` for more anomaly types (e.g., regex for unauthorized APIs).
- **Decentralized Layer**: Replace mock hashes with web3.py for Ethereum. Store proofs on-chain.
- **Scaling**: Use Celery/Redis for async monitoring tasks.
- **Testing**: Add more tests in `tests/`. Use pytest.
- **Deployment Pipeline**: Add GitHub Actions YAML for CI/CD.
- **Version 1 Demo**: Simulates 5 agent actions with one anomaly. Extend to real AI agents (e.g., integrate with LangChain).

## Components Breakdown
| Component | Description | Tech | Extension Points |
|-----------|-------------|------|------------------|
| Agent Sim | Mock AI agent | Python classes | Integrate real AI (e.g., OpenAI API) |
| Guardian | Monitoring logic | FastAPI routes | Add ML-based anomaly detection (e.g., scikit-learn) |
| Verifier | Proof generation | Cryptography (hashlib) | Blockchain integration (web3) |
| Demo | End-to-end script | Python script | Build UI dashboard |

For questions, open an issue on GitHub.
