# Sentinel Compliance Evidence: 'full' Fixture Hardening

This document provides audit-grade evidence of AI Act compliance for the 'full' test fixture.

## Regulatory Mapping

### Article 13: Transparency and Provision of Information
- **Requirement**: AI system identification, disclosure of limitations, and instructions for use.
- **Evidence**:
  - **Disclosure & Notice**: `const ai_disclosure_provided` contains the required wording (line 10).
  - **Content**: Explicit mention of **transparency**, **purpose**, **limitation**, and **model** behavior in the documentation header (lines 5-8).
  - **Performance**: System performance and instructions are managed via the high-risk registry.

### Article 14: Human Oversight
- **Requirement**: Technical stop buttons (kill switches) and manual intervention hooks.
- **Evidence**:
  - **Manual Override**: Implementation of `manual_override` (line 25).
  - **Kill Switch**: Implementation of `kill_switch` logic (line 26).
  - **Manual Intervention**: The `manual_intervention()` function provides the human-in-the-loop checkpoint (line 39).

### Article 20: Automatically Generated Logs
- **Requirement**: Traceability and automated record-keeping throughout the AI lifecycle.
- **Evidence**:
  - **Audit Log**: `console.log` captures the required **log**, **trace_id**, and **correlation_id** fields (line 14).

### Connectivity & Integrity
- **Connectivity Marker**: External traceability is established via `fetch("https://api.example.com/v1/trace")` (line 22).

## Verification Target
This fixture is designed to produce a `PASS` status under static analysis by aligning exactly with technical detection patterns for high-risk systems.
