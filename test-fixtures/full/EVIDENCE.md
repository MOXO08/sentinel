# Sentinel Compliance Evidence: 'full' Fixture

## Regulatory Mapping

### Article 13: Transparency and Provision of Information
- **Requirement**: AI system identification for end-users.
- **Implementation**: path1.js line 6 (`transparency_label`).

### Article 14: Human Oversight
- **Requirement**: Technical stop buttons and manual override hooks.
- **Implementation**: path1.js line 9 (`requires_manual_check`) and line 33 (`kill_switch`).

### Article 20: Automatically Generated Logs
- **Requirement**: Automated record-keeping for traceability.
- **Implementation**: path1.js line 21 (`console.log` with trace metadata).
