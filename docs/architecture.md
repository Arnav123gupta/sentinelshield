# SentinelShield Architecture

```mermaid
flowchart TD
    A[Incoming HTTP Request] --> B[Request Parsing]
    B --> C[Input Normalization]
    C --> D[Rule-Based Detection Engine]
    D --> E{Detection Result}
    E -->|No rule matched| F[ALLOW]
    E -->|Rule matched| G[BLOCK]

    B --> H[Traffic Tracking]
    H --> I[Rate Limiter and Repeat Detector]
    I --> J{Traffic Decision}
    J -->|Within limits| K[Continue Protection Flow]
    J -->|Limit exceeded| L[Protection BLOCK]

    F --> M[Security Event Logs]
    G --> M
    L --> M
    M --> N[Alerts and Dashboard Statistics]
    N --> O[Security Dashboard]

```

## Architecture Explanation

1. **Request parsing:** Collects HTTP request details.
2. **Input normalization:** Decodes input before detection.
3. **Detection engine:** Checks configured rules for SQL injection, XSS, path traversal, LFI and command injection.
4. **Traffic protection:** Checks rate limits and repeated requests.
5. **Decision:** Allows or blocks requests according to the protection logic.
6. **Logging and alerts:** Records security events for analysis.
7. **Dashboard:** Displays available security statistics.

*Note: Verify the exact runtime flow against the source code before final submission.*
