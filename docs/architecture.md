# SentinelShield Architecture

## Request Protection Flow

```mermaid
flowchart TD
    A[Incoming HTTP Request] --> B[Flask Request Parsing]
    B --> C[Build HTTPRequest Model]
    C --> D[Rule-Based Detection]
    D --> E{Suspicious Pattern Detected?}

    E -->|Yes| F[Log Detection]
    F --> G[BLOCK: HTTP 403]

    E -->|No| H[ProtectionManager]
    H --> I{IP Already Blocked?}
    I -->|Yes| J[BLOCK]
    I -->|No| K[Rate Limiter]

    K --> L{Rate Limit Exceeded?}
    L -->|Yes| M[Block Client IP]
    L -->|No| N[Repeat Detector]

    N --> O{Repeat Threshold Exceeded?}
    O -->|Yes| M
    O -->|No| P[ALLOW: HTTP 200]

    M --> Q[Log Protection Block]
    Q --> J

    G --> R[Security Event Log]
    J --> R
    P --> S[Allowed Response]
    R --> T[Dashboard Statistics]
    T --> U[Security Dashboard]
