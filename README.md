# SentinelShield

**Advanced Intrusion Detection & Web Protection System**

SentinelShield is a Python-based defensive security system for detecting suspicious web requests, applying traffic protection, generating security logs and alerts, and providing a local security dashboard.

## Features

- SQL Injection detection
- XSS detection
- Path Traversal detection
- LFI detection
- Command Injection pattern detection
- Request rate limiting
- Repeated request detection
- Temporary IP blocking
- Security event logging
- Security alerts
- Local security dashboard

## Architecture

Incoming HTTP Request -> Detection Engine -> Traffic Protection -> ALLOW/BLOCK -> Security Logs -> Alerts -> Dashboard

## Detection Categories

| Category | Severity |
|---|---|
| SQL Injection | High |
| XSS | High |
| Path Traversal | High |
| LFI | Critical |
| Command Injection | Critical |

## Technology Stack

- Python 3
- Regular Expressions
- JSON logging
- HTML/CSS
- Git
- Kali Linux

## Testing

Controlled local tests were performed for detection, traffic protection, logging, alerts, dashboard statistics, and detection/protection integration.

## Project Goal

The goal of SentinelShield is to demonstrate practical defensive cybersecurity concepts including threat detection, request protection, logging, alerting, and security monitoring.

## Disclaimer

SentinelShield is intended for defensive security learning, development, and authorized testing environments only.
