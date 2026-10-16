# SentinelShield — Practical Journal

## 1. Project Objective
To build and evaluate a local Python-based defensive web request protection prototype that detects configured suspicious patterns, applies traffic controls, records security events and presents security information through a dashboard.

## 2. Environment and Tools
- Operating system: Kali Linux
- Language: Python
- Web framework: Flask
- Testing: pytest
- Version control: Git
- Test environment: Local application and automated tests

## 3. Main Components
- HTTP request model
- Rule-based detection engine
- Request protection and traffic controls
- Security event and alert logging
- Dashboard statistics and interface

## 4. Detection Rules
The configured detector checks for:
- SQL injection patterns
- Cross-site scripting (XSS) patterns
- Path traversal patterns
- Local file inclusion (LFI) patterns
- Command injection patterns

The detector inspects request paths, query parameter values, headers and request bodies. Detection is signature-based and may miss patterns that are not covered by configured rules.

## 5. Initial Controlled Test Results
A manual detector test set contained nine cases:
- Safe home request: ALLOW — PASS
- Safe search request: ALLOW — PASS
- SQL injection pattern: BLOCK — PASS
- XSS pattern: BLOCK — PASS
- Path traversal pattern: BLOCK — PASS
- LFI pattern: BLOCK — PASS
- Command injection pattern: BLOCK — PASS
- XSS pattern in a request header: BLOCK — PASS
- XSS pattern in a request body: BLOCK — PASS

Result: 9 of 9 expected outcomes matched in this initial test set. This is not a general detection-accuracy percentage.

## 6. Automated Test Results
The project test suite reported 72 passed tests. Record the date and final output when collecting submission evidence.

## 7. Evidence to Collect
- Screenshot of the project running locally
- Screenshot showing the automated test summary
- Screenshot of a safe request being allowed
- Screenshot of a controlled suspicious request being blocked
- Screenshot of relevant security event logs
- Screenshot of the dashboard

## 8. Limitations
- Detection depends on the configured regular-expression rules.
- Passing tests does not prove detection of every possible attack.
- False-positive and false-negative rates have not yet been established using a comprehensive labelled dataset.
- This prototype is for authorized local testing and learning, not a production security guarantee.

## 9. Final Analysis
Complete this section after collecting and reviewing the final evidence. Record the test cases performed, expected and actual outcomes, any false positives or false negatives, and practical recommendations. Do not invent results.
