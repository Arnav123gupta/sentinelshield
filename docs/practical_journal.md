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

### Verification Performed
- Automated test suite: 72 tests passed in 0.39 seconds during final verification.
- Safe local home request: HTTP 200; response status was `allowed`.
- Controlled SQL injection test against the local application: HTTP 403; response status was `blocked`.
- Dashboard HTML was regenerated using the current security logs.
- `git diff --check` completed without whitespace errors after dashboard cleanup.

### Evidence Records
Text outputs were saved under `reports/`, including:
- `pytest-results.txt`
- `local-verification.txt`
- `safe-response.json`
- `blocked-response.json`
- `app-runtime.log`

### Interpretation
The observed requests behaved as expected in these controlled checks, and the automated suite passed. These results support the prototype's intended behavior for the tested cases; they do not establish comprehensive real-world detection accuracy.

### Limitations and Recommendations
- Only the recorded test cases and automated suite outcomes are claimed here.
- False-positive and false-negative rates have not been measured using a comprehensive labelled dataset.
- The rule-based detector may miss variants outside its configured patterns.
- Capture and review the requested screenshots before final submission.
- Keep testing restricted to systems that are owned by the tester or explicitly authorized.
