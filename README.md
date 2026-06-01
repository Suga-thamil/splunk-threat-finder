# Splunk Threat Finder v2.0

## Overview

Splunk Threat Finder is a Python-based cybersecurity threat analysis tool designed to detect suspicious activity from log data and generate analyst-friendly incident reports.

The project simulates Security Operations Center (SOC) workflows by identifying common attack techniques, extracting Indicators of Compromise (IOCs), mapping detections to MITRE ATT&CK techniques, and producing investigation guidance.

---

## Features

### Threat Detection

* Brute Force Followed by Successful Login
* Password Spraying Detection
* PowerShell Execution Detection
* Known Malicious IP Detection

### Threat Analysis

* MITRE ATT&CK Mapping
* IOC Extraction
* Risk Scoring
* Severity Classification
* Priority Classification (P1–P4)

### Reporting

* Executive Summary
* Threat Statistics
* Severity Distribution
* Priority Distribution
* Analyst Verdict
* IOC Summary
* Timeline Reconstruction
* Investigation Playbooks

---

## MITRE ATT&CK Techniques

| Technique ID | Technique              |
| ------------ | ---------------------- |
| T1110        | Brute Force            |
| T1110.003    | Password Spraying      |
| T1059.001    | PowerShell             |
| T1583        | Acquire Infrastructure |

---

## Sample Detections

### Brute Force Attack

The tool detects multiple failed login attempts followed by a successful login from the same IP address.

### Password Spraying

The tool identifies a single IP address attempting authentication against multiple user accounts.

### PowerShell Execution

The tool flags PowerShell execution events for analyst review.

### Known Malicious IP

The tool compares source IP addresses against a threat intelligence list and generates alerts for matches.

---

## Output Example

The generated report includes:

* Executive Summary
* Threat Statistics
* Severity Distribution
* Priority Distribution
* Incident Summary
* IOC Summary
* Timeline
* Threat Findings
* Investigation Playbooks

---

## Technologies Used

* Python
* CSV Log Analysis
* Splunk Enterprise
* SPL (Search Processing Language)
* MITRE ATT&CK Framework

---

## Validation in Splunk

The detections were validated using Splunk Enterprise by:

* Importing sample log datasets
* Running SPL searches
* Reconstructing attack timelines
* Performing IOC analysis
* Investigating ransomware-style activity

---

## Future Improvements

* HTML Dashboard Reporting
* Windows Event Log Support
* Automated Splunk Alert Generation
* Threat Intelligence API Integration
* Advanced Behavioral Analytics

---

## Author

Cybersecurity Student Project

Built to learn SOC operations, threat detection, incident response, and Splunk investigation workflows.

