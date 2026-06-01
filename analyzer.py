"""
Splunk Threat Finder v2.0

Author: Suga-thamil

Detects:
- Brute Force Attacks
- Password Spraying
- PowerShell Execution
- Known Malicious IP Activity
"""
import csv
import sys
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 5
REPORT_FILE = "report.txt"


FIELD_ALIASES = {
    "time": ["_time", "time", "timestamp", "date"],
    "user": ["user", "username", "account", "Account_Name", "TargetUserName"],
    "src_ip": ["src_ip", "src", "source_ip", "Source_Network_Address", "client_ip", "ip"],
    "action": ["action", "status", "result", "login_status"],
    "event_type": ["event_type", "type", "category", "EventType"],
    "process": ["process", "process_name", "New_Process_Name", "Image", "CommandLine"],
}


def get_value(row, field_name):
    for name in FIELD_ALIASES[field_name]:
        if name in row and row[name]:
            return row[name]
    return ""


def normalize_log(row):
    return {
        "time": get_value(row, "time"),
        "user": get_value(row, "user"),
        "src_ip": get_value(row, "src_ip"),
        "action": get_value(row, "action").lower(),
        "event_type": get_value(row, "event_type").lower(),
        "process": get_value(row, "process").lower(),
    }


def read_logs(filename):
    logs = []

    with open(filename, "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            logs.append(normalize_log(row))

    return logs

def load_malicious_ips():

    malicious_ips = set()

    with open("malicious_ips.csv", "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            malicious_ips.add(row["ip"])

    return malicious_ips

def calculate_severity(failed_attempts):
    if failed_attempts >= 20:
        return "CRITICAL"
    elif failed_attempts >= 10:
        return "HIGH"
    else:
        return "MEDIUM"


def calculate_confidence(failed_attempts):
    if failed_attempts >= 20:
        return 95
    elif failed_attempts >= 10:
        return 85
    else:
        return 70


def is_failed_login(log):
    return (
        "login" in log["event_type"]
        and log["action"] in ["failure", "failed", "fail", "denied"]
    )


def is_successful_login(log):
    return (
        "login" in log["event_type"]
        and log["action"] in ["success", "successful", "allowed"]
    )


def detect_bruteforce(logs):
    failed_logins = defaultdict(int)

    for log in logs:
        if is_failed_login(log):
            key = (log["user"], log["src_ip"])
            failed_logins[key] += 1

    return failed_logins


def build_threat_story(user, src_ip, failed_attempts):
    severity = calculate_severity(failed_attempts)
    confidence = calculate_confidence(failed_attempts)

    return f"""
=== THREAT STORY ===
User '{user}' experienced {failed_attempts} failed login attempts from {src_ip}.
A successful login occurred afterward from the same IP address.

This pattern is commonly associated with brute-force attacks.

Risk Level: {severity}
Confidence: {confidence}%
Risk: Potential account compromise.

Recommended Investigation:
1. Review activity after login.
2. Verify MFA status.
3. Determine whether the IP is trusted.
"""


def detect_account_compromise(failed_logins, logs):
    findings = []
    successful_logins = []

    for log in logs:
        if is_successful_login(log):
            successful_logins.append((log["user"], log["src_ip"]))

    for key, count in failed_logins.items():
        if count >= FAILED_LOGIN_THRESHOLD and key in successful_logins:
            user, src_ip = key
            severity = calculate_severity(count)
            confidence = calculate_confidence(count)
            
            priority = calculate_priority(severity,confidence)

            story = build_threat_story(user, src_ip, count)

            finding = f"""
{story}
=== THREAT FINDING ===
Detection Type: Brute Force Followed by Successful Login
Severity: {severity}
Confidence: {confidence}%
Priority:  {priority}
MITRE ATT&CK: T1110
Technique: Brute Force
User: {user}
Source IP: {src_ip}
Reason: Multiple failed logins followed by successful login.
Recommended Next Step: Review user activity after the successful login.
Suggested SPL Query:
index=* user="{user}" src_ip="{src_ip}"
"""
            findings.append(finding)

    return findings


def detect_powershell(logs):
    findings = []

    priority = "P4"

    for log in logs:
        if "powershell" in log["process"]:

            finding = f"""
=== THREAT FINDING ===
Detection Type: PowerShell Execution
Severity: MEDIUM
Priority: {priority}
MITRE ATT&CK: T1059.001
Technique: PowerShell
User: {log["user"]}
Source IP: {log["src_ip"]}
Process: {log["process"]}
Reason: PowerShell is frequently abused by attackers.
Recommended Next Step: Review command-line arguments and parent process.
"""

            findings.append(finding)

    return findings


def detect_password_spraying(logs):

    findings = []
    ip_to_users = defaultdict(set)

    severity = "HIGH"
    confidence = 85

    priority = calculate_priority(severity,confidence)
    
    for log in logs:
        if is_failed_login(log):
            ip_to_users[log["src_ip"]].add(log["user"])

    for src_ip, users in ip_to_users.items():

        if len(users) >= 3:

            finding = f"""
=== THREAT FINDING ===
Detection Type: Possible Password Spraying
Severity: {severity}
Confidence: {confidence}%
Priority: {priority}
MITRE ATT&CK: T1110.003
Technique: Password Spraying
Source IP: {src_ip}
Targeted Users: {", ".join(users)}
Reason: One source IP attempted failed logins against multiple user accounts.
Recommended Next Step: Check whether this IP is external, blocked, or associated with known attack activity.
Suggested SPL Query:
index=* src_ip="{src_ip}" action=failure
"""

            findings.append(finding)

    return findings


def detect_malicious_ip(logs):

    findings = []

    malicious_ips = load_malicious_ips()
    seen_ips = set()

    for log in logs:

        src_ip = log["src_ip"]

        if src_ip in malicious_ips and src_ip not in seen_ips:

            severity = "HIGH"
            confidence = 95

            priority = calculate_priority(severity,confidence)

            finding = f"""
=== THREAT FINDING ===
Detection Type: Known Malicious IP
Severity: {severity}
Confidence: {confidence}%
Priority: {priority}
MITRE ATT&CK: T1583
Technique: Acquire Infrastructure

Source IP: {src_ip}

Reason:
IP found in threat intelligence database.

Recommended Next Step:
Block and investigate immediately.

Suggested SPL Query:
index=* src_ip="{src_ip}"
"""

            findings.append(finding)
           
            seen_ips.add(src_ip)

    return findings


def calculate_threat_score(findings):
    score = 0

    for finding in findings:
        if "Brute Force Followed by Successful Login" in finding:
            score += 25

        if "PowerShell Execution" in finding:
            score += 15

        if "Possible Password Spraying" in finding:
            score += 20

        if "Known Malicious IP" in finding:
            score += 25

    if score > 100:
        score = 100

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


def calculate_incident_summary(findings):
    total = len(findings)

    high_count = 0
    medium_count = 0
    critical_count = 0

    for finding in findings:
        if "Severity: CRITICAL" in finding:
            critical_count += 1
        elif "Severity: HIGH" in finding:
            high_count += 1
        elif "Severity: MEDIUM" in finding:
            medium_count += 1

    risk_score, threat_score_severity = calculate_threat_score(findings)

    if risk_score >= 80:
        overall_severity = "CRITICAL"
        recommendation = "Immediate investigation required."
    elif risk_score >= 50:
        overall_severity = "HIGH"
        recommendation = "Prioritize investigation soon."
    elif risk_score >= 20:
        overall_severity = "MEDIUM"
        recommendation = "Review findings and validate suspicious activity."
    else:
        overall_severity = "LOW"
        recommendation = "Monitor activity."

    return {
        "total": total,
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "risk_score": risk_score,
        "overall_severity": overall_severity,
        "recommendation": recommendation,
    }


def calculate_priority(severity, confidence):

    if severity == "HIGH" and confidence >= 90:
        return "P1"

    elif severity == "HIGH":
        return "P2"

    elif severity == "MEDIUM":
        return "P3"

    else:
        return "P4"


def extract_ioc_summary(findings):
    users = set()
    ips = set()
    processes = set()
    mitre_techniques = set()

    for finding in findings:
        for line in finding.splitlines():
            line = line.strip()

            if line.startswith("User:"):
                users.add(line.replace("User:", "").strip())

            elif line.startswith("Source IP:"):
                ips.add(line.replace("Source IP:", "").strip())

            elif line.startswith("Process:"):
                processes.add(line.replace("Process:", "").strip())

            elif line.startswith("MITRE ATT&CK:"):
                mitre_techniques.add(line.replace("MITRE ATT&CK:", "").strip())

    return {
        "users": sorted(users),
        "ips": sorted(ips),
        "processes": sorted(processes),
        "mitre_techniques": sorted(mitre_techniques),
    }


def generate_timeline(logs):

    timeline = []

    for log in logs:

        timestamp = log["time"]
        user = log["user"]
        action = log["action"]
        event_type = log["event_type"]

        if event_type == "login":

            timeline.append(
                f"{timestamp} | {user} | login {action}"
            )

        elif event_type == "process":

            timeline.append(
                f"{timestamp} | {user} | {log['process']}"
            )

    return timeline


def generate_analyst_verdict(findings):
    critical_count = 0
    high_count = 0
    medium_count = 0

    detected_types = []

    for finding in findings:
        if "Severity: CRITICAL" in finding:
            critical_count += 1
        elif "Severity: HIGH" in finding:
            high_count += 1
        elif "Severity: MEDIUM" in finding:
            medium_count += 1

        for line in finding.splitlines():
            if line.startswith("Detection Type:"):
                detected_types.append(line.replace("Detection Type:", "").strip())

    if critical_count > 0:
        assessment = "Active Threat Detected"
        priority = "CRITICAL"
        action = "Immediate investigation required."
    elif high_count > 0:
        assessment = "Suspicious Activity Confirmed"
        priority = "HIGH"
        action = "Investigate as soon as possible."
    elif medium_count > 0:
        assessment = "Investigation Recommended"
        priority = "MEDIUM"
        action = "Review findings and validate suspicious activity."
    else:
        assessment = "No Significant Threats Found"
        priority = "LOW"
        action = "Continue monitoring."

    return {
        "assessment": assessment,
        "priority": priority,
        "action": action,
        "detected_types": detected_types,
    }


def generate_playbook(detection_type):

    playbook = []

    if detection_type == "Brute Force Followed by Successful Login":

        playbook = [
            "Review all activity from the source IP.",
            "Review processes executed by the user.",
            "Verify MFA status.",
            "Check for privilege escalation.",
            "Determine whether the login was expected."
        ]

    elif detection_type == "PowerShell Execution":

        playbook = [
            "Review command-line arguments.",
            "Identify parent process.",
            "Check network connections.",
            "Determine whether the script is signed.",
            "Review recent PowerShell history."
        ]

    elif detection_type == "Possible Password Spraying":

        playbook = [
            "Check if the source IP is external.",
            "Review firewall logs.",
            "Identify all affected users.",
            "Check for successful logins afterward.",
            "Force password resets if necessary."
        ]

    elif detection_type == "Known Malicious IP":

        playbook = [
            "Immediately investigate the IP.",
            "Review all events involving the IP.",
            "Check firewall and proxy logs.",
            "Determine affected systems.",
            "Block the IP if confirmed malicious."
        ]

    return playbook


def generate_executive_summary(findings, iocs):
    p1_count = 0
    p2_count = 0
    p3_count = 0
    p4_count = 0

    top_threat = "None"

    for finding in findings:
        if "Priority: P1" in finding:
            p1_count += 1
            top_threat = "Known Malicious IP"
        elif "Priority: P2" in finding:
            p2_count += 1
        elif "Priority: P3" in finding:
            p3_count += 1
        elif "Priority: P4" in finding:
            p4_count += 1

    most_suspicious_ip = "None"

    if iocs["ips"]:
        most_suspicious_ip = iocs["ips"][-1]

    return {
        "p1": p1_count,
        "p2": p2_count,
        "p3": p3_count,
        "p4": p4_count,
        "top_threat": top_threat,
        "most_suspicious_ip": most_suspicious_ip,
    }


def generate_threat_statistics(findings):
    stats = {
        "Brute Force": 0,
        "PowerShell": 0,
        "Password Spraying": 0,
        "Malicious IP": 0
    }

    for finding in findings:

        if "Brute Force Followed by Successful Login" in finding:
            stats["Brute Force"] += 1

        elif "PowerShell Execution" in finding:
            stats["PowerShell"] += 1

        elif "Possible Password Spraying" in finding:
            stats["Password Spraying"] += 1

        elif "Known Malicious IP" in finding:
            stats["Malicious IP"] += 1

    return stats


def generate_severity_distribution(findings):

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:

        if "Severity: CRITICAL" in finding:
            severity_counts["CRITICAL"] += 1

        elif "Severity: HIGH" in finding:
            severity_counts["HIGH"] += 1

        elif "Severity: MEDIUM" in finding:
            severity_counts["MEDIUM"] += 1

        elif "Severity: LOW" in finding:
            severity_counts["LOW"] += 1

    return severity_counts


def generate_priority_distribution(findings):

    priority_counts = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0
    }

    for finding in findings:

        if "Priority: P1" in finding:
            priority_counts["P1"] += 1

        elif "Priority: P2" in finding:
            priority_counts["P2"] += 1

        elif "Priority: P3" in finding:
            priority_counts["P3"] += 1

        elif "Priority: P4" in finding:
            priority_counts["P4"] += 1

    return priority_counts


def write_report(findings, logs):
    timeline = generate_timeline(logs)
    summary = calculate_incident_summary(findings)
    iocs = extract_ioc_summary(findings)
    verdict = generate_analyst_verdict(findings)
    executive_summary = generate_executive_summary(findings, iocs)
    threat_stats = generate_threat_statistics(findings)
    severity_stats = generate_severity_distribution(findings)
    priority_stats = generate_priority_distribution(findings)
   

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write("SPLUNK THREAT ANALYSIS REPORT\n")
        file.write("=" * 40 + "\n\n")
        
        file.write("EXECUTIVE SUMMARY\n")
        file.write("-" * 40 + "\n")
        file.write(f"P1 Alerts: {executive_summary['p1']}\n")
        file.write(f"P2 Alerts: {executive_summary['p2']}\n")
        file.write(f"P3 Alerts: {executive_summary['p3']}\n")
        file.write(f"P4 Alerts: {executive_summary['p4']}\n")
        file.write(f"Top Threat: {executive_summary['top_threat']}\n")
        file.write(f"Most Suspicious IP: {executive_summary['most_suspicious_ip']}\n")
        file.write("\n")

        file.write("THREAT STATISTICS\n")
        file.write("-" * 40 + "\n")

        file.write(
            f"Brute Force Events: "
            f"{threat_stats['Brute Force']}\n"
        )

        file.write(
            f"PowerShell Events: "
            f"{threat_stats['PowerShell']}\n"
        )

        file.write(
            f"Password Spraying Events: "
            f"{threat_stats['Password Spraying']}\n"
        )

        file.write(
            f"Malicious IP Events: "
            f"{threat_stats['Malicious IP']}\n"
        )

        file.write("\n")

        file.write("SEVERITY DISTRIBUTION\n")
        file.write("-" * 40 + "\n")

        file.write(
            f"Critical Alerts: "
            f"{severity_stats['CRITICAL']}\n"
        )

        file.write(
            f"High Alerts: "
            f"{severity_stats['HIGH']}\n"
        )

        file.write(
            f"Medium Alerts: "
            f"{severity_stats['MEDIUM']}\n"
        )

        file.write(
            f"Low Alerts: "
            f"{severity_stats['LOW']}\n"
        )

        file.write("\n")

        file.write("PRIORITY DISTRIBUTION\n")
        file.write("-" * 40 + "\n")

        file.write(
            f"P1 Alerts: "
            f"{priority_stats['P1']}\n"
        )

        file.write(
            f"P2 Alerts: "
            f"{priority_stats['P2']}\n"
        )

        file.write(
            f"P3 Alerts: "
            f"{priority_stats['P3']}\n"
        )

        file.write(
            f"P4 Alerts: "
            f"{priority_stats['P4']}\n"
        )

        file.write("\n")

        file.write("INCIDENT SUMMARY\n")
        file.write("-" * 40 + "\n")
        file.write(f"Total Findings: {summary['total']}\n")
        file.write(f"Critical Findings: {summary['critical']}\n")
        file.write(f"High Findings: {summary['high']}\n")
        file.write(f"Medium Findings: {summary['medium']}\n")
        file.write(f"Overall Risk Score: {summary['risk_score']}/100\n")
        file.write("Scoring Method: Detection-based threat scoring\n")
        file.write(f"Overall Incident Severity: {summary['overall_severity']}\n")
        file.write(f"Analyst Recommendation: {summary['recommendation']}\n\n")

        file.write("ANALYST VERDICT\n")
        file.write("-" * 40 + "\n")
        file.write(f"Overall Assessment: {verdict['assessment']}\n")
        file.write(f"Priority: {verdict['priority']}\n")
        file.write(f"Recommended Action: {verdict['action']}\n")

        file.write("Detected Threat Types:\n")
        for threat_type in verdict["detected_types"]:
         file.write(f"- {threat_type}\n")

        file.write("\n")

        file.write("IOC SUMMARY\n")
        file.write("-" * 40 + "\n")

        file.write("Users:\n")
        for user in iocs["users"]:
            file.write(f"- {user}\n")

        file.write("\nSource IPs:\n")
        for ip in iocs["ips"]:
            file.write(f"- {ip}\n")

        file.write("\nProcesses:\n")
        for process in iocs["processes"]:
            file.write(f"- {process}\n")

        file.write("\nMITRE Techniques:\n")
        for technique in iocs["mitre_techniques"]:
            file.write(f"- {technique}\n")

        file.write("\nTIMELINE\n")
        file.write("-" * 40 + "\n")

        for event in timeline:
            file.write(event + "\n")

        file.write("\n")

        if not findings:
            file.write("No suspicious activity found.\n")
        else:
            for number, finding in enumerate(findings, start=1):

                file.write(f"\nFinding #{number}\n")
                file.write("-" * 40 + "\n")
                file.write(finding)
                file.write("\n")

                detection_type = None

                for line in finding.split("\n"):
                    if "Detection Type:" in line:
                        detection_type = line.replace(
                            "Detection Type:",
                            ""
                        ).strip()
                        break

                if detection_type:

                    playbook = generate_playbook(detection_type)

                    file.write("\n")
                    file.write("INVESTIGATION PLAYBOOK\n")
                    file.write("-" * 40 + "\n")

                    for step_number, step in enumerate(playbook, start=1):
                        file.write(
                            f"Step {step_number}: {step}\n"
                        )

                    file.write("\n")

    print(f"Report created: {REPORT_FILE}")

    
def main():

    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "sample_logs.csv"

    logs = read_logs(filename)
    print(f"Analyzing file: {filename}")

    failed_logins = detect_bruteforce(logs)

    findings = []
    findings.extend(detect_account_compromise(failed_logins, logs))
    findings.extend(detect_powershell(logs))
    findings.extend(detect_password_spraying(logs))
    findings.extend(detect_malicious_ip(logs))

    write_report(findings, logs)


if __name__ == "__main__":
    main()
