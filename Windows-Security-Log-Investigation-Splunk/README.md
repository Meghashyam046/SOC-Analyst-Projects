# Windows Security Log Investigation & Brute-Force Detection using Splunk

## Objective

Analyze Windows Security Event Logs using Splunk to identify
suspicious authentication activity, failed logins, potential
brute-force behavior, privileged activity, process creation,
and other security events.

## Dataset

The project uses simulated Windows security logs for
educational and SOC investigation purposes.

## Tools Used

- Splunk Enterprise
- SPL
- Windows Security Logs
- CSV
- GitHub

## Key Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |
| 4720 | User Account Created |
| 4728 | User Added to Global Group |
| 4732 | User Added to Local Group |
| 7045 | New Service Installed |

## Investigation Activities

- Windows log ingestion
- Event ID analysis
- Failed login investigation
- Source IP analysis
- User account analysis
- Potential brute-force detection
- Successful login analysis
- Authentication correlation
- Malicious event investigation
- Process analysis
- Privileged activity analysis
- New account investigation
- New service investigation
- Splunk dashboard creation

## Detection Example

```spl
index=windows_logs event_id=4625
| stats count by source_ip user
| where count >= 10
| sort -count
