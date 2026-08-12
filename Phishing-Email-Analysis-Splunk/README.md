# Phishing Email Analysis & Investigation using Splunk

## Objective

Investigate email security logs using Splunk to identify
potential phishing and malicious email activity.

## Tools Used

- Splunk Enterprise
- SPL (Search Processing Language)
- CSV
- GitHub

## Investigation Process

1. Ingested email security logs into Splunk
2. Verified the ingested events
3. Classified emails as Normal or Malicious
4. Investigated high spam-score emails
5. Analyzed suspicious senders
6. Investigated source IP addresses
7. Analyzed email attachments
8. Reviewed email security actions
9. Created a Splunk investigation dashboard

## Detection Queries

### Malicious Email Detection

spl
source="email_logs.csv" host="shyam" sourcetype="csv" category="MALICIOUS"

##High Spam Score
source="email_logs.csv" host="shyam" sourcetype="csv" spam_score>=8
| table timestamp sender recipient subject attachment spam_score src_ip category

##Suspicious Senders
source="email_logs.csv" host="shyam" sourcetype="csv" category="MALICIOUS"
| stats count by sender
| sort -count

##Source IP Investigation
source="email_logs.csv" host="shyam" sourcetype="csv" category="MALICIOUS"
| stats count by src_ip
| sort -count

##Attachment Analysis
source="email_logs.csv" host="shyam" sourcetype="csv" category="MALICIOUS"
| stats count by attachment
| sort -count
