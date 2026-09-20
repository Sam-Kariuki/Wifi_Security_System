# Wi-Fi Security Monitoring and Forensic Analysis for Unauthorized Device Detection

## Project Description

This project is a lightweight Wi-Fi security monitoring and forensic analysis prototype developed for a controlled senior school laboratory environment.

The system is designed to:

- Monitor observed network devices.
- Maintain an authorized-device registry.
- Identify potentially unauthorized devices.
- Generate and record security events.
- Prevent duplicate security events.
- Maintain historical device observations.
- Support security-event investigation.
- Provide a forensic timeline.
- Generate forensic security-event reports.
- Present monitoring information through a web dashboard.

## Project Objectives

The project aims to demonstrate how Wi-Fi device monitoring, security-event logging, and digital-forensics principles can be combined to support the investigation of unauthorized-device activity in a controlled school network environment.

## Technologies

- Python
- Flask
- SQLite
- HTML/CSS
- JavaScript
- Wireshark
- ReportLab

## Project Structure

- pp.py - Main Flask application
- monitor/ - Network device discovery
- database/ - Database functionality
- detection/ - Device authorization and detection
- security/ - Security-event logging
- Reports/ - Forensic report generation
- Templates/ - Web interface templates

## Privacy and Security

The project is designed for authorized and controlled testing.

Real network records, local databases, evaluation backups, generated reports, credentials, and other potentially sensitive information are excluded from the remote repository.

Unknown devices are treated as potentially unauthorized and require verification rather than being automatically classified as malicious.

## Development Status

The prototype has been functionally tested in a controlled laboratory environment.

## Research Context

Final-year Cybersecurity and Digital Forensics project.

