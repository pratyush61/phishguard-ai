 # PhishGuard AI

### Automated Email Phishing Detection, Risk Analysis & Protection

PhishGuard AI is an intelligent email security system that detects phishing attempts using machine learning, URL reputation analysis, and an explainable risk-scoring engine.

Connect your Gmail account, scan incoming emails, identify suspicious links, analyze message content, and monitor potential threats through an interactive Flask dashboard.

## Features

- Machine Learning-Based Email Classification
- URL Reputation Analysis using VirusTotal API
- Intelligent Risk Scoring Engine
- Gmail Integration through IMAP
- Optional Email Quarantine
- Automated Security Alerts through SMTP
- Interactive Flask Dashboard
- Scheduled Email Scanning
- SQLite Database Logging
- Docker Support

## Tech Stack

- Python
- Flask
- Scikit-learn
- TF-IDF
- SQLite
- Gmail IMAP / SMTP
- VirusTotal API
- APScheduler
- Pytest
- Docker

## Getting Started

### Prerequisites

- Python 3
- pip
- Git
- Gmail account (optional)
- VirusTotal API key (optional)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/pratyush61/phishguard-ai.git
cd phishguard-ai