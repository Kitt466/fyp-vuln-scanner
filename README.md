# Automated Vulnerability Scanner

## Final Year Project (FYP)

## Overview
This project is an automated vulnerability scanner that detects open ports, identifies running services, maps service versions to known CVEs, and generates structured security reports.

## Features
- Port scanning
- Service detection
- CVE lookup using NVD API
- Risk scoring system
- GUI interface
- PDF/HTML report generation

## Architecture
The system is divided into:
- GUI Layer
- Core Scanning Engine
- CVE Analysis Module
- Reporting Module

## Tech Stack
- Python
- Nmap
- PySide6 / Tkinter
- NVD CVE API
- ReportLab

## Usage
```bash
python main.py
