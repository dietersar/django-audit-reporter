# django-audit-reporter

Audits Django projects for vulnerable and outdated dependencies, generates HTML and text reports, and emails a consolidated summary.

## Overview

This repository contains a small audit package for reviewing multiple Django projects from a single configuration.

It includes:

- `django_audit.py` – main audit engine
- `django_audit.sh` – shell wrapper that loads the environment and runs the Python script
- `django_audit.json.example` – example JSON configuration
- `django_audit.env.example` – example environment configuration

## Features

- Audit multiple Django projects
- Check Python dependency vulnerabilities using `pip-audit`
- Audit installed Python packages from project virtual environments
- Detect Python version declaration files
- Check Python release support status using endoflife.date
- Optionally audit frontend npm dependencies
- Optionally report outdated frontend npm packages
- Generate both HTML and text reports
- Send reports by email via SMTP
- Support dry-run execution

## Requirements

- Linux
- Python 3
- `pip-audit` installed in the audit virtual environment
- SMTP server access
- Optional: Node/NPM for frontend audits

## Files

- `django_audit.py` – main script
- `django_audit.sh` – launcher script
- `django_audit.json.example` – sample config
- `django_audit.env.example` – sample environment file

## Environment configuration

Example:

```env
BASE_DIR=/home/youruser/djangodev
AUDIT_VENV=/home/youruser/djangodev/scripts/.audit-venv
AUDIT_PYTHON=/home/youruser/djangodev/scripts/.audit-venv/bin/python

NVM_DIR=/home/youruser/.nvm
EXTRA_PATH=/home/youruser/.nvm/versions/node/vXX.XX.X/bin:/usr/local/bin:/usr/bin:/bin
