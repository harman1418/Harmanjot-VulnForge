# VulnForge - Autonomous AI Penetration Testing Platform

**Student Name:** Harmanjot Singh  
**University Roll No:** 2232100  
**Department:** B. Tech (CSE)  
**Status:** 🟢 LIVE & CLOUD HOSTED (24/7)

> [!IMPORTANT]
> **NOTE TO EVALUATORS**
> Because this project is built using a modern, scalable cloud microservice architecture, the backend is currently deployed and running live on a Microsoft Azure Virtual Machine. Therefore, it cannot be executed offline locally from this disk.

## Evaluation Resources

### 1. Video Demonstration
Please watch `01_VulnForge_Live_Demo.mp4` for a complete walkthrough of the UI, authentication, scanning capabilities, and backend server proof. 

*(Note: Due to GitHub's file size limits, the video file may be provided separately via Google Drive or YouTube link if you are viewing this on GitHub).*

### 2. Live Project Links
- **Frontend Application:** [https://vulnforge.app](https://vulnforge.app)
- **Backend API Endpoint:** [http://20.205.28.98:8000/docs](http://20.205.28.98:8000/docs)

### 3. API Documentation
You can view the full API documentation by opening the included file:
`03_VulnForge_API_Documentation.html`

### 4. Source Code
The complete original source code for both the frontend (React) and backend (FastAPI/Python) is included in the `SourceCode` directory on this repository.

---

## Project Architecture & Source Code

### Frontend Architecture
- **Tech Stack:** React, Vite, Vanilla CSS
- **Description:** A highly responsive, modern UI with dark/light mode, real-time scan updates, and dynamic routing.

```text
VulnForge_Frontend/
├── public/                # Static assets (images, icons)
├── src/
│   ├── assets/            # Local media and static files
│   ├── components/        # Reusable UI elements
│   │   ├── GenerateReportModal.jsx # Dynamic reporting modal
│   │   ├── MatrixBackground.jsx    # Hacker-style animated background
│   │   ├── Navbar.jsx              # Main navigation and tools dropdown
│   │   ├── ThemeToggle.jsx         # Dark/Light mode switcher
│   │   └── (10+ other components)
│   ├── config/            # Application configuration
│   ├── context/           # React context for global state (Auth, Theme)
│   ├── hooks/             # Custom React hooks
│   ├── pages/             # Core application views
│   │   ├── CryptoLab.jsx  # Offline encoding/hashing tools
│   │   ├── Dashboard.jsx  # User metrics and recent scans
│   │   ├── ScanReport.jsx # Deep dive vulnerability results page
│   │   ├── Targets.jsx    # Target management system
│   │   ├── ToolRunner.jsx # Execution interface for 15+ scanners
│   │   └── (10+ other views including Auth, Landing, etc.)
│   ├── styles/            # SCSS/CSS modules
│   ├── types/             # TypeScript definitions
│   ├── utils/             # Helper logic (apiClient.ts, api.js)
│   ├── index.css          # Global design system & custom styling
│   ├── App.jsx            # Main application router
│   └── main.jsx           # React entry point
├── index.html             # Base HTML template
├── package.json           # Node.js dependencies
└── vite.config.js         # Build tool configuration
```

### Backend Architecture
- **Tech Stack:** Python, FastAPI, Uvicorn, Systemd (Azure VM)
- **Description:** A modular microservices backend handling authentication, API routing, asynchronous scanning tools, and AI-powered report generation.

```text
VulnForge_Backend/
├── main.py                # Core FastAPI application & server config
├── routers/               # API Endpoints (Microservices)
│   ├── api_scan.py        # API discovery scanner
│   ├── auth.py            # JWT and OAuth authentication
│   ├── clickjacking.py    # UI redress vulnerability scanner
│   ├── cookie_check.py    # Secure cookie validation
│   ├── cors_check.py      # Cross-Origin Resource Sharing scanner
│   ├── dns_brute.py       # DNS bruteforcing tool
│   ├── fullscan.py        # Automated comprehensive scan initiator
│   ├── gobuster_scan.py   # Directory and file fuzzing
│   ├── nuclei_scan.py     # CVE & vulnerability template scanner
│   ├── portscan.py        # Nmap-powered open port enumeration
│   ├── report_generator.py# HTML/PDF executive summary generator
│   ├── sqli.py            # SQL Injection vulnerability scanner
│   ├── ssl_scan.py        # SSL/TLS certificate validation
│   ├── subdomain.py       # Subdomain enumeration tool
│   ├── xss.py             # Cross-Site Scripting scanner
│   └── ... (and many more modular scanners)
├── utils/                 # Helper functions & core logic
│   ├── ai_analyzer.py     # LLM integration for executive summaries
│   ├── cve_db.py          # Vulnerability database integrations
│   └── report_templates/  # HTML templates for final audit reports
├── clear_users.py         # Database utility script
├── factory_reset.py       # System reset utility
└── requirements.txt       # Python dependencies
```

---
**Thank you for reviewing VulnForge!**
