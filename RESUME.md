# Professional Resume

## Summary

Cybersecurity professional with expertise in threat detection, security monitoring, and automation frameworks. Proven track record in developing enterprise-grade detection systems and threat intelligence pipelines.

---

## Key Projects

### CUSTOM_LOGGERS - Unified PowerShell Detection Framework

**Overview:** A comprehensive PowerShell-based security monitoring framework that centralizes detection and logging for Windows environments by mapping system events to the MITRE ATT&CK framework.

**What it Accomplishes:**
- Provides real-time detection and logging of adversarial tactics across all stages of the attack lifecycle
- Centralizes security telemetry from Windows Event Logs, Sysmon, and Security logs into standardized, technique-tagged output
- Enables security teams to rapidly identify and respond to threats using industry-standard ATT&CK mappings

**Primary Technologies:**
- PowerShell 3.0+ (compatible with Windows Server 2012 and later)
- Sysmon for advanced system event monitoring
- Windows Event Log APIs (Get-WinEvent)
- WMI (Windows Management Instrumentation) for fallback detection

**Practical Relevance:**
This framework addresses a critical gap in enterprise security monitoring by providing a lightweight, deployable solution that doesn't require expensive SIEM infrastructure. Organizations can immediately begin collecting ATT&CK-mapped security telemetry suitable for threat hunting, incident response, and compliance reporting. The modular architecture allows security teams to deploy only the detection capabilities they need, reducing noise while maintaining comprehensive coverage.

**Key Features:**
- Modular monitors for each MITRE ATT&CK tactic (Execution, Persistence, Credential Access, Discovery, Lateral Movement, Defense Evasion, Initial Access, Command & Control, Impact)
- Sliding time-window polling to prevent duplicate event processing
- Configurable log levels and refresh intervals
- Technique-specific counters for analytics and reporting
- SIEM-ready log format with pipe-delimited fields
- Graceful shutdown with automatic summary generation

---

### optimized_threat_int_engine - Threat Intelligence Processing Pipeline

**Overview:** An advanced threat intelligence engine that builds actionable insights from Indicators of Compromise (IOCs) while implementing intelligent deletion safety mechanisms.

**What it Accomplishes:**
- Processes and enriches IOC data from multiple threat intelligence sources
- Provides contextual analysis to determine the risk and actionability of threat indicators
- Implements safe deletion pipelines that prevent accidental removal of critical threat intelligence

**Primary Technologies:**
- Python for core processing engine
- RESTful APIs for threat intelligence feed integration
- Database systems for IOC storage and relationship mapping
- Machine learning models for IOC scoring and prioritization

**Practical Relevance:**
Security operations centers (SOCs) are often overwhelmed with threat intelligence data, much of which is outdated, irrelevant, or of unknown quality. This engine solves the "IOC overload" problem by intelligently processing indicators, providing context, and safely managing their lifecycle. The deletion safety pipeline ensures that teams can confidently prune their threat intelligence databases without risking the removal of active, relevant indicators. This results in faster threat detection, reduced false positives, and more efficient security operations.

**Key Features:**
- Automated IOC ingestion from multiple threat feeds
- Contextual enrichment with OSINT and commercial threat intelligence
- Confidence scoring and age-based relevance assessment
- Deletion safety checks that verify IOC usage before removal
- Integration-ready APIs for SIEM and security orchestration platforms
- Audit trails for all IOC lifecycle events

---

## Education

### Bachelor of Science in Computer Science
**Institution:** [University Name]  
**Graduation Year:** [Year]  
**Relevant Coursework:** Network Security, Operating Systems, Database Systems, Software Engineering

### Professional Certifications
- **Certified Information Systems Security Professional (CISSP)** - [Year]
- **GIAC Security Essentials (GSEC)** - [Year]
- **Microsoft Certified: Azure Security Engineer Associate** - [Year]

*Note: Specific institution names, years, and certifications should be updated with actual credentials.*

---

## Technical Skills

**Security Technologies:** MITRE ATT&CK, Sysmon, Windows Event Logging, SIEM Integration, Threat Intelligence Platforms, Incident Response Tools

**Programming Languages:** PowerShell, Python, Bash, SQL

**Operating Systems:** Windows Server (2012+), Windows 10/11, Linux (Ubuntu, CentOS)

**Tools & Frameworks:** Git, RESTful APIs, JSON/XML processing, WMI, ETW (Event Tracing for Windows)

---

## Contact Information

**Email:** [your.email@domain.com]  
**LinkedIn:** [linkedin.com/in/yourprofile]  
**GitHub:** [github.com/yourusername]

---

*Last Updated: February 2026*
