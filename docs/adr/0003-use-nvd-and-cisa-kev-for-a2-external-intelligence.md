# Use NVD and CISA KEV for A2 External Intelligence

InfraRisk Analyzer will use the authenticated NVD CVE API to retrieve normalized vulnerability details for an Operator-provided CVE Identifier and will scrape CISA's public Known Exploited Vulnerabilities catalog for matching exploitation and remediation evidence. This pair keeps A2 centered on Change-Risk Review, satisfies the distinct API and HTML-source requirements, and separates source facts from the Operator's Risk Level; a Known Exploited Vulnerability is a high-risk signal, never an automatic approval or block.
