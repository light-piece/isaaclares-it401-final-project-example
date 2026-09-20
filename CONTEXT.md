# InfraRisk Analyzer Domain Context

InfraRisk Analyzer helps early-career IT operations staff reason about proposed infrastructure changes before they affect production systems. The project focuses on change risk, mitigations, review needs, and rollback readiness rather than automated approval.

## Language

**IT Change**:
A proposed modification to infrastructure, access, network behavior, application deployment, or system configuration.
_Avoid_: Task, ticket, update

**Change Risk**:
The chance that an IT Change could disrupt availability, weaken security, break connectivity, or create operational recovery problems.
_Avoid_: Danger score, severity

**Risk Level**:
A Low, Medium, or High classification that summarizes Change Risk for an IT Change. A Risk Level is a review aid, not an approval decision.
_Avoid_: Severity, score, priority

**Risk Finding**:
A specific concern discovered during review of an IT Change, such as missing rollback steps, broad access impact, or insufficient testing.
_Avoid_: Alert, issue, warning

**Mitigation**:
An action that reduces the likelihood or impact of a Risk Finding before the IT Change proceeds.
_Avoid_: Fix, recommendation, advice

**Affected System**:
The service, server, network segment, cloud resource, account group, or application touched by an IT Change.
_Avoid_: Asset, target, item

**Change Owner**:
The person or team responsible for preparing an IT Change and coordinating its review.
_Avoid_: Assignee, requester, user

**Change Ticket**:
The tracking identifier for an IT Change in a service desk, issue tracker, or change-management workflow.
_Avoid_: Case, issue, task

**Change Type**:
A category that describes the kind of IT Change being reviewed. Assignment 1 uses Firewall, DNS, Access, Patching, Deployment, and Server Config.
_Avoid_: Category, label

**Review Status**:
The current review state of an IT Change. Assignment 1 uses Draft, Needs Review, Ready for Window, and Blocked.
_Avoid_: Approval, progress, state

**Approval Record**:
A note that a required human review area, such as Network, Security, Systems, or App Owner, has a Pending or Signed Off status for an IT Change. An Approval Record is displayed as metadata; InfraRisk Analyzer does not grant approval authority.
_Avoid_: App approval, decision, permission

**Audit Trail**:
A short chronological record of important review events for an IT Change. Assignment 1 displays two or three concise events per change.
_Avoid_: History, log, activity feed

**Risk Signal**:
A condition that contributes to Change Risk, such as production impact, security exposure, missing rollback steps, or broad user impact.
_Avoid_: Factor, trigger, flag

**Scheduled Window**:
The planned time period when an IT Change is expected to be performed.
_Avoid_: Date, deadline, maintenance time

**Rollback Plan**:
The documented steps for restoring the prior working state if an IT Change causes unacceptable impact.
_Avoid_: Backup plan, undo steps

**Risk Summary**:
A plain-English explanation of the most important Change Risk, Risk Signals, and mitigations for an IT Change.
_Avoid_: AI answer, generated text, description

**Operator**:
The junior sysadmin, network-ops practitioner, or DevOps learner preparing or reviewing an IT Change.
_Avoid_: User, admin, engineer

**Change-Risk Review**:
The structured evaluation of an IT Change to identify Change Risk, required mitigations, review needs, and rollback readiness.
_Avoid_: Approval, audit, scan

**External Intelligence**:
Current, source-attributed information acquired from an external web source that informs a Change-Risk Review. It is distinct from the Operator's reviewed Risk Level.
_Avoid_: Live verdict, automated decision, real-time guarantee

**External Intelligence Snapshot**:
The timestamped External Intelligence retained with an IT Change to show the evidence available when its Change-Risk Review occurred.
_Avoid_: Current state, live record

**External Intelligence Review**:
A CVE-focused Change-Risk Review that relates source-attributed External Intelligence to one selected IT Change. It informs review without changing the IT Change's manually assigned Risk Level.
_Avoid_: Vulnerability scan, automated verdict

**CVE Identifier**:
The standardized identifier for a publicly disclosed cybersecurity vulnerability, used by an Operator to request relevant External Intelligence.
_Avoid_: Vulnerability number, security ticket

**Known Exploited Vulnerability**:
A vulnerability that a trusted source identifies as exploited in the wild. It is evidence that can elevate Change Risk; it is not an automatic decision about an IT Change.
_Avoid_: Confirmed breach, automatic block

**Change Review Board**:
The workspace where an Operator compares proposed IT Changes, filters them by Risk Level and Change Type, and reviews mitigations before escalation.
_Avoid_: Dashboard, explore page, approval board

## Product Language

- Application name: **InfraRisk Analyzer**
- Tagline: **Review infrastructure changes before they become outages.**
- Product direction: **IT change-risk analysis for infrastructure operations**
- Primary audience: **junior sysadmin and network-ops practitioners**
- Primary action: **Review Change Risk**
- Assignment 1 route: **`/explore`, presented as the Change Review Board**
- Assignment 1 data: **six fictional IT Changes: firewall allow rule, DNS cutover, privileged access update, Linux patch window, web app deployment, and SSH hardening config**
- Assignment 1 sorting: **High Risk first, then Medium, then Low**
- Assignment 1 risk method: **Risk Levels are manually assigned in sample data and explained by visible Risk Signals.**
- Assignment 1 homepage: **hero pitch, three capability panels, and a compact sample Risk Summary**
- Assignment 1 board layout: **filter bar, risk count summary, and dense IT Change cards with review metadata**
- Future intelligence direction: **AI-generated Risk Summaries that identify Risk Signals, missing review items, mitigation gaps, and rollback concerns**
- Future persistence direction: **stored IT Changes, Risk Findings, Approval Records, and Audit Trail events**
- Assignment 1 disclosure: **Demonstration data, not a production change-management or approval system.**
- Decision boundary: **The application identifies risks and mitigations; it does not approve production changes.**
