import json
import os

from flask import abort, render_template, request

from models import ITChange


RISK_RANK = {"High": 0, "Medium": 1, "Low": 2}
CHANGE_TYPES = ("Firewall", "DNS", "Access", "Patching", "Deployment", "Server Config")


def register_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/explore")
    def explore():
        data_path = os.path.join(app.config["DATA_DIR"], "it_changes.json")
        with open(data_path, encoding="utf-8") as data_file:
            changes = [ITChange.from_dict(item) for item in json.load(data_file)]

        selected_risk = request.args.get("risk_level", "")
        selected_change_type = request.args.get("change_type", "")

        if selected_risk and selected_risk not in RISK_RANK:
            abort(400, description="Unknown risk level filter.")
        if selected_change_type and selected_change_type not in CHANGE_TYPES:
            abort(400, description="Unknown change type filter.")

        if selected_risk:
            changes = [change for change in changes if change.risk_level == selected_risk]
        if selected_change_type:
            changes = [
                change for change in changes if change.change_type == selected_change_type
            ]

        changes.sort(key=lambda change: (RISK_RANK[change.risk_level], change.title))
        risk_counts = {
            risk_level: sum(1 for change in changes if change.risk_level == risk_level)
            for risk_level in RISK_RANK
        }

        return render_template(
            "explore.html",
            changes=changes,
            risk_levels=RISK_RANK.keys(),
            change_types=CHANGE_TYPES,
            selected_risk=selected_risk,
            selected_change_type=selected_change_type,
            risk_counts=risk_counts,
        )

    @app.route("/prototype/external-intelligence")
    def external_intelligence_prototype():
        """THROWAWAY UI PROTOTYPE: three External Intelligence Review layouts."""
        if not app.config.get("DEBUG", False):
            abort(404)

        variants = {
            "A": "Evidence ledger",
            "B": "Decision desk",
            "C": "Review brief",
        }
        variant = request.args.get("variant", "A").upper()
        if variant not in variants:
            abort(400, description="Unknown prototype variant.")

        prototype_review = {
            "change_ticket": "CHG-1042",
            "change_title": "Firewall Allow Rule for Vendor Monitoring",
            "affected_system": "Campus perimeter firewall",
            "risk_level": "High",
            "cve": "CVE-2024-3400",
            "description": "An OS command injection vulnerability in PAN-OS software.",
            "published": "2024-04-12",
            "cvss": "10.0 Critical",
            "kev_status": "Listed in CISA KEV",
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "date_added": "2024-04-12",
            "due_date": "2024-04-19",
            "required_action": "Apply mitigations per vendor instructions or discontinue use.",
            "retrieved_at": "Prototype sample — request-time evidence",
        }
        return render_template(
            "external_intelligence_prototype.html",
            variant=variant,
            variant_name=variants[variant],
            review=prototype_review,
        )
