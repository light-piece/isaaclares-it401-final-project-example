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
