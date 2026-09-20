import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app("development")
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_homepage_introduces_infrarisk_analyzer(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"InfraRisk Analyzer" in response.data
    assert b"Review infrastructure changes before they become outages." in response.data
    assert b"Review Change Risk" in response.data
    assert b"Risk signals" in response.data
    assert b"Rollback readiness" in response.data
    assert b"Review metadata" in response.data
    assert b"Sample risk summary" in response.data
    assert b"Firewall change needs security review before the window." in response.data
    assert b"Isaac Lares" in response.data


def test_change_review_board_displays_all_it_changes_high_risk_first(client):
    response = client.get("/explore")

    assert response.status_code == 200
    assert b"6 IT changes" in response.data
    expected_changes = [
        b"Firewall Allow Rule for Vendor Monitoring",
        b"DNS Cutover for Student Portal",
        b"Privileged Access Update for Admin Group",
        b"Linux Patch Window for Web Servers",
        b"Web App Deployment for Registration Service",
        b"SSH Hardening Config for Bastion Host",
    ]
    for change in expected_changes:
        assert change in response.data

    assert response.data.index(b"Firewall Allow Rule") < response.data.index(b"Linux Patch Window")
    assert response.data.index(b"Linux Patch Window") < response.data.index(b"SSH Hardening Config")


def test_change_review_board_combines_risk_level_and_change_type_filters(client):
    response = client.get("/explore?risk_level=High&change_type=Firewall")

    assert response.status_code == 200
    assert b"1 IT change" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"DNS Cutover for Student Portal" not in response.data
    assert b"Linux Patch Window for Web Servers" not in response.data
    assert b'<option value="High" selected>' in response.data
    assert b'<option value="Firewall" selected>' in response.data


def test_change_review_board_filters_by_risk_level(client):
    response = client.get("/explore?risk_level=High")

    assert response.status_code == 200
    assert b"3 IT changes" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"DNS Cutover for Student Portal" in response.data
    assert b"Privileged Access Update for Admin Group" in response.data
    assert b"Linux Patch Window for Web Servers" not in response.data
    assert b'<option value="High" selected>' in response.data


def test_change_review_board_filters_by_change_type(client):
    response = client.get("/explore?change_type=Patching")

    assert response.status_code == 200
    assert b"1 IT change" in response.data
    assert b"Linux Patch Window for Web Servers" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" not in response.data
    assert b'<option value="Patching" selected>' in response.data


@pytest.mark.parametrize(
    "query",
    ["risk_level=Critical", "change_type=Campus"],
)
def test_change_review_board_rejects_invalid_filter_values(client, query):
    response = client.get(f"/explore?{query}")

    assert response.status_code == 400


def test_change_review_board_explains_empty_results_and_offers_to_clear_filters(client):
    response = client.get("/explore?risk_level=Low&change_type=Firewall")

    assert response.status_code == 200
    assert b"0 IT changes" in response.data
    assert b"No IT changes match these filters." in response.data
    assert b'href="/explore"' in response.data


def test_change_review_board_displays_review_metadata_and_disclaimer(client):
    response = client.get("/explore")

    assert response.status_code == 200
    assert b"Demonstration data, not a production change-management or approval system." in response.data
    assert b"Risk signals" in response.data
    assert b"Mitigation" in response.data
    assert b"Rollback plan" in response.data
    assert b"Change ticket" in response.data
    assert b"Change owner" in response.data
    assert b"Review status" in response.data
    assert b"Approval records" in response.data
    assert b"Audit trail" in response.data
    assert b"Network" in response.data
    assert b"Signed Off" in response.data
    assert b"Pending" in response.data


def test_external_intelligence_review_initial_state_lists_local_it_changes(client):
    response = client.get("/intelligence")

    assert response.status_code == 200
    assert b"External Intelligence Review" in response.data
    assert b'action="/intelligence"' in response.data
    assert b'method="get"' in response.data
    assert b'name="change_ticket"' in response.data
    assert b'name="cve"' in response.data
    assert b"CHG-1042 \xe2\x80\x94 Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"CHG-1082 \xe2\x80\x94 SSH Hardening Config for Bastion Host" in response.data
    assert b"Select an IT Change and enter a CVE Identifier" in response.data


def test_external_intelligence_review_populated_get_normalizes_and_displays_context(client):
    response = client.get(
        "/intelligence?change_ticket=CHG-1042&cve=%20cve-2024-3400%20"
    )

    assert response.status_code == 200
    assert b'<option value="CHG-1042" selected>' in response.data
    assert b'value="CVE-2024-3400"' in response.data
    assert b"CHG-1042" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"Firewall" in response.data
    assert b"Data center edge firewall" in response.data
    assert b"High" in response.data
    assert b"Source evidence has not been acquired yet." in response.data


@pytest.mark.parametrize("cve", ["", "2024-3400", "CVE-24-3400", "CVE-2024-ABC"])
def test_external_intelligence_review_rejects_malformed_cve_with_friendly_page(
    client, cve
):
    response = client.get(
        "/intelligence", query_string={"change_ticket": "CHG-1042", "cve": cve}
    )

    assert response.status_code == 400
    assert b"Check the CVE Identifier" in response.data
    assert b"Use a value like CVE-2024-3400." in response.data
    assert b"Traceback" not in response.data


def test_external_intelligence_review_rejects_unknown_change_ticket(client):
    response = client.get(
        "/intelligence",
        query_string={"change_ticket": "CHG-9999", "cve": "CVE-2024-3400"},
    )

    assert response.status_code == 404
    assert b"IT Change not found" in response.data
    assert b"Choose an IT Change from the locally stored list." in response.data
    assert b"Traceback" not in response.data


@pytest.mark.parametrize("path", ["/", "/explore", "/intelligence"])
def test_primary_navigation_connects_review_board_and_external_intelligence(
    client, path
):
    response = client.get(path)

    assert response.status_code == 200
    assert b'href="/explore"' in response.data
    assert b"Change Review Board" in response.data
    assert b'href="/intelligence"' in response.data
    assert b"External Intelligence Review" in response.data


def test_production_path_has_no_prototype_route_or_controls(client):
    prototype_response = client.get("/prototype/external-intelligence?variant=A")
    review_response = client.get(
        "/intelligence?change_ticket=CHG-1042&cve=CVE-2024-3400"
    )

    assert prototype_response.status_code == 404
    assert b"Prototype variant switcher" not in review_response.data
    assert b"Rendered state" not in review_response.data
    assert b"Variant A" not in review_response.data
