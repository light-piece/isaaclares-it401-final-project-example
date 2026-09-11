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
