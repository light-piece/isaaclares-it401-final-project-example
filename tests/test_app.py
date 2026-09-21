from unittest.mock import Mock, patch

import pytest
import requests

from app import create_app
from services.cisa_kev_service import CisaKevEvidence, CisaKevService


@pytest.fixture
def client():
    app = create_app("development")
    app.config["TESTING"] = True
    app.config["NVD_API_KEY"] = "test-nvd-key"
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def cisa_is_offline(monkeypatch):
    monkeypatch.setattr(CisaKevService, "get_cve", lambda self, cve_id: None)


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


def nvd_response(**overrides):
    cve = {
        "id": "CVE-2024-3400",
        "published": "2024-04-12T18:15:00.000",
        "descriptions": [{
            "lang": "en",
            "value": "An OS command injection vulnerability in PAN-OS software.",
        }],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}
            }]
        },
    }
    cve.update(overrides)
    return {"vulnerabilities": [{"cve": cve}]}


def test_external_intelligence_review_fetches_and_displays_nvd_evidence(client):
    response_mock = Mock()
    response_mock.status_code = 200
    response_mock.json.return_value = nvd_response()
    response_mock.raise_for_status.return_value = None

    with patch("services.nvd_service.requests.get", return_value=response_mock) as get:
        response = client.get(
            "/intelligence?change_ticket=CHG-1042&cve=%20cve-2024-3400%20"
        )

    assert response.status_code == 200
    get.assert_called_once()
    assert get.call_args.kwargs["params"] == {"cveId": "CVE-2024-3400"}
    assert get.call_args.kwargs["headers"]["apiKey"] == "test-nvd-key"
    assert get.call_args.kwargs["timeout"] == 10
    assert get.call_args.kwargs["headers"]["User-Agent"].startswith("InfraRisk Analyzer/")
    assert b"English description" in response.data
    assert b"An OS command injection vulnerability" in response.data
    assert b"Published" in response.data
    assert b"2024-04-12" in response.data
    assert b"CVSS v3.1" in response.data
    assert b"10.0" in response.data
    assert b"CRITICAL" in response.data
    assert b"NVD" in response.data


def test_external_intelligence_review_guides_operator_through_three_questions(client):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()

    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 200
    assert b"Is this system affected?" in response.data
    assert b"How serious is it?" in response.data
    assert b"What should I do?" in response.data
    assert b'aria-pressed="true"' in response.data
    assert b"Source fact" in response.data
    assert b"Operator interpretation" in response.data
    assert b"Technical source details" in response.data
    assert b"If JavaScript is unavailable" in response.data


def test_external_intelligence_review_can_select_a_guiding_question_without_new_acquisition(
    client,
):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()

    with patch("services.nvd_service.requests.get", return_value=response_mock) as get:
        response = client.get(
            "/intelligence",
            query_string={
                "change_ticket": "CHG-1042",
                "cve": "CVE-2024-3400",
                "question": "action",
            },
        )

    assert response.status_code == 200
    assert get.call_count == 1
    assert b'data-question="action"' in response.data
    assert b'aria-controls="answer-action" aria-pressed="true"' in response.data
    assert b'id="answer-action"' in response.data
    assert b"https://nvd.nist.gov/vuln/detail/CVE-2024-3400" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"Manually assigned Risk Level" in response.data


def test_external_intelligence_review_combines_exact_cisa_kev_evidence(client, monkeypatch):
    kev = CisaKevEvidence(
        cve_id="CVE-2024-3400",
        vendor_project="Palo Alto Networks",
        product="PAN-OS",
        vulnerability_name="PAN-OS command injection",
        date_added="2024-04-16",
        due_date="2024-05-06",
        required_action="Apply vendor mitigations or discontinue use of the product.",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        retrieved_at="2026-09-20T20:00:00+00:00",
    )
    monkeypatch.setattr(CisaKevService, "get_cve", lambda self, cve_id: kev)

    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()
    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": " cve-2024-3400 "},
        )

    assert response.status_code == 200
    assert b"NVD API evidence" in response.data
    assert b"CISA KEV catalog evidence" in response.data
    assert b"Palo Alto Networks" in response.data
    assert b"PAN-OS command injection" in response.data
    assert b"2024-05-06" in response.data
    assert b"Strong Risk Signal" in response.data
    assert b"not proof that the system is vulnerable" in response.data
    assert b"Verify that the selected Affected System uses the affected product and version" in response.data
    assert b"https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in response.data


def test_external_intelligence_review_explains_cisa_no_match_without_calling_it_safe(
    client,
):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()
    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 200
    assert b"not listed in the CISA KEV catalog" in response.data
    assert b"does not mean the vulnerability is safe" in response.data
    assert b"affected product and version" in response.data


def test_external_intelligence_review_preserves_nvd_when_cisa_is_unavailable(client, monkeypatch):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()

    def unavailable(_service, _cve_id):
        from services.cisa_kev_service import CisaKevSourceError

        raise CisaKevSourceError

    monkeypatch.setattr(CisaKevService, "get_cve", unavailable)
    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 503
    assert b"NVD API evidence" in response.data
    assert b"CISA KEV evidence unavailable" in response.data
    assert b"cannot claim" in response.data
    assert b"Firewall Allow Rule for Vendor Monitoring" in response.data
    assert b"Manually assigned Risk Level" in response.data
    assert b"Traceback" not in response.data


@pytest.mark.parametrize("failure", [requests.Timeout(), requests.HTTPError()])
def test_external_intelligence_review_handles_cisa_acquisition_failures(
    client, monkeypatch, failure
):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = nvd_response()

    def unavailable(_service, _cve_id):
        from services.cisa_kev_service import CisaKevSourceError

        raise CisaKevSourceError from failure

    monkeypatch.setattr(CisaKevService, "get_cve", unavailable)
    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 503
    assert b"CISA KEV evidence unavailable" in response.data
    assert b"Traceback" not in response.data


@pytest.mark.parametrize(
    "status,heading,body",
    [
        (429, b"NVD rate limit reached", b"try again later"),
        (500, b"NVD source unavailable", b"could not acquire"),
    ],
)
def test_external_intelligence_review_handles_nvd_http_failures(
    client, status, heading, body
):
    response_mock = Mock()
    response_mock.status_code = status
    response_mock.raise_for_status.side_effect = requests.HTTPError()

    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    expected_status = 429 if status == 429 else 502
    assert response.status_code == expected_status
    assert heading in response.data
    assert body in response.data
    assert b"Traceback" not in response.data


@pytest.mark.parametrize("failure", [requests.Timeout(), ValueError("bad json")])
def test_external_intelligence_review_handles_network_and_malformed_json(client, failure):
    with patch("services.nvd_service.requests.get", side_effect=failure):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 502
    assert b"NVD source unavailable" in response.data
    assert b"Traceback" not in response.data


def test_external_intelligence_review_handles_missing_key_without_request(client):
    client.application.config["NVD_API_KEY"] = None

    with patch("services.nvd_service.requests.get") as get:
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 503
    assert b"NVD API key is not configured" in response.data
    get.assert_not_called()


def test_external_intelligence_review_handles_empty_nvd_result(client):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = {"vulnerabilities": []}

    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 404
    assert b"No NVD record found" in response.data


def test_external_intelligence_review_labels_missing_nvd_fields(client):
    response_mock = Mock(status_code=200)
    response_mock.raise_for_status.return_value = None
    response_mock.json.return_value = {
        "vulnerabilities": [{"cve": {"id": "CVE-2024-3400", "descriptions": []}}]
    }

    with patch("services.nvd_service.requests.get", return_value=response_mock):
        response = client.get(
            "/intelligence",
            query_string={"change_ticket": "CHG-1042", "cve": "CVE-2024-3400"},
        )

    assert response.status_code == 200
    assert b"Unavailable" in response.data


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
