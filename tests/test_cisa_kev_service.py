from unittest.mock import Mock, patch

from services.cisa_kev_service import CisaKevService


CATALOG_HTML = """
<table>
  <thead><tr>
    <th>CVE ID</th><th>Vendor/Project</th><th>Product</th>
    <th>Vulnerability Name</th><th>Date Added</th><th>Due Date</th>
    <th>Required Action</th>
  </tr></thead>
  <tbody>
    <tr><td><a href="#">CVE-2024-9999</a></td><td>Other</td><td>Other Product</td>
      <td>Other vulnerability</td><td>2024-01-01</td><td>2024-01-22</td><td>Patch it</td></tr>
    <tr><td><a href="#">CVE-2024-3400</a></td><td>Palo Alto Networks</td><td>PAN-OS</td>
      <td>Command injection</td><td>2024-04-16</td><td>2024-05-06</td>
      <td>Apply vendor mitigations.</td></tr>
  </tbody>
</table>
"""


def test_cisa_service_searches_html_and_normalizes_exact_match():
    response = Mock(status_code=200, text=CATALOG_HTML)
    response.raise_for_status.return_value = None

    with patch("services.cisa_kev_service.requests.get", return_value=response) as get:
        evidence = CisaKevService().get_cve("CVE-2024-3400")

    get.assert_called_once()
    assert get.call_args.kwargs["params"] == {"search_api_fulltext": "CVE-2024-3400"}
    assert evidence.cve_id == "CVE-2024-3400"
    assert evidence.vendor_project == "Palo Alto Networks"
    assert evidence.product == "PAN-OS"
    assert evidence.vulnerability_name == "Command injection"
    assert evidence.date_added == "2024-04-16"
    assert evidence.due_date == "2024-05-06"
    assert evidence.required_action == "Apply vendor mitigations."


def test_cisa_service_returns_no_match_for_irrelevant_html_results():
    response = Mock(
        status_code=200,
        text=CATALOG_HTML.replace("CVE-2024-3400", "CVE-2024-3401"),
    )
    response.raise_for_status.return_value = None

    with patch("services.cisa_kev_service.requests.get", return_value=response):
        assert CisaKevService().get_cve("CVE-2024-3400") is None
