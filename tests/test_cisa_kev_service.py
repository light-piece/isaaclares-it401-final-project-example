from unittest.mock import Mock, patch

import pytest
import requests

from services.cisa_kev_service import CisaKevService, CisaKevSourceError


@pytest.fixture(autouse=True)
def clear_cisa_cache():
    CisaKevService._cache.clear()
    yield
    CisaKevService._cache.clear()


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


CURRENT_CARD_HTML = """
<article class="c-teaser c-teaser--horizontal">
  <div class="c-teaser__meta">Linux | Kernel</div>
  <h3 class="c-teaser__title">
    <a href="https://www.cve.org/CVERecord?id=CVE-2025-39682"><span>CVE-2025-39682</span></a>
  </h3>
  <div class="c-teaser__vuln-name">Linux Kernel vulnerability</div>
  <ul>
    <li><span>Date Added:</span> 2025-06-18</li>
    <li><span>Due Date:</span> 2025-07-09</li>
  </ul>
  <div class="c-teaser__teaser-action">Apply vendor mitigations.</div>
</article>
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


def test_cisa_service_parses_current_card_based_catalog_markup():
    response = Mock(status_code=200, text=CURRENT_CARD_HTML)

    with patch("services.cisa_kev_service.requests.get", return_value=response):
        evidence = CisaKevService().get_cve("CVE-2025-39682")

    assert evidence.cve_id == "CVE-2025-39682"
    assert evidence.vendor_project == "Linux"
    assert evidence.product == "Kernel"
    assert evidence.vulnerability_name == "Linux Kernel vulnerability"
    assert evidence.date_added == "2025-06-18"
    assert evidence.due_date == "2025-07-09"
    assert evidence.required_action == "Apply vendor mitigations."


def test_cisa_service_returns_no_match_for_irrelevant_html_results():
    response = Mock(
        status_code=200,
        text=CATALOG_HTML.replace("CVE-2024-3400", "CVE-2024-3401"),
    )
    response.raise_for_status.return_value = None

    with patch("services.cisa_kev_service.requests.get", return_value=response):
        assert CisaKevService().get_cve("CVE-2024-3400") is None


def test_cisa_service_reuses_and_expires_cached_outcome_without_sleeping():
    now = [100.0]
    response = Mock(status_code=200, text=CATALOG_HTML)
    service = CisaKevService(clock=lambda: now[0])

    with patch("services.cisa_kev_service.requests.get", return_value=response) as get:
        assert service.get_cve(" cve-2024-3400 ").cve_id == "CVE-2024-3400"
        assert service.get_cve("CVE-2024-3400").cve_id == "CVE-2024-3400"
        assert get.call_count == 1

        now[0] += CisaKevService.CACHE_TTL
        assert service.get_cve("CVE-2024-3400").cve_id == "CVE-2024-3400"
        assert get.call_count == 2


@pytest.mark.parametrize("response", [Mock(status_code=503), Mock(status_code=200, text="<html>broken</html>")])
def test_cisa_service_rejects_unavailable_or_unrecognizable_catalog(response):
    with patch("services.cisa_kev_service.requests.get", return_value=response):
        with pytest.raises(CisaKevSourceError):
            CisaKevService().get_cve("CVE-2024-3400")


def test_cisa_service_rejects_truncated_expected_table_rows():
    html = CATALOG_HTML.replace(
        "<td>Apply vendor mitigations.</td>", ""
    )
    response = Mock(status_code=200, text=html)

    with patch("services.cisa_kev_service.requests.get", return_value=response):
        with pytest.raises(CisaKevSourceError):
            CisaKevService().get_cve("CVE-2024-3400")


def test_cisa_service_wraps_network_failures_as_source_errors():
    with patch(
        "services.cisa_kev_service.requests.get", side_effect=requests.Timeout()
    ):
        with pytest.raises(CisaKevSourceError):
            CisaKevService().get_cve("CVE-2024-3400")
