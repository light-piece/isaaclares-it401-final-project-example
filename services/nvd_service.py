from dataclasses import dataclass
from datetime import datetime, timezone

import requests


class NvdError(Exception):
    """Base class for expected NVD acquisition failures."""


class NvdConfigurationError(NvdError):
    pass


class NvdNotFoundError(NvdError):
    pass


class NvdRateLimitError(NvdError):
    pass


class NvdSourceError(NvdError):
    pass


@dataclass(frozen=True)
class NvdEvidence:
    cve_id: str
    description: str
    published: str
    cvss_version: str
    cvss_score: str
    cvss_severity: str
    source_url: str
    retrieved_at: str


class NvdService:
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    USER_AGENT = "InfraRisk Analyzer/2.0 (IT401 educational project)"
    TIMEOUT = 10

    def __init__(self, api_key, api_url=None, timeout=TIMEOUT):
        self.api_key = api_key
        self.api_url = api_url or self.API_URL
        self.timeout = timeout

    def get_cve(self, cve_id):
        if not self.api_key:
            raise NvdConfigurationError

        try:
            response = requests.get(
                self.api_url,
                params={"cveId": cve_id},
                headers={"apiKey": self.api_key, "User-Agent": self.USER_AGENT},
                timeout=self.timeout,
            )
            if response.status_code == 429:
                raise NvdRateLimitError
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])
            if not vulnerabilities:
                raise NvdNotFoundError
            vulnerability = vulnerabilities[0]
            cve = vulnerability["cve"]
        except NvdError:
            raise
        except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
            raise NvdSourceError

        return self._normalize(cve)

    def search(self, vendor, product, version="", limit=10):
        """Find possible CVE matches for user-supplied product context."""
        if not self.api_key:
            raise NvdConfigurationError
        terms = " ".join(part.strip() for part in (vendor, product, version) if part.strip())
        if not terms:
            raise NvdNotFoundError
        try:
            response = requests.get(
                self.api_url,
                params={"keywordSearch": terms, "resultsPerPage": limit},
                headers={"apiKey": self.api_key, "User-Agent": self.USER_AGENT},
                timeout=self.timeout,
            )
            if response.status_code == 429:
                raise NvdRateLimitError
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])[:limit]
            if not vulnerabilities:
                raise NvdNotFoundError
            return [self._normalize(item["cve"]) for item in vulnerabilities]
        except NvdError:
            raise
        except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
            raise NvdSourceError

    @staticmethod
    def _normalize(cve):
        descriptions = cve.get("descriptions", [])
        description = next(
            (item.get("value") for item in descriptions if item.get("lang") == "en"),
            "Unavailable",
        )
        version, score, severity = "Unavailable", "Unavailable", "Unavailable"
        metrics = cve.get("metrics", {})
        for metric_key, label in (
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ):
            metric_entries = metrics.get(metric_key, [])
            if metric_entries:
                cvss_data = metric_entries[0].get("cvssData", {})
                version = label
                score = str(cvss_data.get("baseScore", "Unavailable"))
                severity = cvss_data.get("baseSeverity", "Unavailable")
                break

        cve_id = cve.get("id", "Unavailable")
        return NvdEvidence(
            cve_id=cve_id,
            description=description or "Unavailable",
            published=(cve.get("published") or "Unavailable")[:10],
            cvss_version=version,
            cvss_score=score,
            cvss_severity=severity,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            retrieved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
