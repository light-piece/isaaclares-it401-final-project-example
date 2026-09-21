from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import re

import requests


class CisaKevError(Exception):
    """Base class for expected CISA KEV acquisition failures."""


class CisaKevSourceError(CisaKevError):
    pass


@dataclass(frozen=True)
class CisaKevEvidence:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: str
    required_action: str
    source_url: str
    retrieved_at: str


class _TableParser(HTMLParser):
    """Collect table rows while discarding markup and scripts."""

    def __init__(self):
        super().__init__()
        self.rows = []
        self._row = None
        self._cell = None
        self._text = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip_depth += 1
        if self._skip_depth:
            return
        if tag == "tr":
            self._row = []
        elif tag in {"th", "td"} and self._row is not None:
            self._cell = []
            self._cell_tag = tag

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in {"th", "td"} and self._cell is not None:
            self._row.append((self._cell_tag, _clean(" ".join(self._cell))))
            self._cell = None
        elif tag == "tr" and self._row:
            self.rows.append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._skip_depth == 0 and self._cell is not None:
            self._cell.append(data)


def _clean(value):
    return re.sub(r"\s+", " ", value).strip()


def _field_name(header):
    return re.sub(r"[^a-z]", "", header.lower())


class CisaKevService:
    CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    USER_AGENT = "InfraRisk Analyzer/2.0 (IT401 educational project)"
    TIMEOUT = 10

    def __init__(self, catalog_url=None, timeout=TIMEOUT):
        self.catalog_url = catalog_url or self.CATALOG_URL
        self.timeout = timeout

    def get_cve(self, cve_id):
        try:
            response = requests.get(
                self.catalog_url,
                params={"search_api_fulltext": cve_id},
                headers={"User-Agent": self.USER_AGENT},
                timeout=self.timeout,
            )
            response.raise_for_status()
            parser = _TableParser()
            parser.feed(response.text)
        except (requests.RequestException, TypeError, ValueError):
            raise CisaKevSourceError

        requested_id = cve_id.upper()
        headers = None
        for row in parser.rows:
            row_headers = [value for tag, value in row if tag == "th"]
            if row_headers:
                headers = row_headers
            evidence = self._normalize_row(row, requested_id, headers)
            if evidence:
                return evidence
        return None

    def _normalize_row(self, row, requested_id, headers=None):
        cells = [value for tag, value in row if tag == "td"]
        if not headers or not cells or len(headers) != len(cells):
            return None

        values = dict(zip((_field_name(header) for header in headers), cells))
        cve_id = values.get("cveid", "").upper()
        if cve_id != requested_id:
            return None

        return CisaKevEvidence(
            cve_id=cve_id,
            vendor_project=values.get("vendorproject", "Unavailable"),
            product=values.get("product", "Unavailable"),
            vulnerability_name=values.get("vulnerabilityname", "Unavailable"),
            date_added=values.get("dateadded", "Unavailable"),
            due_date=values.get("duedate", "Unavailable"),
            required_action=values.get("requiredaction", "Unavailable"),
            source_url=self.catalog_url,
            retrieved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
