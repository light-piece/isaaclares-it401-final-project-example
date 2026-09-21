from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import time

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


@dataclass(frozen=True)
class _CachedLookup:
    expires_at: float
    evidence: "CisaKevEvidence | None"


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


class _TeaserParser(HTMLParser):
    """Parse the current card-based CISA KEV catalog markup."""

    def __init__(self):
        super().__init__()
        self.teasers = []
        self._article = None
        self._field = None
        self._field_tag = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "").split()
        if tag == "article" and "c-teaser" in classes:
            self._article = {"vendor_project": "", "cve_id": "", "vulnerability_name": "", "date_added": "", "due_date": "", "required_action": ""}
        if not self._article:
            return
        if tag == "a" and attrs.get("href", "").find("/CVERecord?id=") >= 0:
            self._field = "cve_id"
            self._field_tag = tag
        elif "c-teaser__meta" in classes:
            self._field = "vendor_project"
            self._field_tag = tag
        elif "c-teaser__vuln-name" in classes:
            self._field = "vulnerability_name"
            self._field_tag = tag
        elif "c-teaser__teaser-action" in classes:
            self._field = "required_action"
            self._field_tag = tag
        elif tag == "li":
            self._field = "list_item"
            self._field_tag = tag
        if self._field_tag == tag:
            self._text = []

    def handle_endtag(self, tag):
        if not self._article:
            return
        if tag != self._field_tag and tag != "article":
            return
        value = _clean(" ".join(self._text))
        if self._field == "list_item" and value:
            if "Date Added:" in value:
                self._article["date_added"] = value.split("Date Added:", 1)[1].strip()
            elif "Due Date:" in value:
                self._article["due_date"] = value.split("Due Date:", 1)[1].strip()
        elif self._field in self._article and value:
            self._article[self._field] = value
        if tag == "article":
            self.teasers.append(self._article)
            self._article = None
            self._field = None
            self._field_tag = None
        self._text = []

    def handle_data(self, data):
        if self._article is not None:
            self._text.append(data)


def _clean(value):
    return re.sub(r"\s+", " ", value).strip()


def _field_name(header):
    return re.sub(r"[^a-z]", "", header.lower())


class CisaKevService:
    CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    USER_AGENT = "InfraRisk Analyzer/2.0 (IT401 educational project)"
    TIMEOUT = 10
    CACHE_TTL = 15 * 60
    _cache = {}

    def __init__(self, catalog_url=None, timeout=TIMEOUT, clock=None):
        self.catalog_url = catalog_url or self.CATALOG_URL
        self.timeout = timeout
        self.clock = clock or time.monotonic

    def get_cve(self, cve_id):
        requested_id = cve_id.strip().upper()
        cache_key = (self.catalog_url, requested_id)
        cached = self._cache.get(cache_key)
        if cached and cached.expires_at > self.clock():
            return cached.evidence
        if cached:
            del self._cache[cache_key]

        try:
            response = requests.get(
                self.catalog_url,
                params={"search_api_fulltext": requested_id},
                headers={"User-Agent": self.USER_AGENT},
                timeout=self.timeout,
            )
            if not 200 <= response.status_code < 300:
                raise CisaKevSourceError
            parser = _TableParser()
            parser.feed(response.text)
            teaser_parser = _TeaserParser()
            teaser_parser.feed(response.text)
        except CisaKevSourceError:
            raise
        except (requests.RequestException, TypeError, ValueError, AttributeError):
            raise CisaKevSourceError from None

        for teaser in teaser_parser.teasers:
            if teaser["cve_id"].upper() == requested_id:
                vendor_project = teaser["vendor_project"]
                vendor, _, product = vendor_project.partition("|")
                evidence = CisaKevEvidence(
                    cve_id=requested_id,
                    vendor_project=vendor.strip() or "Unavailable",
                    product=product.strip() or "Unavailable",
                    vulnerability_name=teaser["vulnerability_name"] or "Unavailable",
                    date_added=teaser["date_added"] or "Unavailable",
                    due_date=teaser["due_date"] or "Unavailable",
                    required_action=teaser["required_action"] or "Unavailable",
                    source_url=self.catalog_url,
                    retrieved_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                )
                self._cache[cache_key] = _CachedLookup(self.clock() + self.CACHE_TTL, evidence)
                return evidence

        headers = None
        found_expected_table = False
        malformed_row = False
        for row in parser.rows:
            row_headers = [value for tag, value in row if tag == "th"]
            if row_headers:
                headers = row_headers
                found_expected_table = self._has_expected_headers(headers)
            if found_expected_table and headers:
                cells = [value for tag, value in row if tag == "td"]
                if cells and len(headers) != len(cells):
                    malformed_row = True
            evidence = self._normalize_row(row, requested_id, headers)
            if evidence:
                self._cache[cache_key] = _CachedLookup(
                    self.clock() + self.CACHE_TTL, evidence
                )
                return evidence
        if not found_expected_table or malformed_row:
            raise CisaKevSourceError

        self._cache[cache_key] = _CachedLookup(self.clock() + self.CACHE_TTL, None)
        return None

    @staticmethod
    def _has_expected_headers(headers):
        names = {_field_name(header) for header in headers}
        return {
            "cveid",
            "vendorproject",
            "product",
            "vulnerabilityname",
            "dateadded",
            "duedate",
            "requiredaction",
        }.issubset(names)

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
