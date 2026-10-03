"""Fixed public endpoints; no inventory addresses or arbitrary URLs are sent."""
import json
import math
import re
import threading
import time
from typing import Any, Protocol
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

CVE = re.compile(r"CVE-\d{4}-\d{4,19}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")


def canonical_cpe(value: str) -> str | None:
    """Conservative subset: do not guess identities, wildcards or escaped bindings."""
    parts = value.split(":")
    if value.startswith("cpe:/") and 5 <= len(parts) <= 7:
        parts = ["cpe", "2.3", parts[1][1:], *parts[2:]]
        parts += ["*"] * (13 - len(parts))
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"a", "o", "h"}:
        return None
    if any(not COMPONENT.fullmatch(x) or x in {"-", "~"} for x in parts[3:6]):
        return None
    if any(x not in {"*", "-"} and not COMPONENT.fullmatch(x) for x in parts[6:]):
        return None
    result = ":".join(parts)
    return result if len(result) <= 500 else None


class ProviderError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError("Provider redirect refused")


_request_lock = threading.Lock()
_last_nvd_request = 0.0


def fetch_json(url: str) -> dict[str, Any]:
    global _last_nvd_request
    # Serialize outbound provider requests and fail fast instead of queuing web workers.
    if not _request_lock.acquire(blocking=False):
        raise ProviderError("Provider busy; retry shortly")
    try:
        if url.startswith(NVD.url):
            now = time.monotonic()
            if now - _last_nvd_request < 6:
                raise ProviderError("NVD rate limit: retry after 6 seconds")
            _last_nvd_request = now
        request = Request(url, headers={"User-Agent": "SignalHound/epic12", "Accept": "application/json"})
        try:
            with build_opener(NoRedirect()).open(request, timeout=10) as response:
                content = response.read(8_000_001)
            if len(content) > 8_000_000:
                raise ProviderError("Provider response exceeds size limit")
            result = json.loads(content)
            if not isinstance(result, dict):
                raise ProviderError("Invalid provider response")
            return result
        except (OSError, ValueError) as exc:
            raise ProviderError("Provider unavailable or invalid response; retry later") from exc
    finally:
        _request_lock.release()


class Provider(Protocol):
    name: str
    url: str

    def lookup(self, reference: str) -> dict[str, Any]: ...


def score(value: Any, maximum: float) -> float | None:
    if value is None:
        return None
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= maximum:
        raise ProviderError("Invalid provider score")
    return number


class NVD:
    name = "NVD"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def lookup(self, reference: str) -> dict[str, Any]:
        if CVE.fullmatch(reference):
            params = {"cveId": reference, "resultsPerPage": 20}
        elif canonical_cpe(reference) == reference:
            params = {"cpeName": reference, "isVulnerable": "", "resultsPerPage": 20}
        else:
            raise ProviderError("Unsupported reference")
        raw = fetch_json(self.url + "?" + urlencode(params))
        total = int(raw["totalResults"])
        items = raw["vulnerabilities"]
        if total < 0 or not isinstance(items, list) or total < len(items):
            raise ProviderError("Invalid NVD result count")
        records = []
        for item in items[:20]:
            cve = item["cve"]
            cve_id = cve["id"]
            if not CVE.fullmatch(cve_id):
                raise ProviderError("Invalid CVE identifier")
            if "cveId" in params and cve_id != reference:
                raise ProviderError("Provider returned an unrelated CVE")
            metrics = cve.get("metrics", {})
            cvss = None
            for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                values = metrics.get(version, [])
                if values:
                    metric = next((v for v in values if v.get("type") == "Primary"), values[0])
                    data = metric["cvssData"]
                    cvss = {"score": score(data.get("baseScore"), 10), "version": data.get("version"),
                            "vector": data.get("vectorString"), "source": metric.get("source")}
                    break
            descriptions = cve.get("descriptions", [])
            records.append({
                "cve_id": cve_id,
                "description": next((d["value"] for d in descriptions if d.get("lang") == "en"), "No English description available")[:12000],
                "status": cve.get("vulnStatus", "Unknown"), "published": cve.get("published"),
                "modified": cve.get("lastModified"), "cvss": cvss,
                "configurations": cve.get("configurations", []),
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            })
        return {"records": records, "total": total, "truncated": total > len(records)}


class EPSS:
    name = "FIRST EPSS"
    url = "https://api.first.org/data/v1/epss"

    def lookup(self, reference: str) -> dict[str, Any]:
        ids = reference.split(",")
        if not ids or len(ids) > 20 or not all(CVE.fullmatch(i) for i in ids):
            raise ProviderError("Invalid CVE identifiers")
        raw = fetch_json(self.url + "?" + urlencode({"cve": reference, "limit": 20}))
        if raw.get("status") != "OK":
            raise ProviderError("Invalid EPSS response")
        return {row["cve"]: {"score": score(row["epss"], 1), "percentile": score(row["percentile"], 1),
                             "date": row["date"]}
                for row in raw["data"] if row["cve"] in ids}


class KEV:
    name = "CISA KEV"
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def lookup(self, reference: str) -> dict[str, Any]:
        raw = fetch_json(self.url)
        rows = raw["vulnerabilities"]
        if not isinstance(rows, list) or int(raw["count"]) != len(rows) or not rows:
            raise ProviderError("Incomplete KEV catalog")
        entries = {}
        for row in rows:
            if not CVE.fullmatch(row["cveID"]):
                raise ProviderError("Invalid KEV entry")
            entries[row["cveID"]] = {"date_added": row.get("dateAdded"), "due_date": row.get("dueDate"),
                                     "required_action": row.get("requiredAction")}
        return {"entries": entries, "catalog_version": raw["catalogVersion"], "date_released": raw["dateReleased"]}
