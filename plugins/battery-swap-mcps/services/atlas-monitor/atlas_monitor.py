"""Restricted Atlas CONNECTIONS reader. No database client or mutation API."""
import asyncio
import base64
import json
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote, unquote

import httpx

PROJECT_ID = "69cd58b657e3ebb03722b5ba"
CLUSTER_NAME = "Cluster0"
ORIGIN = "https://cloud.mongodb.com"
PREFIX = f"/api/atlas/v2/groups/{PROJECT_ID}"
MAX_BODY = 2 * 1024 * 1024
GRANULARITIES = {"PT1M": 60, "PT5M": 300, "PT1H": 3600}
HOST_PORT = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}:[0-9]{1,5}\Z")


class AtlasError(Exception):
    def __init__(self, code, status=None, retry_after=None, api_error_code=None):
        super().__init__(code)  # Never retain response bodies or transport exceptions.
        self.code, self.status, self.retry_after = code, status, retry_after
        self.api_error_code = api_error_code

    def result(self):
        return {"status": "unavailable", "code": self.code,
                "http_status": self.status, "retry_after_seconds": self.retry_after,
                "atlas_error_code": self.api_error_code}


class BoundedStream(httpx.AsyncByteStream):
    """Also bounds intermediate HTTP Digest401 bodies consumed by httpx itself."""
    def __init__(self, source):
        self.source = source

    async def __aiter__(self):
        size = 0
        async for chunk in self.source:
            size += len(chunk)
            if size > MAX_BODY:
                raise AtlasError("RESPONSE_TOO_LARGE")
            yield chunk

    async def aclose(self):
        await self.source.aclose()


class BoundedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner):
        self.inner = inner

    async def handle_async_request(self, request):
        response = await self.inner.handle_async_request(request)
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            await response.aclose()
            raise AtlasError("UNEXPECTED_CONTENT_ENCODING")
        if response.is_stream_consumed and len(response.content) > MAX_BODY:
            await response.aclose()
            raise AtlasError("RESPONSE_TOO_LARGE")
        response.stream = BoundedStream(response.stream)
        return response

    async def aclose(self):
        await self.inner.aclose()


def finite_number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def utc(value):
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if d.utcoffset() is None or d.utcoffset().total_seconds() != 0:
            raise ValueError()
        return d
    except (ValueError, TypeError, AttributeError):
        raise AtlasError("INVALID_UTC_WINDOW") from None


def window(start, end, granularity):
    a, b = utc(start), utc(end)
    if granularity not in GRANULARITIES or not 0 < (b-a).total_seconds() <= 86400:
        raise AtlasError("INVALID_WINDOW_OR_GRANULARITY")
    if b.timestamp() > time.time() + 300:
        raise AtlasError("FUTURE_WINDOW")
    return {"start": a.isoformat(), "end": b.isoformat(), "granularity": granularity, "m": "CONNECTIONS"}


def cluster_hosts(cluster):
    # Match the exact cluster's standard seed list; never guess from a replica-set name.
    if cluster.get("name") != CLUSTER_NAME or cluster.get("groupId") != PROJECT_ID:
        raise AtlasError("CLUSTER_SCOPE_MISMATCH")
    strings = cluster.get("connectionStrings")
    uri = strings.get("standard", "") if isinstance(strings, dict) else ""
    if not isinstance(uri, str) or not uri.startswith("mongodb://"):
        raise AtlasError("CLUSTER_HOST_MAPPING_UNAVAILABLE")
    authority = uri[len("mongodb://"):].split("/", 1)[0]
    if "@" in authority:  # Do not process credential-bearing connection strings.
        raise AtlasError("CLUSTER_HOST_MAPPING_UNAVAILABLE")
    hosts = {h.lower() for h in authority.split(",")}
    if not hosts or len(hosts) > 3 or any(not HOST_PORT.fullmatch(h) for h in hosts):
        raise AtlasError("CLUSTER_HOST_MAPPING_UNAVAILABLE")
    return hosts


def select_processes(rows, hosts):
    selected = {}
    matched_hosts = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("groupId") != PROJECT_ID:
            continue
        pid = row.get("id", "").lower() if isinstance(row.get("id"), str) else ""
        if not HOST_PORT.fullmatch(pid):
            continue
        alias = row.get("userAlias")
        alias_id = f"{alias}:{row.get('port')}".lower() if isinstance(alias, str) else ""
        matches = hosts.intersection({pid, alias_id})
        if matches:
            if len(matches) != 1 or matches.intersection(matched_hosts):
                raise AtlasError("CLUSTER_PROCESS_MAPPING_AMBIGUOUS")
            matched_hosts.update(matches)
            selected[pid] = row
    if not selected or len(selected) > 3:
        raise AtlasError("CLUSTER_PROCESSES_UNAVAILABLE")
    return sorted(selected)


def measurements(data, start, end):
    if data.get("groupId") != PROJECT_ID:
        raise AtlasError("MEASUREMENT_SCOPE_MISMATCH")
    rows = data.get("measurements")
    if not isinstance(rows, list):
        raise AtlasError("INVALID_RESPONSE")
    metrics = [x for x in rows if isinstance(x, dict) and x.get("name") == "CONNECTIONS"]
    if len(metrics) > 1:
        raise AtlasError("INVALID_RESPONSE")
    metric = metrics[0] if metrics else None
    if metric is None:
        return {"status": "missing_data", "points": [], "latest": None, "peak": None}
    points = metric.get("dataPoints")
    if not isinstance(points, list) or len(points) > 1500:
        raise AtlasError("INVALID_RESPONSE")
    output = []
    seen_timestamps = set()
    for p in points:
        if not isinstance(p, dict):
            raise AtlasError("INVALID_RESPONSE")
        try:
            stamp = utc(p.get("timestamp"))
        except AtlasError:
            raise AtlasError("INVALID_RESPONSE") from None
        if stamp in seen_timestamps:
            raise AtlasError("INVALID_RESPONSE")
        seen_timestamps.add(stamp)
        value = p.get("value")
        if value is not None and (not finite_number(value) or value < 0):
            raise AtlasError("INVALID_RESPONSE")
        if start <= stamp <= end:
            output.append({"timestamp": stamp.isoformat(), "value": value})
    output.sort(key=lambda x: x["timestamp"])
    values = [p["value"] for p in output if p["value"] is not None]
    # Latest sample remains null if unavailable; do not substitute an older value.
    return {"status": "available" if values else "missing_data", "points": output,
            "latest": output[-1]["value"] if output else None,
            "peak": max(values) if values else None, "missing_samples": sum(p["value"] is None for p in output)}


def cluster_summary(data):
    """Project-scoped metadata from existing atlas-inspect-cluster, without URIs."""
    if not isinstance(data, dict) or data.get("groupId") != PROJECT_ID or data.get("name") != CLUSTER_NAME:
        raise AtlasError("CLUSTER_SCOPE_MISMATCH")
    state = data.get("stateName")
    if state not in (None, "IDLE", "CREATING", "UPDATING", "DELETING", "DELETED", "REPAIRING"):
        state = "UNKNOWN"
    return {"project_id": PROJECT_ID, "cluster_name": CLUSTER_NAME, "state": state,
            "paused": data.get("paused") if isinstance(data.get("paused"), bool) else None}


def alert_summary(rows, process_ids, *, complete=False):
    """Sanitize results of existing atlas-list-alerts; no new alert API/tool."""
    if not isinstance(rows, list) or len(rows) > 1000:
        raise AtlasError("INVALID_ALERT_RESPONSE")
    allowed = {pid for pid in process_ids if isinstance(pid, str) and HOST_PORT.fullmatch(pid)}
    output, unattributed = [], 0
    for row in rows:
        if not isinstance(row, dict) or row.get("groupId") != PROJECT_ID or row.get("metricName") != "CONNECTIONS":
            continue
        named_cluster = row.get("clusterName")
        if (named_cluster is not None and named_cluster != CLUSTER_NAME) or (named_cluster is None and row.get("hostnameAndPort") not in allowed):
            unattributed += 1
            continue
        status = row.get("status")
        if status not in ("OPEN", "CLOSED", "TRACKING", "CANCELLED"):
            status = "UNKNOWN"
        stamps = {}
        for key in ("created", "updated", "resolved"):
            value = row.get(key)
            if value is None:
                stamps[key] = None
            else:
                try: stamps[key] = utc(value).isoformat()
                except AtlasError: stamps[key] = None
        output.append({"cluster_name": CLUSTER_NAME, "metric": "CONNECTIONS", "status": status, **stamps})
    return {"project_id": PROJECT_ID, "cluster_name": CLUSTER_NAME, "alerts": output,
            "source_complete": complete is True, "unattributed_connection_alerts": unattributed,
            "interpretation": "Excluded unattributed alerts and incomplete pagination cannot establish absence or recovery."}


class AtlasMonitor:
    def __init__(self, client_id=None, client_secret=None, transport=None, request_seconds=10, call_seconds=60, auth_mode="service_account"):
        if auth_mode not in ("service_account", "api_key"):
            raise AtlasError("INVALID_AUTH_MODE")
        self.auth_mode = auth_mode
        if auth_mode == "api_key" and client_id and (not isinstance(client_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", client_id)):
            raise AtlasError("INVALID_CREDENTIAL_FORMAT")
        self._id, self._secret = client_id, client_secret
        transport = BoundedTransport(transport if transport is not None else httpx.AsyncHTTPTransport(trust_env=False))
        self.http = httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False, timeout=request_seconds)
        self._digest = httpx.DigestAuth(client_id, client_secret) if auth_mode == "api_key" and client_id and client_secret else None
        self.request_seconds, self.call_seconds = request_seconds, call_seconds
        self._token, self._expiry, self._cooldown = None, 0, 0
        self._allowed_pids = set()
        self._backoff_status = 429
        self._auth_lock, self._call_lock = asyncio.Lock(), asyncio.Lock()

    async def close(self):
        await self.http.aclose()
        self._token, self._id, self._secret, self._digest = None, None, None, None

    async def _wire(self, method, path, headers, content=None, params=None, auth=None):
        headers = {**headers, "Accept-Encoding": "identity"}
        async def read():
            async with self.http.stream(method, ORIGIN + path, headers=headers, content=content, params=params, auth=auth) as r:
                body = bytearray()
                async for chunk in r.aiter_bytes(chunk_size=65536):
                    if len(body) + len(chunk) > MAX_BODY:
                        raise AtlasError("RESPONSE_TOO_LARGE")
                    body.extend(chunk)
                return r.status_code, dict(r.headers), bytes(body)
        try:
            return await asyncio.wait_for(read(), self.request_seconds)
        except (TimeoutError, asyncio.TimeoutError, httpx.TimeoutException):
            raise AtlasError("REQUEST_TIMEOUT") from None
        except httpx.HTTPError:
            raise AtlasError("NETWORK_ERROR") from None
        except (ValueError, KeyError, NotImplementedError):
            raise AtlasError("INVALID_AUTH_CHALLENGE") from None

    def _status(self, status, headers, body=None):
        error_code = None
        if body:
            try:
                value = json.loads(body).get("errorCode")
                if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", value) and not any(key and key in value for key in (self._id, self._secret, self._token)):
                    error_code = value
            except (ValueError, UnicodeError, AttributeError, RecursionError):
                pass
        if status == 429 or (status in (502, 503, 504) and "retry-after" in headers):
            raw = headers.get("retry-after", "60")
            try:
                seconds = float(raw)
                if not math.isfinite(seconds): raise ValueError()
            except (ValueError, TypeError):
                try: seconds = parsedate_to_datetime(raw).timestamp() - time.time()
                except (ValueError, TypeError, OverflowError): seconds = 60
            seconds = max(1, seconds)
            self._cooldown = time.monotonic() + seconds
            self._backoff_status = status
            code = "RATE_LIMITED" if status == 429 else "TEMPORARILY_UNAVAILABLE"
            raise AtlasError(code, status, math.ceil(seconds), error_code)
        code = {401: "UNAUTHORIZED", 403: "FORBIDDEN_ROLE_OR_API_ACCESS_LIST",
                404: "RESOURCE_OR_CAPABILITY_UNAVAILABLE"}.get(status, "ATLAS_HTTP_ERROR")
        raise AtlasError(code, status, api_error_code=error_code)

    def _json(self, body):
        try:
            data = json.loads(body)
            if not isinstance(data, dict): raise ValueError()
            return data
        except (ValueError, UnicodeError, RecursionError):
            raise AtlasError("INVALID_RESPONSE") from None

    async def _bearer(self):
        async with self._auth_lock:
            if self._token and time.monotonic() < self._expiry:
                return self._token
            if not self._id or not self._secret:
                raise AtlasError("NOT_CONFIGURED")
            basic = base64.b64encode(f"{self._id}:{self._secret}".encode()).decode()
            status, headers, body = await self._wire("POST", "/api/oauth/token",
                {"Authorization": "Basic " + basic, "Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"}, b"grant_type=client_credentials")
            if status != 200: self._status(status, headers, body)
            data = self._json(body)
            token, expiry = data.get("access_token"), data.get("expires_in")
            if not isinstance(data.get("token_type"), str) or data["token_type"].lower() != "bearer":
                raise AtlasError("INVALID_TOKEN_RESPONSE")
            if not isinstance(token, str) or not token or "\r" in token or "\n" in token or not finite_number(expiry) or expiry <= 0:
                raise AtlasError("INVALID_TOKEN_RESPONSE")
            self._token = token
            self._expiry = time.monotonic() + max(0, expiry-30)
            return token

    async def _get(self, path, params=None):
        # Only fixed project/cluster metadata, process list, and CONNECTIONS routes.
        valid = path in (PREFIX + f"/clusters/{CLUSTER_NAME}", PREFIX + "/processes")
        if path.startswith(PREFIX + "/processes/") and path.endswith("/measurements"):
            encoded = path[len(PREFIX + "/processes/"):-len("/measurements")]
            pid = unquote(encoded)
            valid = pid in self._allowed_pids and quote(pid, safe="") == encoded and params is not None and params.get("m") == "CONNECTIONS" and set(params) == {"start", "end", "granularity", "m"}
        if not valid:
            raise AtlasError("ENDPOINT_NOT_ALLOWED")
        refreshed = False
        for attempt in range(2):
            remaining = self._cooldown - time.monotonic()
            if remaining > 0:
                code = "RATE_LIMITED" if self._backoff_status == 429 else "TEMPORARILY_UNAVAILABLE"
                raise AtlasError(code, self._backoff_status, math.ceil(remaining))
            request_headers = {"Accept": "application/vnd.atlas.2025-03-12+json"}
            auth = None
            if self.auth_mode == "service_account":
                request_headers["Authorization"] = "Bearer " + await self._bearer()
            else:
                if self._digest is None:
                    raise AtlasError("NOT_CONFIGURED")
                auth = self._digest
            status, headers, body = await self._wire("GET", path, request_headers, params=params, auth=auth)
            if status == 200: return self._json(body)
            if self.auth_mode == "service_account" and status == 401 and not refreshed and attempt == 0:
                self._token, self._expiry, refreshed = None, 0, True
                continue
            if status in (502, 503, 504) and attempt == 0:
                # No long waits; surface Retry-After instead of retrying prematurely.
                if "retry-after" in headers:
                    self._status(status, headers, body)
                await asyncio.sleep(0.25)
                continue
            self._status(status, headers, body)

    async def _processes(self):
        rows = []
        for page in range(1, 6):
            data = await self._get(PREFIX + "/processes", {"itemsPerPage": 100, "pageNum": page})
            batch = data.get("results")
            if not isinstance(batch, list) or len(batch) > 100: raise AtlasError("INVALID_RESPONSE")
            rows.extend(batch)
            if len(batch) < 100: return rows
        raise AtlasError("PROCESS_PAGINATION_LIMIT")

    async def connections(self, start_utc, end_utc, granularity="PT1M"):
        base = {"project_id": PROJECT_ID, "cluster_name": CLUSTER_NAME, "metric": "CONNECTIONS"}
        try:
            params = window(start_utc, end_utc, granularity)
            async def collect():
                # Serialize calls including cooldown/token state. No periodic polling loop.
                async with self._call_lock:
                    self._allowed_pids = set()
                    cluster = await self._get(PREFIX + f"/clusters/{CLUSTER_NAME}")
                    hosts = cluster_hosts(cluster)
                    pids = select_processes(await self._processes(), hosts)
                    self._allowed_pids = set(pids)
                    nodes = []
                    for pid in pids:
                        try:
                            data = await self._get(PREFIX + "/processes/" + quote(pid, safe="") + "/measurements", params)
                            if data.get("processId") != pid:
                                raise AtlasError("MEASUREMENT_SCOPE_MISMATCH")
                            nodes.append({"process_id": pid, **measurements(data, utc(start_utc), utc(end_utc))})
                        except AtlasError as error:
                            nodes.append({"process_id": pid, **error.result()})
                            if error.status in (401, 403):
                                break  # Do not query other processes after access denial.
                    complete = len(pids) == len(hosts) and all(n["status"] == "available" for n in nodes)
                    return {**base, "status": "available" if complete else "partial", "window": params,
                            "expected_nodes": len(hosts), "mapped_nodes": len(pids),
                            "returned_nodes": len(nodes), "nodes": nodes,
                            "interpretation": "Per-process samples; do not sum node peaks or infer client identity/TLS cause. M0 API availability requires live verification."}
            return await asyncio.wait_for(collect(), self.call_seconds)
        except AtlasError as error:
            return {**base, **error.result()}
        except (TimeoutError, asyncio.TimeoutError):
            return {**base, **AtlasError("CALL_TIMEOUT").result()}
