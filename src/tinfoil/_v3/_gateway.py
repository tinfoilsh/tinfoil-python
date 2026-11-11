"""Requests through Tinfoil's inference gateway, each sealed to a verified replica of the model it names.

The gateway is an HTTP origin that authenticates the API key, selects a
replica and copies bytes. It is not attested and holds no HPKE key, so the
routing inputs travel in plaintext headers: ``X-Tinfoil-Model`` names the
model, ``X-Tinfoil-Cache-Prefix`` keys the prompt head so that a conversation
stays on one replica, and ``X-Tinfoil-Seal`` names the enclave the body was
sealed to. A ``412`` naming another enclave is a seal redirect: the named
host is verified and the request re-sealed to it.
"""

from __future__ import annotations

import asyncio
import base64
import email.message
import email.parser
import email.policy
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from typing import Generic, Protocol, TypeVar

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinfoil._v3 import _cachesecret
from tinfoil._v3._chain import (
    AsyncReplay,
    Replay,
    replayable,
    with_enclave_url,
    with_enclave_url_async,
)
from tinfoil._v3._ehbp import check_ehbp
from tinfoil._v3._enclave import Enclave
from tinfoil._v3._errors import (
    AttestationError,
    ConfigurationError,
    NetworkError,
    TinfoilError,
    network_error,
)
from tinfoil._v3._fetch import get_bounded, get_bounded_async
from tinfoil._v3._transport import (
    USE_CLIENT_DEFAULT,
    AsyncAttestedTransport,
    AsyncEHBPMode,
    AsyncRetiringTransport,
    AttestedTransport,
    EHBPMode,
    RetiringTransport,
    UseClientDefault,
)
from tinfoil._v3._types import DEFAULT_HTTP_TIMEOUT, TimeoutTypes, VerificationCheck
from tinfoil._v3.verifier import Verification, Verifier, parse_reference

DEFAULT_GATEWAY_URL = "https://inference-gateway.tinfoil.sh/v1/"
"""Tinfoil's gateway, the base URL a gateway client uses when none is given."""
CATALOG_PATH = "/catalog"
CATALOG_FETCH_TIMEOUT = 10.0
CATALOG_REFRESH_INTERVAL = 10.0
"""The gateway lists only replicas passing its health checks and reloads its config every 10 seconds, so a client
refreshes as often."""
MAX_CATALOG_BYTES = 2 << 20
TRUSTED_REPO_OWNER = "tinfoilsh/"

MODEL_HEADER = "X-Tinfoil-Model"
CACHE_PREFIX_HEADER = "X-Tinfoil-Cache-Prefix"
SEAL_HEADER = "X-Tinfoil-Seal"
MAX_SEAL_REDIRECTS = 3
MAX_REROUTED = 1024
MAX_MULTIPART_BODY_SIZE = 64 << 20

# The engine's cache salt is derived here: no router sits between a gateway client and the engine.
CACHE_SALT_DOMAIN_TAG = b"tinfoil/client-cache-salt/v2"
CACHE_ROUTE_DOMAIN_TAG = b"tinfoil/client-cache-route/v2"

CALLER_AUTHORIZED_CONFIG = "caller-authorized config requires a direct enclave client"


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """A model's untrusted repository and replica hosts as the gateway lists them."""

    repo: str
    hosts: tuple[str, ...] = ()

    def trusted(self) -> bool:
        """Whether the entry can be used: a bare ``tinfoilsh/`` repository, without a tag or digest, and at least
        one host."""
        try:
            reference = parse_reference(self.repo)
        except ValueError:
            return False
        return reference.repo == self.repo and self.repo.startswith(TRUSTED_REPO_OWNER) and len(self.hosts) > 0


Catalog = Mapping[str, CatalogEntry]
"""Model names to their untrusted repository and replica entries."""


@dataclass(frozen=True, slots=True)
class ModelPin:
    """Pins a model to ``tinfoilsh/name[@tag][@sha256:digest]``. A None ``verifier`` inherits the gateway's; one
    that is set replaces it."""

    repo: str
    verifier: Verifier | None = None


@dataclass(frozen=True, slots=True)
class ReplicaVerification:
    """A gateway replica's last successful verification."""

    host: str
    """The replica the verification is for."""
    models: tuple[str, ...]
    """The models requested through the replica: request labels, not attested identities."""
    reference: str
    """The repository reference the replica was verified against."""
    pinned_model: str
    """The pinned model the verification serves, or empty when the model was not pinned."""
    verification: Verification


def fetch_catalog(host: str, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT) -> Catalog:
    """The catalog of the gateway at ``host``, keeping only models with replicas of a bare ``tinfoilsh/``
    repository, without a tag or digest. Raises NetworkError when it cannot be fetched or decoded."""
    body = get_bounded(
        f"https://{host}{CATALOG_PATH}",
        timeout=timeout,
        deadline=None,
        overall=CATALOG_FETCH_TIMEOUT,
        max_bytes=MAX_CATALOG_BYTES,
        ok=(200, 200),
    )
    return parse_catalog(body)


async def fetch_catalog_async(host: str, *, timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT) -> Catalog:
    """``fetch_catalog`` on the event loop."""
    body = await get_bounded_async(
        f"https://{host}{CATALOG_PATH}",
        timeout=timeout,
        deadline=None,
        overall=CATALOG_FETCH_TIMEOUT,
        max_bytes=MAX_CATALOG_BYTES,
        ok=(200, 200),
    )
    return parse_catalog(body)


def parse_catalog(body: bytes) -> Catalog:
    """The usable entries of the JSON catalog ``body``: an object of model names to ``{"repo", "hosts"}`` objects.
    A body of another shape is a NetworkError; an entry that is not trusted is dropped."""
    try:
        raw = json.loads(body)
    except ValueError as err:
        raise network_error(f"decoding gateway catalog: {err}") from err
    if not isinstance(raw, dict):
        raise network_error("decoding gateway catalog: want a JSON object")
    catalog: dict[str, CatalogEntry] = {}
    for model, value in raw.items():
        if not isinstance(value, dict):
            raise network_error(f"decoding gateway catalog: entry {model!r} is not an object")
        repo = value.get("repo", "")
        hosts = value.get("hosts") or []
        if not isinstance(repo, str) or not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
            raise network_error(f"decoding gateway catalog: entry {model!r} has fields of the wrong type")
        entry = CatalogEntry(repo=repo, hosts=tuple(hosts))
        if entry.trusted():
            catalog[model] = entry
    return catalog


@dataclass(frozen=True, slots=True)
class _Replica:
    """What a verified replica transport is keyed by: the host, the reference it is verified against and the pinned
    model it serves, empty when unpinned."""

    host: str
    ref: str
    model: str = ""


class _Policy:
    """The gateway's verification policy: the pins, whether only pinned models are served, and the verifier for
    unpinned models."""

    def __init__(self, model_pins: Mapping[str, ModelPin] | None, pinned_only: bool, verifier: Verifier | None):
        if pinned_only and not model_pins:
            raise ConfigurationError("pinned-only mode requires at least one model pin")
        if verifier is None:
            verifier = Verifier()
        if verifier.caller_authorizes_config:
            raise ConfigurationError(CALLER_AUTHORIZED_CONFIG)
        self.pins: dict[str, ModelPin] = {}
        self.pinned_only = pinned_only
        self.verifier = verifier
        for model, pin in (model_pins or {}).items():
            if pin.verifier is not None and pin.verifier.caller_authorizes_config:
                raise ConfigurationError(f'model "{model}": {CALLER_AUTHORIZED_CONFIG}')
            if not model.strip() or not pin.repo.startswith(TRUSTED_REPO_OWNER):
                raise ConfigurationError(
                    f'model pin "{model}" repository "{pin.repo}" must belong to {TRUSTED_REPO_OWNER}'
                )
            try:
                parse_reference(pin.repo)
            except ValueError as err:
                raise ConfigurationError(f'model "{model}": {err}') from err
            self.pins[model] = ModelPin(repo=pin.repo, verifier=pin.verifier or verifier)

    def resolve(self, model: str, catalog: Catalog) -> tuple[tuple[str, ...], _Replica]:
        """The hosts serving ``model`` and the replica key its requests are verified under."""
        pin = self.pins.get(model)
        if self.pinned_only and pin is None:
            raise ConfigurationError(f'model "{model}" is not pinned')
        entry = catalog.get(model)
        if entry is None or not entry.trusted():
            raise ConfigurationError(
                f'model "{model}" has no valid bare {TRUSTED_REPO_OWNER} repository with replicas '
                "in the gateway catalog"
            )
        if pin is not None:
            repo = pin.repo.split("@", 1)[0]
            if entry.repo != repo:
                raise AttestationError(f'model "{model}": expected repository "{repo}", gateway offered "{entry.repo}"')
            return entry.hosts, _Replica(host="", ref=pin.repo, model=model)
        return entry.hosts, _Replica(host="", ref=entry.repo)

    def verifier_for(self, replica: _Replica) -> Verifier:
        pin = self.pins.get(replica.model) if replica.model else None
        if pin is not None and pin.verifier is not None:
            return pin.verifier
        return self.verifier


def rank(hosts: tuple[str, ...] | list[str], prefix: str, first: str) -> list[str]:
    """``hosts`` by descending rendezvous score for the cache ``prefix``, or in random order without one, with
    ``first`` moved to the front when it is among them."""
    ordered = list(hosts)
    if not prefix:
        secrets.SystemRandom().shuffle(ordered)
        return ordered

    def score(host: str) -> int:
        digest = hashlib.sha256(f"{prefix}\x00{host}".encode()).digest()
        return int.from_bytes(digest[:8], "big")

    ordered.sort(key=score, reverse=True)
    if first in ordered:
        ordered.remove(first)
        ordered.insert(0, first)
    return ordered


def bearer_credential(authorization: str) -> str:
    """The credential of a Bearer authorization, whose scheme is case-insensitive, and "" for any other scheme."""
    scheme, separator, credential = authorization.strip().partition(" ")
    if not separator or scheme.lower() != "bearer":
        return ""
    return credential.strip()


def _hkdf(secret: str, api_key: str, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=api_key.encode(), info=info).derive(secret.encode())


def cache_salt(secret: str, api_key: str) -> str:
    """The engine's cache salt for ``secret`` under ``api_key``: unpadded base64url of the derived key."""
    return base64.urlsafe_b64encode(_hkdf(secret, api_key, CACHE_SALT_DOMAIN_TAG)).rstrip(b"=").decode()


def cache_prefix(secret: str, api_key: str, head: bytes) -> str:
    """The routing prefix for the prompt ``head`` under ``secret`` and ``api_key``: lowercase hex HMAC."""
    key = _hkdf(secret, api_key, CACHE_ROUTE_DOMAIN_TAG)
    return hmac.new(key, head, hashlib.sha256).hexdigest()


def prompt_head(members: Mapping[str, _cachesecret.Member], text: str) -> str | None:
    """The JSON text of the prompt head, which later turns of a conversation share: a non-empty string
    ``instructions``, otherwise the first element of the first of ``messages``, ``input`` or ``prompt`` that is
    present and not null, or the value itself when it is not an array. Empty arrays are skipped."""
    instructions = members.get("instructions")
    if instructions is not None:
        raw = text[instructions.value_start : instructions.value_end]
        if raw.startswith('"') and json.loads(raw) != "":
            return raw
    for name in ("messages", "input", "prompt"):
        member = members.get(name)
        if member is None:
            continue
        raw = text[member.value_start : member.value_end]
        if raw == "null":
            continue
        if not raw.startswith("["):
            return raw
        if json.loads(raw) == []:
            continue
        start = 1
        while raw[start] in " \t\n\r":
            start += 1
        _, end = json.JSONDecoder().raw_decode(raw, start)
        return raw[start:end]
    return None


def _media_type(content_type: str) -> tuple[str, dict[str, str]]:
    """The lowercased media type of a Content-Type value and its parameters."""
    message = email.message.EmailMessage()
    message["Content-Type"] = content_type
    params = {key.lower(): value for key, value in message.get_params(failobj=[])[1:]}
    return message.get_content_type(), params


@dataclass(frozen=True, slots=True)
class Prepared:
    """A request's routing headers and body after preparation."""

    headers: httpx.Headers
    body: bytes | None
    """The body to send, or None to forward the request's own body."""


def prepare(method: str, path: str, headers: httpx.Headers, content: bytes | None, secret: str) -> Prepared:
    """Sets ``X-Tinfoil-Model`` from a JSON body's ``model`` or a multipart upload's ``model`` field, and for an
    eligible JSON body derives the cache salt and prefix from the secret. ``content`` is None when the body is not
    in memory, in which case nothing is read. Raises ConfigurationError for a body that must not be routed."""
    headers = headers.copy()
    if method.upper() != "POST" or content is None or not content:
        return Prepared(headers, None)
    media_type, params = _media_type(headers.get("Content-Type", ""))
    if media_type == "multipart/form-data":
        if headers.get(MODEL_HEADER, ""):
            return Prepared(headers, None)
        headers[MODEL_HEADER] = multipart_model(content, params.get("boundary", ""))
        return Prepared(headers, content)
    if media_type != "application/json":
        return Prepared(headers, None)
    body = content
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return Prepared(headers, body)
    scanned = _cachesecret.scan_object(text)
    if scanned is not None:
        routed = (_cachesecret.MODEL_FIELD, _cachesecret.FIELD, _cachesecret.CACHE_SALT_FIELD)
        repeated = [key for key in routed if _cachesecret.has_duplicates(scanned, key)]
        if repeated:
            names = ", ".join(f'"{key}"' for key in repeated)
            raise ConfigurationError(f"request body repeats the {names} member{'s' if len(repeated) > 1 else ''}")
        members = {member.key: member for member in scanned}
        model = members.get(_cachesecret.MODEL_FIELD)
        if not headers.get(MODEL_HEADER, "") and model is not None:
            raw = text[model.value_start : model.value_end]
            if raw.startswith('"') and json.loads(raw) != "":
                headers[MODEL_HEADER] = json.loads(raw)
        if _cachesecret.path_eligible(method, path):
            body = scope_cache(headers, scanned, text, secret)
    return Prepared(headers, body)


def scope_cache(headers: httpx.Headers, members: list[_cachesecret.Member], text: str, client_secret: str) -> bytes:
    """The body with the secret replaced by the derived ``cache_salt``, and the headers with the derived cache
    prefix. The secret is the body's non-empty string ``user_cache_secret``, otherwise ``client_secret``; with
    neither, nothing changes. The secret itself never leaves the client. Only the two members are spliced: the
    ``user_cache_secret`` member is cut out and the ``cache_salt`` value replaced, or the member appended, so
    every other byte the caller sent, its whitespace, key order and number spelling included, is forwarded as
    it is."""
    by_key = {member.key: member for member in members}
    secret = ""
    field = by_key.get(_cachesecret.FIELD)
    if field is not None:
        raw = text[field.value_start : field.value_end]
        if raw.startswith('"'):
            secret = json.loads(raw)
    secret = secret or client_secret
    if not secret:
        return text.encode()
    api_key = bearer_credential(headers.get("Authorization", ""))
    salt = cache_salt(secret, api_key)
    headers.pop(CACHE_PREFIX_HEADER, None)
    head = prompt_head(by_key, text)
    if head is not None:
        headers[CACHE_PREFIX_HEADER] = cache_prefix(secret, api_key, head.encode())
    edits: list[tuple[int, int, str]] = []
    if field is not None:
        edits.append(_removal(members, members.index(field)))
    existing = by_key.get(_cachesecret.CACHE_SALT_FIELD)
    if existing is not None:
        edits.append((existing.value_start, existing.value_end, json.dumps(salt)))
    else:
        close = text.rindex("}")
        comma = "," if len(members) > (1 if field is not None else 0) else ""
        edits.append((close, close, f'{comma}"{_cachesecret.CACHE_SALT_FIELD}":{json.dumps(salt)}'))
    return _spliced(text, edits).encode()


def _removal(members: list[_cachesecret.Member], index: int) -> tuple[int, int, str]:
    """The span that cuts member ``index`` out of its object: the member and the comma that separates it from
    the next one, or from the previous one when it is last."""
    member = members[index]
    if index + 1 < len(members):
        return member.key_start, members[index + 1].key_start, ""
    if index > 0:
        return members[index - 1].value_end, member.value_end, ""
    return member.key_start, member.value_end, ""


def _spliced(text: str, edits: list[tuple[int, int, str]]) -> str:
    """``text`` with each ``(start, end, replacement)`` applied. The spans do not overlap, so applying them from
    the end keeps the earlier offsets valid."""
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


def multipart_model(body: bytes, boundary: str) -> str:
    """The value of the one non-empty, non-file ``model`` field of a multipart upload. Raises ConfigurationError
    for a missing boundary, a malformed body, or a missing, repeated, empty or file ``model`` part."""
    if not boundary:
        raise ConfigurationError("multipart upload is missing its boundary")
    _check_multipart_size(len(body))
    header = f'Content-Type: multipart/form-data; boundary="{boundary}"\r\nMIME-Version: 1.0\r\n\r\n'.encode()
    message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(header + body)
    if message.defects or not message.is_multipart():
        raise ConfigurationError("invalid multipart upload")
    models: list[str] = []
    for part in message.iter_parts():
        if part.defects:
            raise ConfigurationError("invalid multipart upload")
        if (
            part.get_content_disposition() != "form-data"
            or part.get_param("name", header="content-disposition") != "model"
        ):
            continue
        if part.get_filename() is not None:
            raise ConfigurationError("multipart upload must contain exactly one non-empty model field")
        payload = part.get_payload(decode=True)
        models.append(payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else "")
    if len(models) != 1 or not models[0].strip():
        raise ConfigurationError("multipart upload must contain exactly one non-empty model field")
    return models[0]


_T = TypeVar("_T", "ReplicaTransport", "AsyncReplicaTransport")


class Keyed(Protocol):
    """What a replica transport reads from its attested transport."""

    @property
    def current(self) -> Verification | None: ...

    def ensure_verified(self, *, timeout: TimeoutTypes | UseClientDefault = ...) -> Verification: ...


class AsyncKeyed(Protocol):
    @property
    def current(self) -> Verification | None: ...

    async def ensure_verified(self) -> Verification: ...


class ReplicaTransport:
    """One replica's verified transport and the models requested through it. ``chain`` can be retired: it then
    takes no new requests and closes once the responses in flight through it are done."""

    def __init__(self, keyed: Keyed, chain: httpx.BaseTransport) -> None:
        self.keyed = keyed
        self.chain = RetiringTransport(chain)
        self.models: set[str] = set()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.models.add(request.headers.get(MODEL_HEADER, ""))
        return self.chain.handle_request(request)


class AsyncReplicaTransport:
    def __init__(self, keyed: AsyncKeyed, chain: httpx.AsyncBaseTransport) -> None:
        self.keyed = keyed
        self.chain = AsyncRetiringTransport(chain)
        self.models: set[str] = set()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.models.add(request.headers.get(MODEL_HEADER, ""))
        return await self.chain.handle_async_request(request)


class _Shared(Generic[_T]):
    """What the synchronous and asynchronous gateway transports have in common: the policy, the replica
    transports built so far, and the hosts the gateway rerouted each cache prefix to.

    Replica transports are retained while the catalog lists their host.
    Each time the catalog changes, the transports of hosts it no longer
    lists are evicted: they take no new requests and close once their
    responses in flight are done. A host that a seal redirect named but the
    catalog does not list keeps its transport until the catalog next
    changes. A request routed from the previous catalog that reaches an
    evicted transport is refused as retired, and is routed by the current
    catalog when it is sent again.
    """

    def __init__(
        self,
        *,
        base_url: str,
        relay: str,
        model_pins: Mapping[str, ModelPin] | None,
        pinned_models_only: bool,
        verifier: Verifier | None,
        verification_check: VerificationCheck | None,
        user_cache_secret: str | None,
        timeout: TimeoutTypes,
    ) -> None:
        self.policy = _Policy(model_pins, pinned_models_only, verifier)
        self.base_url = base_url
        self.relay = relay
        self.check = verification_check
        self.secret = _cachesecret.resolve(user_cache_secret)
        self.timeout = timeout
        self.lock = threading.Lock()
        self.enclaves: dict[_Replica, _T] = {}
        self.rerouted: dict[str, str] = {}
        self.retained_for: Catalog | None = None

    def evict(self, catalog: Catalog) -> list[_T]:
        """The replica transports of hosts that ``catalog`` no longer lists, removed from the retained ones when
        the catalog differs from the one they were last retained for; the caller retires them."""
        with self.lock:
            if catalog is self.retained_for or catalog == self.retained_for:
                return []
            self.retained_for = catalog
            listed = {host for entry in catalog.values() for host in entry.hosts}
            evicted = [replica for replica in self.enclaves if replica.host not in listed]
            return [self.enclaves.pop(replica) for replica in evicted]

    def enclave_for(self, replica: _Replica) -> Enclave:
        return Enclave(
            replica.host,
            replica.ref,
            relay=self.relay,
            verifier=self.policy.verifier_for(replica),
            verification_check=self.check,
        )

    def rerouted_host(self, prefix: str) -> str:
        with self.lock:
            return self.rerouted.get(prefix, "")

    def remember(self, prefix: str, host: str) -> None:
        if not prefix:
            return
        with self.lock:
            if len(self.rerouted) >= MAX_REROUTED:
                self.rerouted = {}
            self.rerouted[prefix] = host

    def resolve(self, model: str, catalog: Catalog) -> tuple[tuple[str, ...], _Replica]:
        return self.policy.resolve(model, catalog)

    def models_of(self, catalog: Catalog) -> list[str]:
        models: list[str] = []
        for model in catalog:
            try:
                self.policy.resolve(model, catalog)
            except TinfoilError:
                continue
            models.append(model)
        return sorted(models)

    def verifications(self, current: Callable[[_T], Verification | None]) -> list[ReplicaVerification]:
        with self.lock:
            entries = list(self.enclaves.items())
        results: list[ReplicaVerification] = []
        for replica, transport in entries:
            verified = current(transport)
            if verified is not None:
                results.append(
                    ReplicaVerification(
                        host=replica.host,
                        models=tuple(sorted(transport.models)),
                        reference=replica.ref,
                        pinned_model=replica.model,
                        verification=verified,
                    )
                )
        results.sort(key=lambda r: (r.host, r.reference, r.pinned_model))
        return results


def replica_chain(keyed: httpx.BaseTransport, host: str, base_url: str) -> httpx.BaseTransport:
    """What a replica's requests go through around ``keyed``, from the inside out: the proxy header, then one
    replay after a key rejection."""
    return Replay(with_enclave_url(keyed, host, base_url), buffer_bodies=True)


def replica_chain_async(keyed: httpx.AsyncBaseTransport, host: str, base_url: str) -> httpx.AsyncBaseTransport:
    return AsyncReplay(with_enclave_url_async(keyed, host, base_url), buffer_bodies=True)


def _sealed(request: httpx.Request, host: str) -> httpx.Request:
    headers = request.headers.copy()
    headers[SEAL_HEADER] = host
    return httpx.Request(
        request.method, request.url, headers=headers, stream=request.stream, extensions=request.extensions
    )


def _prepared_request(request: httpx.Request, prepared: Prepared) -> httpx.Request:
    if prepared.body is None:
        return httpx.Request(
            request.method, request.url, headers=prepared.headers, stream=request.stream, extensions=request.extensions
        )
    headers = prepared.headers
    headers.pop("Transfer-Encoding", None)
    headers["Content-Length"] = str(len(prepared.body))
    return httpx.Request(
        request.method, request.url, headers=headers, content=prepared.body, extensions=request.extensions
    )


def _reroute_failure(err: TinfoilError, host: str) -> TinfoilError:
    failure = type(err)(f"following gateway route to enclave {host}: {err.message}")
    failure.__cause__ = err
    return failure


class _CatalogCache:
    """Fetches the catalog on first use and refreshes it on use once ``CATALOG_REFRESH_INTERVAL`` has passed.
    Concurrent callers share one fetch. Until a fetch succeeds, callers wait for it and a failure is retried on
    the next use. After that, callers never wait: a stale catalog is returned while a refresh runs in the
    background, and a failed refresh keeps it for another interval. ``close`` starts no further refresh; one in
    flight finishes on its own, and its result is dropped."""

    def __init__(self, fetch: Callable[[TimeoutTypes], Catalog]) -> None:
        self._fetch = fetch
        self._lock = threading.Lock()
        self._catalog: Catalog | None = None
        self._refresh_at = 0.0
        self._inflight: threading.Event | None = None
        self._error: BaseException | None = None
        self._closed = False

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def get(self, timeout: TimeoutTypes) -> Catalog:
        with self._lock:
            if self._catalog is not None:
                if time.monotonic() >= self._refresh_at and self._inflight is None and not self._closed:
                    # Only this caller starts the refresh; moving the next refresh ahead now keeps later callers
                    # from starting another before this one finishes.
                    self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL
                    self._inflight = threading.Event()
                    threading.Thread(target=self._load, args=(timeout, self._inflight), daemon=True).start()
                return self._catalog
            inflight = self._inflight
            owner = inflight is None
            if inflight is None:
                inflight = self._inflight = threading.Event()
        if owner:
            self._load(timeout, inflight)
        else:
            inflight.wait()
        loaded, error = self._loaded()
        if loaded is not None:
            return loaded
        if error is None:  # pragma: no cover - a finished load leaves a catalog or an error
            raise network_error("gateway catalog is unavailable")
        raise error

    def _loaded(self) -> tuple[Catalog | None, BaseException | None]:
        with self._lock:
            return self._catalog, self._error

    def _load(self, timeout: TimeoutTypes, inflight: threading.Event) -> None:
        try:
            catalog = self._fetch(timeout)
        except BaseException as err:
            with self._lock:
                self._error = err
                if self._catalog is not None:
                    self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL
                self._inflight = None
            inflight.set()
            return
        with self._lock:
            if not self._closed:
                self._catalog = catalog
                self._error = None
                self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL
            self._inflight = None
        inflight.set()


class GatewayTransport(httpx.BaseTransport):
    """Seals each request to a verified replica of the model it names. Cache prefixes keep conversations on the
    same replica across requests."""

    def __init__(
        self,
        *,
        base_url: str,
        relay: str,
        catalog: Callable[[], Catalog] | None = None,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _build: Callable[[_Replica], ReplicaTransport] | None = None,
    ) -> None:
        self._build = _build
        self._shared: _Shared[ReplicaTransport] = _Shared(
            base_url=base_url,
            relay=relay,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            timeout=timeout,
        )
        self._supplied = catalog
        self._cache = _CatalogCache(lambda timeout: fetch_catalog(relay, timeout=timeout))
        self._closed = False

    @property
    def secret(self) -> str:
        return self._shared.secret

    @property
    def timeout(self) -> TimeoutTypes:
        return self._shared.timeout

    def catalog(self, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> Catalog:
        """The current catalog. Reading it evicts the replica transports of hosts a changed catalog no longer
        lists."""
        if self._supplied is not None:
            catalog = self._supplied()
        else:
            catalog = self._cache.get(self._shared.timeout if isinstance(timeout, UseClientDefault) else timeout)
        for transport in self._shared.evict(catalog):
            transport.chain.retire()
        return catalog

    def models(self, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT) -> list[str]:
        """The catalog's models that the policy serves, sorted, without verifying replicas. A failed catalog
        refresh does not fail it; only the first fetch can."""
        self._check_open()
        return self._shared.models_of(self.catalog(timeout))

    def ensure_verified(
        self, model: str, *, timeout: TimeoutTypes | UseClientDefault = USE_CLIENT_DEFAULT
    ) -> Verification:
        """A valid verification of a replica serving ``model``. Replicas are tried in a fixed order for the model,
        so repeated calls verify the same replica while it stays valid."""
        self._check_open()
        hosts, replica = self._shared.resolve(model, self.catalog(timeout))
        failure: TinfoilError | None = None
        for host in rank(hosts, model, ""):
            try:
                return self._verified(replace(replica, host=host), timeout)[1]
            except TinfoilError as err:
                failure = err
        assert failure is not None
        raise failure

    def verifications(self) -> list[ReplicaVerification]:
        """The last successful verification of each retained replica used so far, without checking them."""
        return self._shared.verifications(lambda transport: transport.keyed.current)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._check_open()
        # Each replica's transport makes the same check; making it here refuses a request before the catalog is
        # read or a replica verified.
        check_ehbp(request)
        content = _buffered(request)
        prepared = prepare(request.method, request.url.path, request.headers, content, self._shared.secret)
        request = _prepared_request(request, prepared)
        model = request.headers.get(MODEL_HEADER, "")
        hosts, replica = self._shared.resolve(model, self.catalog())
        can_replay = replayable(request)
        prefix = request.headers.get(CACHE_PREFIX_HEADER, "")
        transport: ReplicaTransport | None = None
        failure: TinfoilError | None = None
        for host in rank(hosts, prefix, self._shared.rerouted_host(prefix)):
            replica = replace(replica, host=host)
            try:
                transport = self._verified(replica, USE_CLIENT_DEFAULT)[0]
                break
            except TinfoilError as err:
                failure = err
        if transport is None:
            assert failure is not None
            raise failure
        redirects = 0
        while True:
            response = transport.handle_request(_sealed(request, replica.host))
            routed = response.headers.get(SEAL_HEADER, "")
            if response.status_code != 412 or not routed or routed == replica.host or not can_replay:
                return response
            response.close()
            if redirects == MAX_SEAL_REDIRECTS:
                raise NetworkError(
                    f"gateway kept routing away from the enclave the request was sealed to (last: {routed})"
                )
            redirects += 1
            replica = replace(replica, host=routed)
            try:
                transport = self._verified(replica, USE_CLIENT_DEFAULT)[0]
            except TinfoilError as err:
                raise _reroute_failure(err, routed) from err
            self._shared.remember(prefix, routed)

    def close(self) -> None:
        with self._shared.lock:
            self._closed = True
            transports = list(self._shared.enclaves.values())
            self._shared.enclaves = {}
        self._cache.close()
        for transport in transports:
            transport.chain.close()

    def _check_open(self) -> None:
        if self._closed:
            raise ConfigurationError("client is closed")

    def _transport(self, replica: _Replica) -> ReplicaTransport:
        with self._shared.lock:
            transport = self._shared.enclaves.get(replica)
            if transport is not None:
                return transport
            self._check_open()
            transport = self._shared.enclaves[replica] = (
                self._build(replica) if self._build is not None else self._new_transport(replica)
            )
            return transport

    def _new_transport(self, replica: _Replica) -> ReplicaTransport:
        keyed = AttestedTransport(self._shared.enclave_for(replica), EHBPMode(), timeout=self._shared.timeout)
        return ReplicaTransport(keyed, replica_chain(keyed, replica.host, self._shared.base_url))

    def _verified(
        self, replica: _Replica, timeout: TimeoutTypes | UseClientDefault
    ) -> tuple[ReplicaTransport, Verification]:
        """``replica``'s transport once its replica verifies, so a caller can fall over to another replica before
        sealing anything to it."""
        transport = self._transport(replica)
        return transport, transport.keyed.ensure_verified(timeout=timeout)


class _AsyncCatalogCache:
    """``_CatalogCache`` on the event loop. ``close`` also cancels a refresh in flight at its next await; one
    past its last await finishes, and its result is dropped."""

    def __init__(self, fetch: Callable[[TimeoutTypes], Awaitable[Catalog]]) -> None:
        self._fetch = fetch
        self._catalog: Catalog | None = None
        self._refresh_at = 0.0
        self._inflight: asyncio.Task[None] | None = None
        self._error: BaseException | None = None
        self._closed = False

    async def get(self, timeout: TimeoutTypes) -> Catalog:
        if self._catalog is not None:
            if time.monotonic() >= self._refresh_at and self._inflight is None and not self._closed:
                self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL
                self._start(timeout)
            return self._catalog
        if self._inflight is None:
            self._start(timeout)
        assert self._inflight is not None
        await asyncio.shield(self._inflight)
        loaded, error = self._loaded()
        if loaded is not None:
            return loaded
        if error is None:  # pragma: no cover - a finished load leaves a catalog or an error
            raise network_error("gateway catalog is unavailable")
        raise error

    def _loaded(self) -> tuple[Catalog | None, BaseException | None]:
        return self._catalog, self._error

    def _start(self, timeout: TimeoutTypes) -> None:
        task = asyncio.create_task(self._load(timeout))
        self._inflight = task
        task.add_done_callback(self._done)

    def _done(self, task: asyncio.Task[None]) -> None:
        if self._inflight is task:
            self._inflight = None
        if not task.cancelled():
            task.exception()

    async def _load(self, timeout: TimeoutTypes) -> None:
        try:
            catalog = await self._fetch(timeout)
        except BaseException as err:
            self._error = err
            if self._catalog is not None:
                self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL
            return
        if self._closed:
            return
        self._catalog = catalog
        self._error = None
        self._refresh_at = time.monotonic() + CATALOG_REFRESH_INTERVAL

    def close(self) -> None:
        self._closed = True
        if self._inflight is not None:
            self._inflight.cancel()


class AsyncGatewayTransport(httpx.AsyncBaseTransport):
    """``GatewayTransport`` for ``httpx.AsyncClient``."""

    def __init__(
        self,
        *,
        base_url: str,
        relay: str,
        catalog: Callable[[], Catalog] | None = None,
        model_pins: Mapping[str, ModelPin] | None = None,
        pinned_models_only: bool = False,
        verifier: Verifier | None = None,
        verification_check: VerificationCheck | None = None,
        user_cache_secret: str | None = None,
        timeout: TimeoutTypes = DEFAULT_HTTP_TIMEOUT,
        _build: Callable[[_Replica], AsyncReplicaTransport] | None = None,
    ) -> None:
        self._build = _build
        self._shared: _Shared[AsyncReplicaTransport] = _Shared(
            base_url=base_url,
            relay=relay,
            model_pins=model_pins,
            pinned_models_only=pinned_models_only,
            verifier=verifier,
            verification_check=verification_check,
            user_cache_secret=user_cache_secret,
            timeout=timeout,
        )
        self._supplied = catalog
        self._cache = _AsyncCatalogCache(lambda timeout: fetch_catalog_async(relay, timeout=timeout))
        self._closed = False

    @property
    def secret(self) -> str:
        return self._shared.secret

    @property
    def timeout(self) -> TimeoutTypes:
        return self._shared.timeout

    async def catalog(self) -> Catalog:
        if self._supplied is not None:
            catalog = self._supplied()
        else:
            catalog = await self._cache.get(self._shared.timeout)
        for transport in self._shared.evict(catalog):
            await transport.chain.retire()
        return catalog

    async def models(self) -> list[str]:
        """The catalog's models that the policy serves, sorted, without verifying replicas."""
        self._check_open()
        return self._shared.models_of(await self.catalog())

    async def ensure_verified(self, model: str) -> Verification:
        """A valid verification of a replica serving ``model``."""
        self._check_open()
        hosts, replica = self._shared.resolve(model, await self.catalog())
        failure: TinfoilError | None = None
        for host in rank(hosts, model, ""):
            try:
                return (await self._verified(replace(replica, host=host)))[1]
            except TinfoilError as err:
                failure = err
        assert failure is not None
        raise failure

    def verifications(self) -> list[ReplicaVerification]:
        return self._shared.verifications(lambda transport: transport.keyed.current)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._check_open()
        check_ehbp(request)
        content = await _buffered_async(request)
        prepared = prepare(request.method, request.url.path, request.headers, content, self._shared.secret)
        request = _prepared_request(request, prepared)
        model = request.headers.get(MODEL_HEADER, "")
        hosts, replica = self._shared.resolve(model, await self.catalog())
        can_replay = replayable(request)
        prefix = request.headers.get(CACHE_PREFIX_HEADER, "")
        transport: AsyncReplicaTransport | None = None
        failure: TinfoilError | None = None
        for host in rank(hosts, prefix, self._shared.rerouted_host(prefix)):
            replica = replace(replica, host=host)
            try:
                transport = (await self._verified(replica))[0]
                break
            except TinfoilError as err:
                failure = err
        if transport is None:
            assert failure is not None
            raise failure
        redirects = 0
        while True:
            response = await transport.handle_async_request(_sealed(request, replica.host))
            routed = response.headers.get(SEAL_HEADER, "")
            if response.status_code != 412 or not routed or routed == replica.host or not can_replay:
                return response
            await response.aclose()
            if redirects == MAX_SEAL_REDIRECTS:
                raise NetworkError(
                    f"gateway kept routing away from the enclave the request was sealed to (last: {routed})"
                )
            redirects += 1
            replica = replace(replica, host=routed)
            try:
                transport = (await self._verified(replica))[0]
            except TinfoilError as err:
                raise _reroute_failure(err, routed) from err
            self._shared.remember(prefix, routed)

    async def aclose(self) -> None:
        self._closed = True
        self._cache.close()
        transports = list(self._shared.enclaves.values())
        self._shared.enclaves = {}
        for transport in transports:
            await transport.chain.aclose()

    def _check_open(self) -> None:
        if self._closed:
            raise ConfigurationError("client is closed")

    def _transport(self, replica: _Replica) -> AsyncReplicaTransport:
        transport = self._shared.enclaves.get(replica)
        if transport is not None:
            return transport
        self._check_open()
        transport = self._shared.enclaves[replica] = (
            self._build(replica) if self._build is not None else self._new_transport(replica)
        )
        return transport

    def _new_transport(self, replica: _Replica) -> AsyncReplicaTransport:
        keyed = AsyncAttestedTransport(self._shared.enclave_for(replica), AsyncEHBPMode(), timeout=self._shared.timeout)
        return AsyncReplicaTransport(keyed, replica_chain_async(keyed, replica.host, self._shared.base_url))

    async def _verified(self, replica: _Replica) -> tuple[AsyncReplicaTransport, Verification]:
        transport = self._transport(replica)
        return transport, await transport.keyed.ensure_verified()


def _buffered(request: httpx.Request) -> bytes | None:
    """The body of a POST with a JSON or multipart content type, read into memory so it can be routed and
    replayed; None for any other request, whose body is forwarded as it is. A multipart upload is read only up
    to ``MAX_MULTIPART_BODY_SIZE``: one that declares a larger length is refused before any of it is read, and
    one that streams past the limit is refused at the byte that crosses it."""
    if request.method.upper() != "POST":
        return None
    media_type, _ = _media_type(request.headers.get("Content-Type", ""))
    if media_type not in ("application/json", "multipart/form-data"):
        return None
    if media_type == "multipart/form-data":
        if request.headers.get(MODEL_HEADER, ""):
            # Explicit routing keeps uploads streaming.
            return None
        _check_declared_length(request)
        if not replayable(request):
            assert isinstance(request.stream, httpx.SyncByteStream)
            body = bytearray()
            for chunk in request.stream:
                body += chunk
                _check_multipart_size(len(body))
            request.stream = httpx.ByteStream(bytes(body))
    request.read()
    if media_type == "multipart/form-data":
        _check_multipart_size(len(request.content))
    return request.content


async def _buffered_async(request: httpx.Request) -> bytes | None:
    if request.method.upper() != "POST":
        return None
    media_type, _ = _media_type(request.headers.get("Content-Type", ""))
    if media_type not in ("application/json", "multipart/form-data"):
        return None
    if media_type == "multipart/form-data":
        if request.headers.get(MODEL_HEADER, ""):
            return None
        _check_declared_length(request)
        if not replayable(request):
            assert isinstance(request.stream, httpx.AsyncByteStream)
            body = bytearray()
            async for chunk in request.stream:
                body += chunk
                _check_multipart_size(len(body))
            request.stream = httpx.ByteStream(bytes(body))
    await request.aread()
    if media_type == "multipart/form-data":
        _check_multipart_size(len(request.content))
    return request.content


def _check_declared_length(request: httpx.Request) -> None:
    """Refuses a multipart upload whose ``Content-Length`` is over the limit before reading any of it."""
    declared = request.headers.get("Content-Length", "")
    if declared.isdigit():
        _check_multipart_size(int(declared))


def _check_multipart_size(size: int) -> None:
    if size > MAX_MULTIPART_BODY_SIZE:
        raise ConfigurationError(f"multipart upload exceeds {MAX_MULTIPART_BODY_SIZE} bytes")


__all__ = [
    "CACHE_PREFIX_HEADER",
    "DEFAULT_GATEWAY_URL",
    "MODEL_HEADER",
    "SEAL_HEADER",
    "AsyncGatewayTransport",
    "Catalog",
    "CatalogEntry",
    "GatewayTransport",
    "ModelPin",
    "ReplicaVerification",
    "bearer_credential",
    "cache_prefix",
    "cache_salt",
    "fetch_catalog",
    "fetch_catalog_async",
    "multipart_model",
    "parse_catalog",
    "prepare",
    "prompt_head",
    "rank",
    "scope_cache",
]
