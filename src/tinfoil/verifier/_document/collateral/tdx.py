"""Intel TDX endorsement collateral: captured PCS responses, replayed instead of fetched."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tinfoil.verifier import _json
from tinfoil.verifier._canonical import EncodingError, decode_base64
from tinfoil.verifier._document.collateral.entry import Entry, unmarshal_data


@dataclass(frozen=True, slots=True)
class PCSResponse:
    """One captured Intel PCS response. Headers are kept because Intel delivers issuer chains in response headers."""

    url: str
    headers: Mapping[str, tuple[str, ...]]
    body: bytes


@dataclass(frozen=True, slots=True)
class IntelPCS:
    """Decoded intel-pcs collateral."""

    responses: tuple[PCSResponse, ...]


_PCS_MEMBERS = ("responses",)
_RESPONSE_MEMBERS = ("url", "headers", "body_base64")


def decode_intel_pcs(entry: Entry) -> IntelPCS:
    data = unmarshal_data(entry, "intel-pcs", _PCS_MEMBERS)
    responses: list[PCSResponse] = []
    try:
        for index, item in enumerate(_json.array(data, "responses") or ()):
            response = _json.object_(item, "response", _RESPONSE_MEMBERS)
            headers = _json.mapping(response, "headers", _header_values)
            try:
                body = decode_base64("body_base64", _json.string(response, "body_base64"))
            except EncodingError as err:
                raise EncodingError(f"intel-pcs collateral entry {entry.id!r} response {index}: {err}") from err
            responses.append(
                PCSResponse(url=_json.string(response, "url"), headers=MappingProxyType(headers), body=body)
            )
    except _json.JsonError as err:
        raise _json.JsonError(f"parsing intel-pcs collateral entry {entry.id!r}: {err}") from err
    return IntelPCS(responses=tuple(responses))


def _header_values(value: _json.JsonValue, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, tuple):
        raise _json.JsonError(f"cannot unmarshal JSON value into header {name!r}")
    out: list[str] = []
    for item in value:
        if item is None:
            out.append("")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise _json.JsonError(f"cannot unmarshal JSON value into string within header {name!r}")
    return tuple(out)
