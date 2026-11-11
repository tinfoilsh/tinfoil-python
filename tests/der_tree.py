"""A small DER tree codec for building mutation probes in tests.

A node is ``(identifier, children)`` for a constructed element or
``(identifier, content)`` for a primitive one. ``encode`` recomputes every
length, so a mutated tree re-serializes with consistent lengths; the
mutation itself may be anything, DER-valid or not.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import TypeAlias

Node: TypeAlias = tuple[int, "list[Node] | bytes"]


def parse(data: bytes, offset: int = 0) -> tuple[Node, int]:
    identifier = data[offset]
    first = data[offset + 1]
    position = offset + 2
    if first & 0x80:
        count = first & 0x7F
        length = int.from_bytes(data[position : position + count], "big")
        position += count
    else:
        length = first
    content = data[position : position + length]
    end = position + length
    if identifier & 0x20:
        children: list[Node] = []
        cursor = 0
        while cursor < len(content):
            child, cursor = parse(content, cursor)
            children.append(child)
        return (identifier, children), end
    return (identifier, content), end


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def encode(node: Node) -> bytes:
    identifier, body = node
    content = b"".join(encode(child) for child in body) if isinstance(body, list) else body
    return bytes([identifier]) + encode_length(len(content)) + content


def children(node: Node) -> list[Node]:
    body = node[1]
    assert isinstance(body, list)
    return body


def mutate(data: bytes, change: Callable[[Node], None]) -> bytes:
    """Parse ``data``, apply ``change`` to a deep copy of the tree and re-encode it."""
    tree, end = parse(data)
    assert end == len(data)
    assert encode(tree) == data
    copied = copy.deepcopy(tree)
    change(copied)
    return encode(copied)
