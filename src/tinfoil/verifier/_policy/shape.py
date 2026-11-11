"""The VM shape that a platform measurement was taken for, and the host stack that produced it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Shape:
    """The canonical VM shape descriptor: the launch dimensions that determine a platform measurement.

    ``disks`` counts every attached disk (root, config, external config, one
    per model). ``gpus`` is None when the dimension is unknown for a measured
    slug; a code artifact always declares it.
    """

    cpus: int
    memory_mb: int
    disks: int
    gpus: int | None = None

    def satisfies(self, required: Shape | None) -> bool:
        """Whether this measured slug shape satisfies the shape that a code artifact requires."""
        return satisfies(self, required)


def satisfies(shape: Shape | None, required: Shape | None) -> bool:
    """Whether a measured slug shape satisfies a required shape. GPUs are compared only when both declare them."""
    if shape is None or required is None:
        return False
    if shape.cpus != required.cpus or shape.memory_mb != required.memory_mb or shape.disks != required.disks:
        return False
    return not (shape.gpus is not None and required.gpus is not None and shape.gpus != required.gpus)


def format_shape(shape: Shape) -> str:
    """A shape for error messages, one labeled dimension at a time."""
    gpus = "<nil>" if shape.gpus is None else str(shape.gpus)
    return f"{{CPUs:{shape.cpus} MemoryMB:{shape.memory_mb} GPUs:{gpus} Disks:{shape.disks}}}"


@dataclass(frozen=True, slots=True)
class Stack:
    """The host software that produced a measurement. Informational and never checked."""

    qemu: str = ""
    ovmf: str = ""
