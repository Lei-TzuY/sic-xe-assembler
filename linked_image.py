import hashlib
import json
import os
from pathlib import Path


MANIFEST_SCHEMA = "sicxe-linked-image-v1"


def default_image_path(obj_files):
    """Return the deterministic binary image path for one link invocation."""
    if not obj_files:
        raise ValueError("At least one object file is required for a linked image")
    return str(Path(obj_files[0]).with_suffix('.bin'))


def default_manifest_path(obj_files):
    """Return the deterministic image-manifest path for one link invocation."""
    if not obj_files:
        raise ValueError("At least one object file is required for an image manifest")
    return str(Path(obj_files[0]).with_suffix('.manifest.json'))


def extract_linked_image(plan, memory):
    """Return exactly the linked address range as deterministic raw bytes."""
    start = plan.progaddr
    end = start + plan.total_length
    if start < 0 or end < start or end > len(memory):
        raise ValueError(
            f"Linked image range {start:05X}-{end:05X} exceeds memory size {len(memory):05X}"
        )
    return bytes(memory[start:end])


def _entry_manifest(plan):
    if plan.execution_source is None:
        return {
            "kind": "default-progaddr",
            "address": plan.execution_address,
        }

    for section in plan.sections:
        if section.source_execution_address is None:
            continue
        if section.loaded_execution_address != plan.execution_address:
            continue
        return {
            "kind": "explicit",
            "address": plan.execution_address,
            "input_index": section.input_index,
            "section_index": section.section_index,
            "section": section.name,
            "source_address": section.source_execution_address,
        }

    raise ValueError(
        "Explicit execution address has no matching planned-section provenance"
    )


def build_image_manifest(plan, image_bytes):
    """Build path-independent metadata proving the exact linked output bytes."""
    image = bytes(image_bytes)
    if len(image) != plan.total_length:
        raise ValueError(
            "Linked image length does not match validated load plan: "
            f"expected {plan.total_length}, received {len(image)}"
        )

    return {
        "schema": MANIFEST_SCHEMA,
        "progaddr": plan.progaddr,
        "image_start": plan.progaddr,
        "image_end_exclusive": plan.progaddr + len(image),
        "image_length": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "input_fingerprint": plan.input_fingerprint,
        "link_fingerprint": plan.link_fingerprint,
        "entry": _entry_manifest(plan),
        "inputs": [
            {
                "input_index": snapshot.input_index,
                "byte_length": snapshot.byte_length,
                "sha256": snapshot.sha256,
            }
            for snapshot in plan.inputs
        ],
        "sections": [
            {
                "input_index": section.input_index,
                "section_index": section.section_index,
                "name": section.name,
                "source_start": section.source_start,
                "load_address": section.load_address,
                "length": section.length,
            }
            for section in plan.sections
        ],
    }


def render_image_manifest(plan, image_bytes):
    """Render a stable UTF-8 JSON manifest with no host-path dependence."""
    return json.dumps(
        build_image_manifest(plan, image_bytes),
        indent=2,
        sort_keys=True,
    ) + "\n"


def _write_atomic_bytes(path, payload):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return str(target)


def _write_atomic_text(path, text):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return str(target)


def write_linked_image_artifacts(plan, memory, image_path, manifest_path):
    """Write the validated image slice and its reproducibility manifest."""
    image = extract_linked_image(plan, memory)
    manifest = render_image_manifest(plan, image)
    written_image = _write_atomic_bytes(image_path, image)
    written_manifest = _write_atomic_text(manifest_path, manifest)
    return written_image, written_manifest
