import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from linked_image import (
    MANIFEST_SCHEMA,
    build_image_manifest,
    extract_linked_image,
    render_image_manifest,
)
from load_plan import LoadPlanError, build_load_plan, capture_link_session
from loader import apply_load_plan


class ArtifactVerificationError(ValueError):
    """Raised when linked artifacts cannot be reproduced or authenticated."""


@dataclass(frozen=True)
class ArtifactVerificationResult:
    image_sha256: str
    input_fingerprint: str
    link_fingerprint: str
    progaddr: int
    entry_address: int
    image_length: int
    section_count: int
    input_count: int


def _read_manifest(path):
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ArtifactVerificationError(str(exc)) from exc
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ArtifactVerificationError(
            f"Invalid JSON manifest {path}: {exc.msg} at line {exc.lineno} column {exc.colno}"
        ) from exc
    if not isinstance(manifest, dict):
        raise ArtifactVerificationError("Image manifest root must be a JSON object")
    return raw, manifest


def _require_manifest_header(manifest):
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ArtifactVerificationError(
            f"Unsupported image manifest schema: {manifest.get('schema')!r}; expected {MANIFEST_SCHEMA}"
        )
    progaddr = manifest.get("progaddr")
    if not isinstance(progaddr, int) or isinstance(progaddr, bool):
        raise ArtifactVerificationError("Image manifest progaddr must be an integer")
    return progaddr


def _read_image(path):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ArtifactVerificationError(str(exc)) from exc


def verify_linked_artifacts(image_path, manifest_path, obj_files):
    """Reproduce one linked image and prove all persisted artifacts match exactly.

    Verification is intentionally independent of the original `.map` file.  The
    object inputs are captured again, a fresh load plan is built from the
    manifest PROGADDR, memory is rematerialized, and both the binary bytes and
    canonical manifest are compared byte-for-byte with the supplied artifacts.
    """
    if not obj_files:
        raise ArtifactVerificationError("At least one object input is required")

    image = _read_image(image_path)
    manifest_raw, manifest = _read_manifest(manifest_path)
    progaddr = _require_manifest_header(manifest)

    declared_sha = manifest.get("image_sha256")
    actual_sha = hashlib.sha256(image).hexdigest()
    if declared_sha != actual_sha:
        raise ArtifactVerificationError(
            "Linked image SHA-256 mismatch: "
            f"manifest={declared_sha!r}, actual={actual_sha}"
        )

    try:
        session = capture_link_session(obj_files)
        plan = build_load_plan(session, progaddr)
    except LoadPlanError as exc:
        raise ArtifactVerificationError(f"Object inputs cannot reproduce link: {exc}") from exc

    if manifest.get("input_fingerprint") != plan.input_fingerprint:
        raise ArtifactVerificationError(
            "INPUTSET mismatch: "
            f"manifest={manifest.get('input_fingerprint')!r}, "
            f"recomputed={plan.input_fingerprint}"
        )
    if manifest.get("link_fingerprint") != plan.link_fingerprint:
        raise ArtifactVerificationError(
            "LINKID mismatch: "
            f"manifest={manifest.get('link_fingerprint')!r}, "
            f"recomputed={plan.link_fingerprint}"
        )

    memory, entry_address = apply_load_plan(plan)
    reproduced_image = extract_linked_image(plan, memory)
    if image != reproduced_image:
        expected_sha = hashlib.sha256(reproduced_image).hexdigest()
        first_difference = next(
            (
                index
                for index, (actual, expected) in enumerate(zip(image, reproduced_image))
                if actual != expected
            ),
            min(len(image), len(reproduced_image)),
        )
        raise ArtifactVerificationError(
            "Linked image is not reproducible from supplied object inputs: "
            f"first difference at image offset 0x{first_difference:X}; "
            f"artifact sha256={actual_sha}, reproduced sha256={expected_sha}"
        )

    expected_manifest = build_image_manifest(plan, reproduced_image)
    if manifest != expected_manifest:
        keys = sorted(set(manifest) | set(expected_manifest))
        differing = next(
            (
                key
                for key in keys
                if manifest.get(key, object()) != expected_manifest.get(key, object())
            ),
            "unknown",
        )
        raise ArtifactVerificationError(
            f"Image manifest metadata does not match reproduced link at field {differing!r}"
        )

    canonical_manifest = render_image_manifest(plan, reproduced_image)
    if manifest_raw != canonical_manifest:
        raise ArtifactVerificationError(
            "Image manifest JSON is semantically valid but not in canonical deterministic form"
        )

    return ArtifactVerificationResult(
        image_sha256=actual_sha,
        input_fingerprint=plan.input_fingerprint,
        link_fingerprint=plan.link_fingerprint,
        progaddr=plan.progaddr,
        entry_address=entry_address,
        image_length=len(image),
        section_count=len(plan.sections),
        input_count=len(plan.inputs),
    )
