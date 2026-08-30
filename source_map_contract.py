from pathlib import Path

from loader_semantics import analyze_object_records
from source_map import (
    SourceMapError,
    _fingerprint,
    _write_atomic_text,
    build_source_map,
    default_source_map_path,
    render_source_map,
)


def _object_sections(obj_path):
    try:
        text = Path(obj_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceMapError(str(exc)) from exc
    records = tuple(line for line in text.splitlines() if line.strip())
    try:
        return analyze_object_records(records)
    except ValueError as exc:
        raise SourceMapError(f"Cannot align source map with invalid object program: {exc}") from exc


def build_object_aligned_source_map(expanded_path, int_path, obj_path, csects, parse_line):
    """Build source metadata whose public CSECT identity matches H records.

    Pass-1 internal names can differ from serialized compatibility names (for
    example DEFAULT -> DEFAUL for source without START). The source map must
    describe the actual object program consumed by the linker, not an internal
    assembler alias.
    """
    payload = build_source_map(expanded_path, int_path, obj_path, csects, parse_line)
    object_sections = _object_sections(obj_path)
    mapped_sections = payload["sections"]
    if len(mapped_sections) != len(object_sections):
        raise SourceMapError(
            "Source-map/object section count mismatch: "
            f"source={len(mapped_sections)}, object={len(object_sections)}"
        )

    for mapped, object_section in zip(mapped_sections, object_sections):
        expected_range = (mapped["source_start"], mapped["length"])
        object_range = (object_section["start"], object_section["length"])
        if expected_range != object_range:
            raise SourceMapError(
                f"Source-map/object range mismatch for section {mapped['section_index']}: "
                f"source={expected_range}, object={object_range}"
            )
        if mapped["name"] != object_section["name"]:
            mapped["assembler_section_name"] = mapped["name"]
            mapped["name"] = object_section["name"]

    payload.pop("source_map_fingerprint", None)
    payload["source_map_fingerprint"] = _fingerprint(b"SICXE-SOURCE-MAP-v1", payload)
    return payload


def write_object_aligned_source_map(
    expanded_path,
    int_path,
    obj_path,
    csects,
    parse_line,
    output_path=None,
):
    path = output_path or default_source_map_path(obj_path)
    source_map = build_object_aligned_source_map(
        expanded_path,
        int_path,
        obj_path,
        csects,
        parse_line,
    )
    return _write_atomic_text(path, render_source_map(source_map))
