import hashlib
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


def _attach_original_provenance(payload, original_source_path, macro_trace):
    if original_source_path is None or macro_trace is None:
        return

    try:
        original_bytes = Path(original_source_path).read_bytes()
    except OSError as exc:
        raise SourceMapError(str(exc)) from exc

    expanded_lines = Path(original_source_path).with_suffix(".expanded.asm")
    # The expanded path itself is already hashed by build_source_map; here we
    # only require trace indices to be contiguous and unique.
    by_line = {}
    for expected_line, item in enumerate(macro_trace, 1):
        expanded_line = item.get("expanded_line")
        if expanded_line != expected_line:
            raise SourceMapError(
                "Macro provenance expanded-line indices must be contiguous: "
                f"expected {expected_line}, received {expanded_line}"
            )
        if expanded_line in by_line:
            raise SourceMapError(f"Duplicate macro provenance line {expanded_line}")
        by_line[expanded_line] = item

    payload["original_source_sha256"] = hashlib.sha256(original_bytes).hexdigest()

    for section in payload["sections"]:
        for region in section["regions"]:
            expanded_line = region.get("expanded_line")
            if expanded_line is None:
                region["provenance"] = None
                continue
            origin = by_line.get(expanded_line)
            if origin is None:
                raise SourceMapError(
                    f"Macro provenance has no expanded line {expanded_line}"
                )
            stack = [dict(frame) for frame in origin.get("macro_stack", ())]
            region["provenance"] = {
                "kind": "macro" if stack else "direct",
                "source_line": origin.get("source_line"),
                "definition_line": origin.get("definition_line"),
                "generated": origin.get("generated"),
                "macro_stack": stack,
            }


def build_object_aligned_source_map(
    expanded_path,
    int_path,
    obj_path,
    csects,
    parse_line,
    original_source_path=None,
    macro_trace=None,
):
    """Build source metadata whose public CSECT identity matches H records.

    Pass-1 internal names can differ from serialized compatibility names (for
    example DEFAULT -> DEFAUL for source without START). The source map must
    describe the actual object program consumed by the linker, not an internal
    assembler alias. Optional macro provenance is attached only after final
    expanded-line mapping, so literal-pool rows inherit the LTORG/CSECT/END
    statement that materialized them.
    """
    payload = build_source_map(expanded_path, int_path, obj_path, csects, parse_line)
    _attach_original_provenance(payload, original_source_path, macro_trace)
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
    original_source_path=None,
    macro_trace=None,
):
    path = output_path or default_source_map_path(obj_path)
    source_map = build_object_aligned_source_map(
        expanded_path,
        int_path,
        obj_path,
        csects,
        parse_line,
        original_source_path=original_source_path,
        macro_trace=macro_trace,
    )
    return _write_atomic_text(path, render_source_map(source_map))
