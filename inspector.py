import hashlib
import json
from pathlib import Path

from disassembler import disassemble
from linked_image import MANIFEST_SCHEMA
from loader_semantics import analyze_object_records


class InspectionError(ValueError):
    pass


def _read_object(path):
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise InspectionError(str(exc)) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InspectionError(f"Object program is not valid UTF-8: {path}") from exc
    records = tuple(line for line in text.splitlines() if line.strip())
    try:
        sections = analyze_object_records(records)
    except ValueError as exc:
        raise InspectionError(f"Invalid object program {path}: {exc}") from exc
    return raw, records, sections


def inspect_object_file(path, include_disassembly=False, base_register=None):
    raw, records, sections = _read_object(path)
    inspected_sections = []
    total_text_bytes = 0
    total_modifications = 0

    for section in sections:
        texts = []
        for text in section["texts"]:
            total_text_bytes += text["length"]
            entry = {
                "address": text["address"],
                "offset": text["offset"],
                "length": text["length"],
                "data_hex": text["data"].hex().upper(),
                "record": text["record"],
            }
            if include_disassembly:
                decoded = disassemble(
                    text["data"],
                    start_address=text["address"],
                    base_register=base_register,
                )
                rendered = []
                for instruction in decoded:
                    mods = [
                        modification["record"]
                        for modification in section["modifications"]
                        if instruction.address
                        <= modification["address"]
                        < instruction.address + instruction.size
                    ]
                    rendered.append({
                        "address": instruction.address,
                        "size": instruction.size,
                        "bytes_hex": instruction.bytes_hex,
                        "mnemonic": instruction.mnemonic,
                        "operand": instruction.operand,
                        "format": instruction.format,
                        "flags": instruction.flags,
                        "target": instruction.target,
                        "warning": instruction.warning,
                        "modifications": tuple(mods),
                    })
                entry["disassembly"] = tuple(rendered)
            texts.append(entry)

        modifications = tuple(
            {
                "address": item["address"],
                "offset": item["offset"],
                "half_bytes": item["half_bytes"],
                "sign": item["sign"],
                "symbol": item["symbol"],
                "record": item["record"],
            }
            for item in section["modifications"]
        )
        total_modifications += len(modifications)
        inspected_sections.append({
            "name": section["name"],
            "start": section["start"],
            "length": section["length"],
            "definitions": tuple(section["definitions"]),
            "references": tuple(sorted(section["references"])),
            "texts": tuple(texts),
            "modifications": modifications,
            "execution_address": section["execution_address"],
        })

    return {
        "kind": "object-program",
        "file": str(path),
        "byte_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "record_count": len(records),
        "section_count": len(inspected_sections),
        "text_bytes": total_text_bytes,
        "modification_count": total_modifications,
        "sections": tuple(inspected_sections),
    }


def _format_instruction(item):
    assembly = item["mnemonic"]
    if item["operand"]:
        assembly += " " + item["operand"]
    details = []
    if item["flags"]:
        details.append(f"nixbpe={item['flags']}")
    if item["target"] is not None:
        details.append(f"target={item['target']:05X}")
    if item["modifications"]:
        details.append("M=" + ",".join(item["modifications"]))
    if item["warning"]:
        details.append(item["warning"])
    suffix = f" ; {'; '.join(details)}" if details else ""
    return f"      {item['address']:05X}  {item['bytes_hex'].ljust(8)}  {assembly}{suffix}"


def render_object_inspection(report):
    lines = [
        "SIC/XE OBJECT INSPECTION",
        f"FILE       {report['file']}",
        f"SHA256     {report['sha256']}",
        f"BYTES      {report['byte_length']}",
        f"RECORDS    {report['record_count']}",
        "",
    ]
    for index, section in enumerate(report["sections"]):
        end = section["start"] + section["length"]
        lines.append(
            f"SECTION {index} {section['name']}  {section['start']:06X}-{end:06X} "
            f"len={section['length']:06X}"
        )
        if section["definitions"]:
            defs = ", ".join(f"{name}={offset:06X}" for name, offset in section["definitions"])
            lines.append(f"  D  {defs}")
        if section["references"]:
            lines.append("  R  " + ", ".join(section["references"]))
        for text in section["texts"]:
            lines.append(
                f"  T  {text['address']:06X} len={text['length']:02X} {text['data_hex']}"
            )
            for instruction in text.get("disassembly", ()):
                lines.append(_format_instruction(instruction))
        for modification in section["modifications"]:
            lines.append(
                f"  M  {modification['address']:06X} width={modification['half_bytes']:02X} "
                f"{modification['sign']}{modification['symbol']}"
            )
        if section["execution_address"] is None:
            lines.append("  E  <none>")
        else:
            lines.append(f"  E  {section['execution_address']:06X}")
        lines.append("")
    lines.append(
        "SUMMARY "
        f"sections={report['section_count']} records={report['record_count']} "
        f"text_bytes={report['text_bytes']} modifications={report['modification_count']}"
    )
    return "\n".join(lines) + "\n"


def _require_fields(mapping, fields, description):
    if not isinstance(mapping, dict):
        raise InspectionError(f"{description} must be a JSON object")
    missing = [field for field in fields if field not in mapping]
    if missing:
        raise InspectionError(
            f"{description} is missing required field(s): {', '.join(missing)}"
        )


def _validate_manifest_shape(manifest):
    _require_fields(
        manifest,
        (
            "schema",
            "progaddr",
            "image_start",
            "image_end_exclusive",
            "image_length",
            "image_sha256",
            "input_fingerprint",
            "link_fingerprint",
            "entry",
            "inputs",
            "sections",
        ),
        "Image manifest",
    )
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise InspectionError(
            f"Unsupported image manifest schema: {manifest['schema']!r}"
        )
    for field in ("progaddr", "image_start", "image_end_exclusive", "image_length"):
        if not isinstance(manifest[field], int) or isinstance(manifest[field], bool):
            raise InspectionError(f"Image manifest field {field} must be an integer")
    if manifest["image_length"] < 0:
        raise InspectionError("Image manifest image_length must be non-negative")
    if manifest["image_end_exclusive"] != manifest["image_start"] + manifest["image_length"]:
        raise InspectionError(
            "Image manifest range is inconsistent with image_length"
        )
    if manifest["progaddr"] != manifest["image_start"]:
        raise InspectionError("Image manifest PROGADDR does not match image_start")
    if not isinstance(manifest["inputs"], list):
        raise InspectionError("Image manifest inputs must be a JSON array")
    if not isinstance(manifest["sections"], list):
        raise InspectionError("Image manifest sections must be a JSON array")

    _require_fields(manifest["entry"], ("kind", "address"), "Image manifest entry")
    for index, item in enumerate(manifest["inputs"]):
        _require_fields(
            item,
            ("input_index", "byte_length", "sha256"),
            f"Image manifest input {index}",
        )
    for index, section in enumerate(manifest["sections"]):
        _require_fields(
            section,
            (
                "input_index",
                "section_index",
                "name",
                "source_start",
                "load_address",
                "length",
            ),
            f"Image manifest section {index}",
        )
    if manifest["entry"].get("kind") == "explicit":
        _require_fields(
            manifest["entry"],
            ("input_index", "section_index", "section", "source_address"),
            "Explicit image manifest entry",
        )


def _read_manifest(path):
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise InspectionError(str(exc)) from exc
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InspectionError(f"Invalid JSON manifest {path}: {exc}") from exc
    _validate_manifest_shape(manifest)
    return raw, manifest


def inspect_image_manifest(path, image_path=None):
    raw, manifest = _read_manifest(path)
    report = {
        "kind": "linked-image-manifest",
        "file": str(path),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "schema": manifest["schema"],
        "progaddr": manifest["progaddr"],
        "image_start": manifest["image_start"],
        "image_end_exclusive": manifest["image_end_exclusive"],
        "image_length": manifest["image_length"],
        "image_sha256": manifest["image_sha256"],
        "input_fingerprint": manifest["input_fingerprint"],
        "link_fingerprint": manifest["link_fingerprint"],
        "entry": manifest["entry"],
        "inputs": tuple(manifest["inputs"]),
        "sections": tuple(manifest["sections"]),
        "image": None,
    }

    if image_path is not None:
        try:
            image = Path(image_path).read_bytes()
        except OSError as exc:
            raise InspectionError(str(exc)) from exc
        actual_sha = hashlib.sha256(image).hexdigest()
        report["image"] = {
            "file": str(image_path),
            "byte_length": len(image),
            "sha256": actual_sha,
            "length_matches": len(image) == manifest["image_length"],
            "sha256_matches": actual_sha == manifest["image_sha256"],
        }
    return report


def render_manifest_inspection(report):
    lines = [
        "SIC/XE LINKED IMAGE INSPECTION",
        f"MANIFEST   {report['file']}",
        f"SCHEMA     {report['schema']}",
        f"PROGADDR   {report['progaddr']:05X}",
        f"IMAGE      {report['image_start']:05X}-{report['image_end_exclusive']:05X} "
        f"len={report['image_length']}",
        f"IMAGE_SHA  {report['image_sha256']}",
        f"INPUTSET   {report['input_fingerprint']}",
        f"LINKID     {report['link_fingerprint']}",
    ]
    entry = report["entry"]
    if entry.get("kind") == "explicit":
        lines.append(
            f"ENTRY      {entry['address']:05X} explicit "
            f"[{entry['input_index']}:{entry['section_index']}] {entry['section']} "
            f"source={entry['source_address']:06X}"
        )
    else:
        lines.append(f"ENTRY      {entry['address']:05X} default PROGADDR")

    lines.extend(["", "INPUTS"])
    for item in report["inputs"]:
        lines.append(
            f"  [{item['input_index']}] bytes={item['byte_length']} sha256={item['sha256']}"
        )

    lines.extend(["", "SECTIONS"])
    for section in report["sections"]:
        end = section["load_address"] + section["length"]
        lines.append(
            f"  [{section['input_index']}:{section['section_index']}] {section['name']} "
            f"source={section['source_start']:06X} load={section['load_address']:05X}-{end:05X} "
            f"len={section['length']:05X}"
        )

    image = report["image"]
    if image is not None:
        lines.extend([
            "",
            "IMAGE FILE",
            f"  FILE       {image['file']}",
            f"  BYTES      {image['byte_length']}",
            f"  SHA256     {image['sha256']}",
            f"  LENGTH_OK  {'yes' if image['length_matches'] else 'NO'}",
            f"  SHA256_OK  {'yes' if image['sha256_matches'] else 'NO'}",
        ])
    return "\n".join(lines) + "\n"
