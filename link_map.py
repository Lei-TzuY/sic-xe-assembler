import os
from pathlib import Path


def default_map_path(obj_files):
    """Return the deterministic map path for one link invocation."""
    if not obj_files:
        raise ValueError("At least one object file is required for a link map")
    return str(Path(obj_files[0]).with_suffix('.map'))


def _image_end(plan):
    return plan.progaddr + plan.total_length


def _symbol_kind(plan, symbol):
    section_names = {section.name for section in plan.sections}
    return "CSECT" if symbol in section_names else "EXTDEF"


def _reference_index(plan):
    references = {}
    for section in plan.sections:
        for relocation in section.relocations:
            loaded_site = section.load_address + relocation.offset
            for sign, symbol in relocation.symbols:
                references.setdefault(symbol, []).append({
                    'sign': sign,
                    'section': section.name,
                    'file_path': section.file_path,
                    'source_address': relocation.address,
                    'loaded_address': loaded_site,
                    'half_bytes': relocation.half_bytes,
                })
    return references


def render_link_map(plan):
    """Render a stable human-readable cross-reference report for a load plan."""
    lines = []
    lines.append("SIC/XE LINK MAP")
    lines.append("=" * 88)
    lines.append(f"PROGADDR  {plan.progaddr:05X}")
    lines.append(f"INPUTSET  {plan.input_fingerprint}")
    lines.append(f"LINKID    {plan.link_fingerprint}")
    lines.append(
        f"IMAGE     {plan.progaddr:05X}-{_image_end(plan):05X} "
        f"(end-exclusive, length={plan.total_length:05X})"
    )
    if plan.execution_source is None:
        lines.append(f"ENTRY     {plan.execution_address:05X}  default PROGADDR")
    else:
        lines.append(
            f"ENTRY     {plan.execution_address:05X}  {plan.execution_source}"
        )

    lines.append("")
    lines.append("INPUT SNAPSHOTS")
    lines.append("-" * 88)
    lines.append("IDX   BYTES      SHA256                                                           FILE")
    for snapshot in plan.inputs:
        lines.append(
            f"{snapshot.input_index:<5} {snapshot.byte_length:<10} "
            f"{snapshot.sha256}  {snapshot.file_path}"
        )

    lines.append("")
    lines.append("CONTROL SECTIONS")
    lines.append("-" * 88)
    lines.append("IDX   NAME    LOAD   END    LENGTH SOURCE  FILE")
    for section in plan.sections:
        lines.append(
            f"{section.input_index}:{section.section_index:<3} "
            f"{section.name:<7} "
            f"{section.load_address:05X}  "
            f"{section.load_address + section.length:05X}  "
            f"{section.length:05X}  "
            f"{section.source_start:05X}  "
            f"{section.file_path}"
        )

    lines.append("")
    lines.append("EXTERNAL SYMBOLS")
    lines.append("-" * 88)
    lines.append("SYMBOL   KIND    ADDRESS  DEFINED BY")
    for symbol in sorted(plan.estab):
        lines.append(
            f"{symbol:<8} {_symbol_kind(plan, symbol):<7} "
            f"{plan.estab[symbol]:05X}    {plan.symbol_sources[symbol]}"
        )

    reference_index = _reference_index(plan)
    lines.append("")
    lines.append("CROSS REFERENCES")
    lines.append("-" * 88)
    for symbol in sorted(plan.estab):
        uses = reference_index.get(symbol, ())
        if not uses:
            lines.append(f"{symbol:<8} (no relocation references)")
            continue
        lines.append(f"{symbol:<8} {len(uses)} relocation term(s)")
        for use in uses:
            lines.append(
                f"  {use['sign']}{symbol:<7} from {use['section']:<6} "
                f"source={use['source_address']:06X} "
                f"load={use['loaded_address']:05X} "
                f"width={use['half_bytes']:02X}  {use['file_path']}"
            )

    lines.append("")
    lines.append("UNUSED R DECLARATIONS")
    lines.append("-" * 88)
    unused_count = 0
    for section in plan.sections:
        if not section.unused_references:
            continue
        unused_count += len(section.unused_references)
        lines.append(
            f"{section.name:<7} {', '.join(section.unused_references)}  "
            f"({section.file_path})"
        )
    if unused_count == 0:
        lines.append("(none)")

    lines.append("")
    lines.append("RELOCATIONS")
    lines.append("-" * 88)
    relocation_count = 0
    for section in plan.sections:
        for relocation in section.relocations:
            relocation_count += 1
            terms = " ".join(
                f"{sign}{symbol}" for sign, symbol in relocation.symbols
            ) or "(none)"
            lines.append(
                f"{section.name:<7} "
                f"source={relocation.address:06X} "
                f"load={section.load_address + relocation.offset:05X} "
                f"width={relocation.half_bytes:02X} "
                f"addend={relocation.addend} "
                f"delta={relocation.delta} "
                f"final={relocation.relocated} "
                f"encoded={relocation.encoded:06X}"
            )
            lines.append(f"  terms: {terms}")
    if relocation_count == 0:
        lines.append("(none)")

    lines.append("")
    lines.append(
        f"SUMMARY sections={len(plan.sections)} symbols={len(plan.estab)} "
        f"relocations={relocation_count} unused_R={unused_count} "
        f"inputs={len(plan.inputs)}"
    )
    return "\n".join(lines) + "\n"


def write_link_map(plan, path):
    """Atomically write a deterministic link map and return its path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(render_link_map(plan), encoding="utf-8")
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return str(target)
