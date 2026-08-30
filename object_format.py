import re


OBJECT_NAME_WIDTH = 6
MAX_OBJECT_RECORD_LENGTH = 73
_OBJECT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,5}$")


def validate_object_name(name, description="Object symbol"):
    """Validate a fixed-field SIC/XE object-program name and return it unchanged."""
    if not isinstance(name, str) or not _OBJECT_NAME_RE.fullmatch(name):
        raise ValueError(
            f"{description} must be 1-6 ASCII alphanumeric characters starting with a letter: {name}"
        )
    return name


def format_object_name(name, description="Object symbol"):
    """Return a validated six-character object-program name field."""
    return validate_object_name(name, description).ljust(OBJECT_NAME_WIDTH)


def parse_object_name_field(field, description="Object symbol"):
    """Validate one exact six-character object-program name field."""
    if len(field) != OBJECT_NAME_WIDTH:
        raise ValueError(f"{description} field must be exactly 6 characters")
    name = field.rstrip(" ")
    if field != name.ljust(OBJECT_NAME_WIDTH):
        raise ValueError(f"{description} field may only use trailing padding spaces")
    return validate_object_name(name, description)


def build_fixed_entry_records(record_type, entries, entry_width):
    """Split fixed-width entries across standard 73-character object records."""
    if len(record_type) != 1:
        raise ValueError("Object record type must be one character")
    if entry_width <= 0:
        raise ValueError("Object record entry width must be positive")
    per_record = (MAX_OBJECT_RECORD_LENGTH - 1) // entry_width
    if per_record <= 0:
        raise ValueError("Object record entry width exceeds record capacity")

    records = []
    for start in range(0, len(entries), per_record):
        chunk = entries[start:start + per_record]
        if any(len(entry) != entry_width for entry in chunk):
            raise ValueError(f"{record_type} record contains an invalid entry width")
        records.append(record_type + "".join(chunk))
    return records
