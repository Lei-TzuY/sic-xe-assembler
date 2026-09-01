import guarded_transfers as _legacy
from static_analysis import CONDITION_VALUES


def conjunctive_case_feasible(
    case,
    register_exact,
    register_ranges,
    memory_exact,
    memory_ranges,
):
    """Evaluate repeated guards on one comparison as a conjunction.

    A guarded path can contain multiple conditional branches driven by the
    same COMP/COMPR result. Evaluating those guards independently is too weak:
    `{LT,GT}` followed by `{EQ,GT}` means `GT`, not "either guard overlaps".
    Group identical symbolic comparisons and intersect their allowed CC sets
    before applying the existing exact/range guard evaluator.
    """
    grouped = {}
    for guard in case.get("guards", ()):
        key = (
            repr(guard.get("left")),
            repr(guard.get("right")),
        )
        allowed = set(guard.get("allowed") or ())
        if key not in grouped:
            grouped[key] = [guard, allowed]
        else:
            grouped[key][1].intersection_update(allowed)

    for guard, allowed in grouped.values():
        if not allowed:
            return False
        combined = {
            "left": guard.get("left"),
            "right": guard.get("right"),
            "allowed": [
                value
                for value in CONDITION_VALUES
                if value in allowed
            ],
        }
        if not _legacy._guard_feasible(
            combined,
            register_exact,
            register_ranges,
            memory_exact,
            memory_ranges,
        ):
            return False
    return True
