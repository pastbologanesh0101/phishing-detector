"""Small shared utilities (pure stdlib, no dependencies)."""


def levenshtein_distance(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute), iterative DP.

    Used for typosquat detection: brand impersonation domains are usually
    one or two character edits away from the real domain
    (e.g. "paypa1.com" vs "paypal.com", "faceb00k.com" vs "facebook.com").
    """
    a, b = a or "", b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (0 if ca == cb else 1)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]
