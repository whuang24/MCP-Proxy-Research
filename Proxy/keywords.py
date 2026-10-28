import re

STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "to", "of", "in",
    "on", "for", "and", "or", "with", "this", "that", "please", "can",
}

# Terms worth flagging for later review -- not blocked, just surfaced
WATCHLIST = [
    "delete", "remove", "drop", "truncate",
    "token", "password", "secret", "credential", "api_key",
    "admin", "sudo", "root",
    "ignore", "override", "bypass", "always",
    "exec", "eval", "curl", "wget", "subprocess",
]


def extract_keywords(payload: dict) -> dict:
    text = str(payload)
    lower = text.lower()

    matched_watchlist = sorted({w for w in WATCHLIST if w in lower})

    method = payload.get("method")
    tool_name = None
    args = {}
    params = payload.get("params")
    if isinstance(params, dict):
        tool_name = params.get("name")
        args = params.get("arguments") or {}

    # Free-text argument values (e.g. a comment body) are where real content hides
    content_snippets = [v for v in args.values() if isinstance(v, str) and len(v.split()) > 3]

    words = set()
    for snippet in content_snippets:
        for w in re.findall(r"[A-Za-z']{4,}", snippet.lower()):
            if w not in STOPWORDS:
                words.add(w)

    return {
        "method": method,
        "tool_name": tool_name,
        "arg_keys": list(args.keys()),
        "matched_watchlist": matched_watchlist,
        "extracted_keywords": sorted(words)[:25],
    }