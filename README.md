# LootExtract

Turn loose python, let it sniff out forgotten secrets and juicy endpoints, then hand you a tidy JSON dossier. LootExtract is a fast wrapper around `grep` with smart post-processing so you can triage codebases in minutes instead of afternoons.

## Why it's awesome
- Two hunting modes: `secrets` for keys/tokens, `endpoints` for URLs, DB strings, and IPs.
- Grep-style speed with sensible defaults (binary skip, line numbers, directory and file ignores).
- Cleans and deduplicates hits into `clean_output.json`, so you don't drown in noise.
- Extra filters to blacklist boring domains and ignore version-like IP chatter.
- Zero dependencies beyond Python 3 and `grep`.

## Quick start
```bash
python lootextract.py -m secrets --dir .
```
- Raw matches land in `raw_output.txt`.
- Parsed results show up in `clean_output.json` with file path, line number, and the matched value.

Want to hunt endpoints instead?
```bash
python lootextract.py -m endpoints --dir ./src
```

## Workflow picks
- **Review raw only**: `python lootextract.py -m secrets --dir . --raw`
- **Parse later**: `python lootextract.py --clean -i raw_output.txt -o clean.json`
- **Target extensions**: `python lootextract.py -m secrets --include-ext .py .env .yml`
- **Add a blacklist** (skips any value containing those substrings, both modes): `python lootextract.py -m endpoints --blacklist staging.example.com dummy`

## Endpoint sanity
LootExtract tries hard to keep signal high:
- Drops endpoints on the built-in blacklist plus anything you pass with `--blacklist`.
- Verifies IPv4/IPv6 against the allowed CIDR lists (defaults allow everything; tighten them in the script if you like).
- Filters bare IP tokens that look too much like version numbers when `FILTER_VERSION_LIKE` is enabled.
- Keeps only the first copy of each endpoint value so duplicates don't spam the report.

## Make it your own
Open `lootextract.py` and tweak the constants near the top:
- `EXCLUDE_DIRS` / `EXCLUDE_FILES` to avoid useless folders.
- `DEFAULT_INCLUDE_EXTS` for a permanent extension allowlist.
- `ENDPOINTS_BLACKLIST` or the CIDR lists to customize noise suppression.
- Grep behavior (case sensitivity, recursion, colors) if you want different flags.

## Pro tips
- Pipe the JSON into `jq` for quick triage: `jq '.[] | {secret: .secret, file: .file, line: .line}' clean_output.json`
- Pair it with git commits or PRs: point `--dir` at a diff checkout to keep sensitive code from escaping.
- Share the `raw_output.txt` with teammates who prefer classic grep output.

Happy looting!
