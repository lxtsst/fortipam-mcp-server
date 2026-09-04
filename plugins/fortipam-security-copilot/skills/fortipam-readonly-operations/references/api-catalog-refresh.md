# API Catalog Refresh

Use this workflow when a new FortiPAM documentation version or corrected FNDN
capture becomes available.

1. Keep raw SDK/OpenAPI archives and authenticated browser captures local and
   untracked. Do not export cookies, tokens, HAR files, raw HTML, or unrestricted
   vendor text.
2. Store the sanitized source catalog and manifest in the governed
   KnowledgeBase API directory.
3. Confirm product, version, coverage, unavailable pages, and SHA-256. Do not
   call an incomplete UI capture an official complete OpenAPI contract.
4. Run the project importer with explicit paths and the approved hash:

   ```text
   PYTHONPATH=src .venv/bin/python scripts/build_runtime_catalog.py \
     --input <sanitized-source.json> \
     --output src/fortipam_mcp/data/<runtime-catalog.json> \
     --expected-sha256 <approved-sha256>
   ```

5. Review the generated diff for descriptions, examples, defaults, credentials,
   cookies, sessions, raw schemas, or machine-specific paths. The runtime asset
   should contain only operation and risk metadata.
6. Update source/version documentation, representative catalog tests, package
   data verification, and review-after date.
7. Validate deterministic tests and MCP catalog tools. Live validation remains
   a separate, fixed-path activity and never expands automatically from catalog
   contents.
