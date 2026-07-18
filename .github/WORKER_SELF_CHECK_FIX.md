# Enhanced Worker self-check regression

The strict file-leak hardening intentionally removes generic API routes such as `api/auth/login` from `file_top_2000.txt` while preserving them in the dedicated API endpoint wordlist.

The updater previously required the removed API route to remain in the strict file-leak dictionary, causing every complete installation to fail immediately after a successful image build.

The runtime and offline checks now validate:

- `api/auth/login` in the dedicated API endpoint wordlist;
- `.env` and `swagger.json` in the strict file-leak dictionary;
- named self-check failures for future diagnostics.
