# Vendored wordlists

These files are committed into this repository so production installation and
Worker image builds do not depend on third-party `raw.githubusercontent.com`
availability.

- `api-endpoints.txt`: SecLists API endpoint paths.
- `raft-small-files.txt`: SecLists RAFT small file names.
- `subdomains-main.txt`: fuzzDicts subdomain labels.
- `SOURCES.env`: pinned upstream commits, line counts and SHA256 values.
- `LICENSE.SecLists`: upstream SecLists MIT license.

Update snapshots only through `.github/workflows/vendor-wordlists.yml` and
review the generated source commits/checksums before merging release changes.

The fuzzDicts upstream repository does not currently expose a root LICENSE
file. Its source and exact commit are recorded in `SOURCES.env`; review the
upstream terms before redistributing the snapshot outside this repository.
