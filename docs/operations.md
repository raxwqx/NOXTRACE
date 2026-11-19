# Operations quick guide

## Fast start

```bash
./noxtrace
```

Or install into a local environment:

```bash
./install.sh
source .venv/bin/activate
noxtrace --help
```

## Safe test setup

Use a loopback service for initial connectivity checks. For example, start a local HTTP server in a separate terminal:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
```

Then, in the NOXTRACE project terminal:

```bash
./noxtrace scan 127.0.0.1 --ports 8000 --authorized
./noxtrace web-audit http://127.0.0.1:8000 --authorized
```

The `--authorized` option is an explicit scope acknowledgement, not a way to make unauthorized use acceptable.

## Exit codes and automation

Every report-producing command accepts `--fail-on-findings`. This is useful in shell pipelines and CI jobs that should stop when a review-worthy result appears.

| Code | Meaning |
| --- | --- |
| `0` | The command completed and the report contains no findings. |
| `2` | The command could not complete, or a report file could not be written. Check the error message and the report status. |
| `3` | The command completed and the report contains at least one finding. Findings are review hints, not proof of a vulnerability. |

Example:

```bash
noxtrace code-audit ./src --json --fail-on-findings
```

`--fail-on-findings` works together with `--json`, `--output`, and `--html`. When both an error and findings are possible, the error code `2` takes precedence.

```bash
# Stop a pipeline when the source review reports findings
if ! noxtrace code-audit ./src --json --fail-on-findings > review.json; then
  echo "Review findings were reported; inspect review.json."
fi
```

## Report files

`--output` and `--html` write to a temporary file and then move it into place, so an interrupted write does not truncate an existing report. Invalid paths, unresolvable `~user` expansions, and unwritable directories return a clear message and exit code `2`.

## Input limits

NOXTRACE rejects whitespace and terminal control characters in DNS names, domains, URLs, scan targets, TLS hosts, and OSV coordinates. It also caps Maven XML input at 5 MB, log triage at an explicit positive line limit, source review at `--max-files`, and TCP scans at 256 unique ports. These are safety limits, not a substitute for authorization.
