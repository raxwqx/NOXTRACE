# Contributing

Thanks for helping improve NOXTRACE.

## Development checklist

1. Keep features modular and make network behavior explicit.
2. Add standard-library unit tests for valid input, invalid input, and failure cases.
3. Mock network interactions in tests unless a live lab integration test is explicitly separated.
4. Keep active checks bounded, timeout-controlled, and restricted to authorized targets.
5. Do not add DDoS, stealth/evasion, credential attacks, exploit delivery, or automatic exploitation.
6. Document data handling, report fields, limitations, and optional dependencies.
7. Run:

   ```bash
   python3 -m compileall -q src tests
   python3 -m unittest discover -s tests -v
   ```

## Code style

Use type hints, clear names, small functions, and errors that explain how to recover. Do not log passwords, access tokens, or unnecessary personal data. Report findings as hints with evidence rather than making unsupported claims.
