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
