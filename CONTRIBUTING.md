# Contributing

Thanks for improving InfraGlance.

## Before You Start

For small fixes, open a pull request directly.

For larger changes, open an issue first so the design can be discussed before implementation.

## Local Checks

Run these before opening a pull request:

```bash
bash -n infraglance.sh
bash -n assume_role
python3 -m py_compile render_report.py
python3 -m unittest discover -s tests
```

If `shellcheck` is installed:

```bash
shellcheck infraglance.sh assume_role
```

## Development Notes

The project has two main files:

- `infraglance.sh` collects AWS data with the AWS CLI.
- `render_report.py` turns collected JSON into static HTML reports.

When adding a new AWS service:

1. Collect raw JSON in `infraglance.sh`.
2. Add a loader in `render_report.py`.
3. Add a table/page or summary card.
4. Add sample fake data under `examples/` if possible.
5. Add a small test when the behavior is easy to test without AWS.

## Do Not Commit

Do not commit:

- `infraglance.conf`
- `data/`
- `site/`
- Any generated report containing real AWS data
- Any AWS keys, session tokens, account secrets, or internal hostnames that should not be public

Use fake data for examples.
