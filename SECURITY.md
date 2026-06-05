# Security Policy

InfraGlance is designed to run with read-only AWS permissions and generate static HTML reports. It should not be given write access to AWS resources.

## Supported Versions

Use the latest version from the `main` branch unless a stable release has been published.

## Reporting a Vulnerability

Please do not open a public issue for sensitive security reports.

Report security concerns by emailing the repository owner or by opening a private GitHub security advisory if available.

Include:

- What you found.
- How it can be reproduced.
- Whether sensitive AWS data, credentials, or generated reports could be exposed.
- Suggested fix, if you have one.

## Sensitive Data

Generated reports and raw scan data can include:

- Account labels
- Instance names
- Private and public IP addresses
- VPC CIDR blocks
- Database identifiers
- Security group details

Do not publish `data/`, `site/`, or `infraglance.conf` to a public repository.

Use report redaction before sharing reports outside your team.

## Recommended AWS Permissions

Use the minimum read-only policy in:

```text
iam/infraglance-readonly-policy.json
```

If publishing to S3, keep publishing permissions separate from collection permissions.
