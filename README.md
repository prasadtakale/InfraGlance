# InfraGlance

> A single command that turns your AWS accounts into a shareable, browser-ready visibility dashboard — no servers, no SaaS subscriptions, nothing to install beyond the AWS CLI and Python.

---

## The Problem

If your organization runs more than a handful of AWS accounts, you already know the frustration: your cloud environment has grown faster than your ability to see it clearly. There is no single place to answer "what is actually running, where, and what is it costing us?" without clicking through dozens of AWS Console screens — and the Console was not designed to give you a cross-account picture.

Think of it like this: imagine you own several office buildings, but the occupancy records, maintenance logs, and utility bills are kept in a separate filing cabinet in each building, organized differently by whoever managed it at the time. Getting a complete picture means physically visiting each one. That is what managing a sprawling AWS environment feels like without the right tooling.

The concrete pains this addresses:

- **Silent waste**: Stopped virtual servers accumulate quietly and keep contributing to your bill. Nobody notices until the monthly invoice arrives.
- **Audit anxiety**: When a compliance auditor asks "show me all your publicly accessible databases," the answer should not require a week of prep work across multiple accounts.
- **The share problem**: The AWS Console is not shareable. You cannot email a snapshot of your infrastructure to a VP, a finance lead, or an external auditor.
- **Multi-account blind spots**: Most teams maintain separate Development, Staging, and Production accounts. Getting a unified view requires juggling separate browser sessions and CLI profiles.
- **Reserved Instance gaps**: Reserved Instances — pre-paid compute commitments that discount hourly rates — expire or go uncovered without obvious notification, leaving money on the table.

---

## The Solution

InfraGlance is a shell script that collects data from your AWS accounts using the AWS CLI, then renders everything into a self-contained static HTML dashboard. Open it in a browser, attach it to an email, or sync it to S3. No web server, no login, no ongoing subscription.

One run. A complete picture.

**Technically:** `infraglance.sh` uses the AWS CLI and IAM (AWS Identity and Access Management — the permission system) role assumption to collect JSON from each account and region you configure. `render_report.py` transforms that data into a multi-page HTML report using only Python's standard library — no `pip install`, no Node.js, no external packages of any kind. The output has zero CDN references and works completely offline.

---

## What You Can See

| Page | What's Shown |
|------|-------------|
| **EC2** | All virtual servers — state (running/stopped), instance type, VPC (Virtual Private Cloud — a private network segment in AWS), IP addresses, days running or stopped, estimated monthly cost, Reserved Instance coverage |
| **RDS** | All managed databases — engine, version, status, encryption state, Multi-AZ failover configuration, public accessibility, VPC placement |
| **Reserved Instances** | Active pre-paid compute commitments — instance type, count, offering type, start/end dates, and which running instances have no coverage |
| **Security Findings** | Auto-detected issues: publicly accessible databases, unencrypted RDS storage, EC2 instances with public IP addresses, security groups open to the internet, default VPCs in use, long-stopped instances |
| **Changes** | Infrastructure diff between the current run and the previous one — new, removed, or modified resources |

All pages include sortable columns, per-table search, and one-click CSV export.

---

## Key Features

✅ **Zero output dependencies** — The generated HTML uses no external libraries or CDN requests. It works offline, in air-gapped environments, and is safe to attach to an email without leaking internal data to third-party hosts.

✅ **AWS GovCloud support** — Set `PARTITION=aws-us-gov` and InfraGlance automatically restricts collection to `us-gov-west-1` and `us-gov-east-1`, with GovCloud-format ARN validation. Most open-source infrastructure tools do not support GovCloud at all.

✅ **Multi-account, multi-region** — Configure as many AWS accounts as you need, each with its own IAM role, named CLI profile, or default credential chain. Regions are either explicit or auto-discovered from your account's enabled list.

✅ **VPC-tabbed navigation** — Each resource page groups instances by VPC with tab-based navigation, so a team responsible for one network segment does not have to scroll past another team's resources to find their own.

✅ **Automatic security findings** — No external security scanner required. InfraGlance flags publicly accessible databases (High), internet-open security groups for SSH/RDP/all-ports (High), unencrypted RDS storage (High), EC2 instances with public IPs (Medium), and default VPCs in use (Low) — out of the box.

✅ **Reserved Instance coverage tracking** — See at a glance which running EC2 instances are not covered by an active pre-paid commitment, so you can act before the discount window closes.

✅ **Run-to-run change detection** — InfraGlance saves a state file after each run and diffs it against the previous one. The Changes page shows what appeared, disappeared, or was modified since last time — lightweight drift tracking with no additional tools.

✅ **Estimated monthly cost** — Calculated from a local `pricing.json` table. No billing API calls, no extra IAM permissions for cost data, no surprises.

✅ **Redaction controls** — Before sharing a report externally, selectively redact private IPs, public IPs, instance names, database identifiers, and VPC CIDR blocks (network address ranges). Share with auditors without exposing network topology.

✅ **Optional S3 publishing** — Set `S3_BUCKET` in the config and the report syncs to S3 automatically after each run. Pair with a bucket policy for a read-only stakeholder URL.

---

## Who This Is For

| Role | Why it helps |
|------|-------------|
| **DevOps / Platform engineers** | One command for a full environment inventory without Console clicking |
| **FinOps / Cost teams** | Spot stopped instances, RI gaps, and cost estimates across accounts in one place |
| **Compliance / Audit teams** | Point-in-time shareable snapshot with built-in security findings; redaction support for external reviewers |
| **Engineering managers** | An understandable, exportable dashboard that does not require AWS Console access to read |
| **Cloud architects** | Cross-account, cross-region view organized by VPC and environment |

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/youruser/infraglance.git && cd infraglance
```

```bash
# 2. Copy and edit the config
cp infraglance.conf.example infraglance.conf
# Set your AWS account IDs, profiles or role ARNs, and target regions
```

```bash
# 3. Validate credentials and config before collecting data
bash infraglance.sh --check
```

```bash
# 4. Run InfraGlance
bash infraglance.sh
```

```bash
# 5. Open the report
open site/index.html          # macOS
xdg-open site/index.html      # Linux
```

---

## Prerequisites

⚠️ **Runtime requirements**

| Requirement | Notes |
|-------------|-------|
| Bash 4+ | macOS ships with Bash 3 — install a current version via `brew install bash` |
| Python 3.8+ | Standard library only — no `pip install` required |
| AWS CLI v2 | Configured with credentials for each target account |

⚠️ **Minimum IAM permissions**

Attach the following read-only policy to each IAM role or user InfraGlance authenticates as. These are the only permissions needed.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeReservedInstances",
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

If using cross-account IAM role assumption, also grant `sts:AssumeRole` on the calling account's IAM entity.

---

## Configuration

All configuration lives in `infraglance.conf`. The example file is fully commented:

```bash
cp infraglance.conf.example infraglance.conf
```

**Key settings:**

```bash
# AWS partition: auto | aws | aws-us-gov
PARTITION="auto"

# Where to write the HTML report and collected JSON
OUTPUT_DIR="./site"
WORK_DIR="./data"

# One or more accounts to scan
ACCOUNTS=("prod" "staging" "shared")

# Per-account: label, authentication, and regions
ACCOUNT_prod_LABEL="Production"
ACCOUNT_prod_PROFILE="prod-profile"   # AWS CLI named profile
ACCOUNT_prod_ROLE_ARN=""              # or an IAM role ARN for cross-account access
ACCOUNT_prod_REGIONS=("us-east-1" "us-west-2")

# Tag key used to assign VPCs to environments (tag-based auto-discovery)
ENVIRONMENT_TAG_KEY="Environment"
AUTO_DISCOVER_VPCS="true"

# Optional: sync the report to S3 after each run
S3_BUCKET="my-infraglance-reports"
S3_PREFIX="infraglance"

# Optional: redact sensitive fields before sharing reports externally
REDACT_PRIVATE_IPS="false"
REDACT_PUBLIC_IPS="false"
REDACT_INSTANCE_NAMES="false"
REDACT_DB_NAMES="false"
REDACT_VPC_CIDRS="false"
```

See [infraglance.conf.example](infraglance.conf.example) for the full reference, including manual VPC-to-environment mappings and cost estimation settings.

---

## Sample Output

The report is a multi-page static HTML dashboard with a consistent layout across all pages:

- **Header**: report title, generation timestamp, and page navigation
- **EC2** (`index.html`): VPC tabs across the top; each tab shows a cost and RI coverage summary bar followed by a sortable instance table. Rows are color-coded — running instances, recently stopped (amber), stopped beyond the configured threshold (bold), and instances missing RI coverage (highlighted)
- **Security Findings** (`findings.html`): High / Medium / Low counts in a summary bar, then a sortable findings table with account, region, resource type, and specific details
- **Changes** (`changes.html`): Rows marked New, Removed, or Changed since the previous run
- All tables include a live search filter, click-to-sort column headers, and an Export CSV button

The output is a folder of plain `.html` files with no JavaScript framework and no external requests.

---

## AWS GovCloud Support

InfraGlance works with **AWS GovCloud (US)** without a separate code path or configuration format. Set `PARTITION="aws-us-gov"` in your config and:

- Region auto-discovery restricts automatically to `us-gov-west-1` and `us-gov-east-1`
- IAM role ARNs follow the GovCloud format: `arn:aws-us-gov:iam::123456789012:role/infraglance-readonly`
- The partition is validated against the identity returned by `sts:GetCallerIdentity` at startup — misconfiguration fails loudly before any data collection begins

Because the generated HTML contains no CDN references, no telemetry, and makes no outbound network requests after the AWS data collection phase, InfraGlance is suitable for use in FedRAMP-aligned environments (FedRAMP is the US federal cloud security compliance framework) where external API calls and third-party tooling are restricted or prohibited. The report can be reviewed entirely offline and is safe to transfer to an air-gapped review environment.

---

## Roadmap

- [ ] **Live cost estimation** — Replace the static `pricing.json` with on-demand AWS Pricing API data, and add per-environment cost breakdowns
- [ ] **Untagged resource alerts** — Flag EC2 and RDS resources missing required tags (cost center, owner, environment) as a Security Findings subcategory
- [ ] **EKS inventory** — Add cluster, node group, and workload visibility alongside EC2 and RDS
- [ ] **Slack / email digest** — Post a summary or alert on new High findings after each run without requiring a persistent process
- [ ] **Historical trending** — Track resource counts and estimated cost over time across runs with a lightweight time-series view

---

## Contributing

Contributions are welcome. InfraGlance is intentionally kept simple — a shell script, a Python file, and a config example. If you are adding a new data source, follow the existing pattern: collect raw JSON in `infraglance.sh`, then parse and render in `render_report.py`. Open an issue to discuss larger changes before writing code, so effort is not duplicated.

---

## License

MIT
