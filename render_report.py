#!/usr/bin/env python3
import argparse
import csv
import html
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


EC2_COLUMNS = [
    "Name",
    "InstanceId",
    "Account",
    "Environment",
    "Region",
    "VpcId",
    "VpcName",
    "State",
    "InstanceType",
    "PrivateIpAddress",
    "PublicIpAddress",
    "AvailabilityZone",
    "LaunchTime",
    "RunningDays",
    "StoppedDays",
    "EstimatedMonthlyCostUSD",
    "RICoverage",
]

RDS_COLUMNS = [
    "DBInstanceIdentifier",
    "Account",
    "Environment",
    "Region",
    "VpcId",
    "VpcName",
    "DBInstanceStatus",
    "DBInstanceClass",
    "Engine",
    "EngineVersion",
    "PubliclyAccessible",
    "StorageEncrypted",
    "MultiAZ",
    "StorageType",
    "AllocatedStorage",
    "AvailabilityZone",
]

FINDING_COLUMNS = [
    "Severity",
    "Finding",
    "Account",
    "Region",
    "VpcId",
    "ResourceType",
    "ResourceId",
    "Details",
]

CHANGE_COLUMNS = [
    "ChangeType",
    "ResourceType",
    "Account",
    "Region",
    "ResourceId",
    "Details",
]

RESERVED_COLUMNS = [
    "Account",
    "Region",
    "InstanceType",
    "InstanceCount",
    "OfferingType",
    "Start",
    "End",
    "State",
]

VPC_COLUMNS = [
    "Name",
    "VpcId",
    "Account",
    "Environment",
    "Region",
    "CidrBlock",
    "State",
    "IsDefault",
    "InstanceTenancy",
]


def str_to_bool(value):
    return str(value).lower() in {"1", "true", "yes", "on"}


def parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age_days(value, now):
    parsed = parse_datetime(value)
    if not parsed:
        return ""
    return max((now - parsed).days, 0)


def stopped_at(state_transition_reason):
    if not state_transition_reason:
        return None
    match = re.search(r"\(([^)]+)\)", state_transition_reason)
    if not match:
        return None
    text = re.sub(r"\s+(?:GMT|UTC)$", "+00:00", match.group(1))
    return parse_datetime(text)


def load_pricing(path):
    if not path:
        return {"default_hourly_usd": 0, "instance_hourly_usd": {}}
    pricing_path = Path(path)
    if not pricing_path.exists():
        return {"default_hourly_usd": 0, "instance_hourly_usd": {}}
    with open(pricing_path) as handle:
        payload = json.load(handle)
    payload.setdefault("default_hourly_usd", 0)
    payload.setdefault("instance_hourly_usd", {})
    return payload


def estimated_monthly(instance_type, pricing, monthly_hours):
    hourly = pricing.get("instance_hourly_usd", {}).get(instance_type, pricing.get("default_hourly_usd", 0))
    try:
        return round(float(hourly) * float(monthly_hours), 2)
    except (TypeError, ValueError):
        return 0


def redact_ip(value):
    return "REDACTED" if value else ""


def redact_cidr(value):
    return "REDACTED" if value else ""


def redact_name(value):
    return "REDACTED" if value else ""


def apply_redaction(ec2_rows, rds_rows, vpc_rows, findings, changes, options):
    if options.redact_instance_names:
        for row in ec2_rows:
            row["Name"] = redact_name(row.get("Name", ""))

    if options.redact_db_names:
        for row in rds_rows:
            row["DBInstanceIdentifier"] = redact_name(row.get("DBInstanceIdentifier", ""))

    if options.redact_private_ips:
        for row in ec2_rows:
            row["PrivateIpAddress"] = redact_ip(row.get("PrivateIpAddress", ""))

    if options.redact_public_ips:
        for row in ec2_rows:
            row["PublicIpAddress"] = redact_ip(row.get("PublicIpAddress", ""))
        for row in findings:
            if "PublicIpAddress=" in row.get("Details", ""):
                row["Details"] = re.sub(r"PublicIpAddress=[^\s,]+", "PublicIpAddress=REDACTED", row["Details"])

    if options.redact_vpc_cidrs:
        for row in vpc_rows:
            row["CidrBlock"] = redact_cidr(row.get("CidrBlock", ""))

    if options.redact_db_names:
        for row in findings:
            if row.get("ResourceType") == "RDS":
                row["ResourceId"] = redact_name(row.get("ResourceId", ""))
        for row in changes:
            if row.get("ResourceType") == "RDS":
                row["ResourceId"] = redact_name(row.get("ResourceId", ""))


def read_manifest(path):
    entries = []
    with open(path, newline="") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if len(row) == 4:
                entries.append({"resource": row[0], "account": row[1], "region": row[2], "path": row[3]})
    return entries


def read_vpc_map(path):
    env_by_vpc = {}
    configured_vpcs = {}
    with open(path, newline="") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if len(row) != 3:
                continue
            account, env_name, vpc_id = row
            env_by_vpc[(account, vpc_id)] = env_name
            configured_vpcs[(account, vpc_id)] = {
                "Account": account,
                "Environment": env_name,
                "VpcId": vpc_id,
                "Name": "",
                "Region": "",
                "CidrBlock": "",
                "State": "",
                "IsDefault": "",
                "InstanceTenancy": "",
            }
    return env_by_vpc, configured_vpcs


def tag_value(tags, key, default=""):
    for tag in tags or []:
        if tag.get("Key") == key:
            return tag.get("Value", default)
    return default


def vpc_name(vpc_details, account, vpc_id):
    return vpc_details.get((account, vpc_id), {}).get("Name", "")


def vpc_environment(vpc_details, env_by_vpc, account, vpc_id):
    return env_by_vpc.get((account, vpc_id), vpc_details.get((account, vpc_id), {}).get("Environment", "Unmapped"))


def load_vpcs(entry, env_by_vpc, environment_tag_key):
    with open(entry["path"]) as handle:
        payload = json.load(handle)

    rows = []
    for vpc in payload.get("Vpcs", []):
        vpc_id = vpc.get("VpcId", "")
        rows.append(
            {
                "Name": tag_value(vpc.get("Tags"), "Name", ""),
                "VpcId": vpc_id,
                "Account": entry["account"],
                "Environment": env_by_vpc.get((entry["account"], vpc_id), tag_value(vpc.get("Tags"), environment_tag_key, "Unmapped")),
                "Region": entry["region"],
                "CidrBlock": vpc.get("CidrBlock", ""),
                "State": vpc.get("State", ""),
                "IsDefault": vpc.get("IsDefault", ""),
                "InstanceTenancy": vpc.get("InstanceTenancy", ""),
            }
        )
    return rows


def load_security_groups(entry):
    with open(entry["path"]) as handle:
        payload = json.load(handle)

    rows = []
    for group in payload.get("SecurityGroups", []):
        rows.append(
            {
                "Account": entry["account"],
                "Region": entry["region"],
                "VpcId": group.get("VpcId", ""),
                "GroupId": group.get("GroupId", ""),
                "GroupName": group.get("GroupName", ""),
                "IpPermissions": group.get("IpPermissions", []),
            }
        )
    return rows


def load_ec2(entry, env_by_vpc, vpc_details, pricing, monthly_hours, now, stopped_amber_days, stopped_red_days):
    with open(entry["path"]) as handle:
        payload = json.load(handle)

    rows = []
    for reservation in payload.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            vpc_id = instance.get("VpcId", "")
            state = instance.get("State", {}).get("Name", "")
            launch_time = instance.get("LaunchTime", "")
            running_days = age_days(launch_time, now) if state == "running" else ""
            stopped_days = ""
            row_class = ""
            if state == "running":
                row_class = "row-running"
            elif state == "stopped":
                stop_time = stopped_at(instance.get("StateTransitionReason", ""))
                if stop_time:
                    stopped_days = max((now - stop_time).days, 0)
                else:
                    stopped_days = "Unknown"
                if isinstance(stopped_days, int) and stopped_days >= stopped_red_days:
                    row_class = "row-stopped-red"
                elif isinstance(stopped_days, int) and stopped_days >= stopped_amber_days:
                    row_class = "row-stopped-amber"
                else:
                    row_class = "row-stopped"
            monthly_cost = estimated_monthly(instance.get("InstanceType", ""), pricing, monthly_hours) if state == "running" else 0
            rows.append(
                {
                    "__RowClass": row_class,
                    "Name": tag_value(instance.get("Tags"), "Name", "name-not-found"),
                    "InstanceId": instance.get("InstanceId", ""),
                    "Account": entry["account"],
                    "Environment": vpc_environment(vpc_details, env_by_vpc, entry["account"], vpc_id),
                    "Region": entry["region"],
                    "VpcId": vpc_id,
                    "VpcName": vpc_name(vpc_details, entry["account"], vpc_id),
                    "State": state,
                    "InstanceType": instance.get("InstanceType", ""),
                    "PrivateIpAddress": instance.get("PrivateIpAddress", ""),
                    "PublicIpAddress": instance.get("PublicIpAddress", ""),
                    "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone", ""),
                    "LaunchTime": launch_time,
                    "RunningDays": running_days,
                    "StoppedDays": stopped_days,
                    "EstimatedMonthlyCostUSD": monthly_cost,
                    "RICoverage": "",
                }
            )
    return rows


def load_rds(entry, env_by_vpc, vpc_details):
    with open(entry["path"]) as handle:
        payload = json.load(handle)

    rows = []
    for instance in payload.get("DBInstances", []):
        vpc_id = instance.get("DBSubnetGroup", {}).get("VpcId", "")
        rows.append(
            {
                "DBInstanceIdentifier": instance.get("DBInstanceIdentifier", ""),
                "Account": entry["account"],
                "Environment": vpc_environment(vpc_details, env_by_vpc, entry["account"], vpc_id),
                "Region": entry["region"],
                "VpcId": vpc_id,
                "VpcName": vpc_name(vpc_details, entry["account"], vpc_id),
                "DBInstanceStatus": instance.get("DBInstanceStatus", ""),
                "DBInstanceClass": instance.get("DBInstanceClass", ""),
                "Engine": instance.get("Engine", ""),
                "EngineVersion": instance.get("EngineVersion", ""),
                "PubliclyAccessible": instance.get("PubliclyAccessible", ""),
                "StorageEncrypted": instance.get("StorageEncrypted", ""),
                "MultiAZ": instance.get("MultiAZ", ""),
                "StorageType": instance.get("StorageType", ""),
                "AllocatedStorage": instance.get("AllocatedStorage", ""),
                "AvailabilityZone": instance.get("AvailabilityZone", ""),
            }
        )
    return rows


def load_reserved(entry):
    with open(entry["path"]) as handle:
        payload = json.load(handle)

    rows = []
    for item in payload.get("ReservedInstances", []):
        rows.append(
            {
                "Account": entry["account"],
                "Region": entry["region"],
                "InstanceType": item.get("InstanceType", ""),
                "InstanceCount": item.get("InstanceCount", ""),
                "OfferingType": item.get("OfferingType", ""),
                "Start": item.get("Start", ""),
                "End": item.get("End", ""),
                "State": item.get("State", ""),
            }
        )
    return rows


def apply_ri_coverage(ec2_rows, reserved_rows):
    coverage = defaultdict(int)
    for row in reserved_rows:
        if row.get("State") != "active":
            continue
        key = (row.get("Account", ""), row.get("Region", ""), row.get("InstanceType", ""))
        try:
            coverage[key] += int(row.get("InstanceCount", 0))
        except (TypeError, ValueError):
            continue

    for row in sorted(ec2_rows, key=lambda item: (item.get("Account", ""), item.get("Region", ""), item.get("InstanceType", ""), item.get("InstanceId", ""))):
        if row.get("State") != "running":
            row["RICoverage"] = "N/A"
            continue
        key = (row.get("Account", ""), row.get("Region", ""), row.get("InstanceType", ""))
        if coverage[key] > 0:
            row["RICoverage"] = "Covered"
            coverage[key] -= 1
        else:
            row["RICoverage"] = "Gap"
            row["__RowClass"] = f'{row.get("__RowClass", "")} row-ri-gap'.strip()


def ec2_summary(ec2_rows):
    running = [row for row in ec2_rows if row.get("State") == "running"]
    covered = [row for row in running if row.get("RICoverage") == "Covered"]
    gaps = [row for row in running if row.get("RICoverage") == "Gap"]
    total_cost = sum(float(row.get("EstimatedMonthlyCostUSD") or 0) for row in running)
    coverage_pct = round((len(covered) / len(running)) * 100, 1) if running else 0
    return {
        "running_count": len(running),
        "stopped_count": len([row for row in ec2_rows if row.get("State") == "stopped"]),
        "monthly_cost": round(total_cost, 2),
        "ri_coverage_pct": coverage_pct,
        "ri_gap_count": len(gaps),
    }


def esc(value):
    return html.escape(str(value if value is not None else ""))


def nav(active):
    links = [
        ("findings.html", "Security Findings"),
        ("changes.html", "Changes"),
        ("index.html", "EC2"),
        ("rds.html", "RDS"),
        ("reserved.html", "Reserved Instances"),
    ]
    return "".join(
        f'<a class="{"active" if label == active else ""}" href="{href}">{label}</a>'
        for href, label in links
    )


def table_html(table_id, columns, rows):
    head = "".join(f"<th>{esc(column)}</th>" for column in columns)
    body = []
    for row in rows:
        cells = "".join(f"<td>{esc(row.get(column, ''))}</td>" for column in columns)
        row_class = row.get("__RowClass", "")
        class_attr = f' class="{esc(row_class)}"' if row_class else ""
        body.append(f"<tr{class_attr}>{cells}</tr>")
    return f"""
    <div class="table-tools">
      <input type="search" data-table="{table_id}" placeholder="Search table">
      <button type="button" data-export="{table_id}">Export CSV</button>
      <span>{len(rows)} rows</span>
    </div>
    <div class="table-wrap">
      <table id="{table_id}">
        <thead><tr>{head}</tr></thead>
        <tbody>{''.join(body)}</tbody>
      </table>
    </div>
    """


def page(title, active, generated_at, content):
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} - {esc(active)}</title>
  <style>
    :root {{ --blue: #0B3C5D; --gold: #F5B041; --white: #FFFFFF; }}
    body {{ margin: 0; font-family: Arial, sans-serif; background: var(--white); color: var(--blue); }}
    header {{ background: var(--blue); color: var(--white); padding: 20px 28px 18px; border-bottom: 4px solid var(--gold); }}
    h1 {{ margin: 0 0 6px; font-size: 24px; font-weight: 700; }}
    h2 {{ margin: 0 0 10px; font-size: 20px; }}
    h3 {{ margin: 18px 0 9px; font-size: 14px; text-transform: uppercase; letter-spacing: 0; }}
    nav {{ display: flex; gap: 4px; margin-top: 16px; flex-wrap: wrap; }}
    nav a {{ color: var(--white); text-decoration: none; padding: 9px 12px; border-radius: 4px; border-bottom: 3px solid transparent; }}
    nav a.active {{ background: var(--gold); color: var(--blue); font-weight: 700; }}
    main {{ padding: 26px 28px 44px; }}
    section {{ margin-bottom: 28px; }}
    .vpc-tabs {{ display: flex; gap: 4px; flex-wrap: wrap; margin: 18px 0 0; border-bottom: 2px solid var(--blue); }}
    .vpc-tab {{ border: 1px solid var(--blue); border-bottom: 0; border-radius: 5px 5px 0 0; background: var(--white); color: var(--blue); padding: 10px 14px; cursor: pointer; font-weight: 600; }}
    .vpc-tab.active {{ background: var(--gold); color: var(--blue); border-color: var(--gold); font-weight: 700; }}
    .vpc-panel {{ display: none; background: var(--white); border: 1px solid rgba(11, 60, 93, 0.55); border-top: 0; border-radius: 0 0 6px 6px; padding: 16px 18px 16px; }}
    .vpc-panel.active {{ display: block; }}
    .vpc-panel .table-wrap {{ border-radius: 4px; }}
    .vpc-title {{ display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; align-items: baseline; margin: 0 0 14px; padding-bottom: 10px; border-bottom: 1px solid rgba(11, 60, 93, 0.28); }}
    .vpc-title h2 {{ margin: 0; }}
    .vpc-meta {{ color: var(--blue); font-size: 13px; font-weight: 600; }}
    .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 10px 0 16px; }}
    .metric {{ background: var(--white); border: 1px solid rgba(11, 60, 93, 0.28); border-left: 5px solid var(--gold); border-radius: 6px; padding: 10px 14px; min-width: 156px; font-size: 16px; }}
    .metric strong {{ display: block; font-size: 20px; margin-top: 3px; }}
    .table-tools {{ display: flex; gap: 10px; align-items: center; margin: 10px 0 10px; flex-wrap: wrap; }}
    input[type="search"] {{ min-width: 284px; padding: 9px 12px; border: 1px solid rgba(11, 60, 93, 0.55); border-radius: 4px; color: var(--blue); font-size: 14px; }}
    button {{ padding: 9px 13px; border: 1px solid var(--blue); border-radius: 4px; background: var(--blue); color: var(--white); cursor: pointer; font-weight: 600; font-size: 14px; }}
    button:hover {{ background: var(--gold); color: var(--blue); }}
    .table-wrap {{ overflow-x: auto; background: var(--white); border: 1px solid rgba(11, 60, 93, 0.7); border-radius: 6px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-right: 1px solid rgba(11, 60, 93, 0.38); border-bottom: 1px solid rgba(11, 60, 93, 0.34); padding: 8px 10px; text-align: left; white-space: nowrap; }}
    th:last-child, td:last-child {{ border-right: 0; }}
    th {{ background: var(--blue); color: var(--white); cursor: pointer; position: sticky; top: 0; }}
    tr:hover td {{ background: rgba(245, 176, 65, 0.08); }}
    tr.row-running td:first-child {{ box-shadow: inset 4px 0 0 var(--blue); }}
    tr.row-stopped td:first-child {{ box-shadow: inset 4px 0 0 rgba(11, 60, 93, 0.30); }}
    tr.row-stopped-amber td:first-child {{ box-shadow: inset 4px 0 0 var(--gold); }}
    tr.row-stopped-red td:first-child {{ box-shadow: inset 6px 0 0 var(--gold); font-weight: 600; }}
    tr.row-ri-gap td:first-child {{ box-shadow: inset 4px 0 0 var(--gold); }}
    .empty {{ background: var(--white); border: 1px solid rgba(11, 60, 93, 0.28); border-left: 5px solid var(--gold); border-radius: 6px; padding: 16px; font-size: 15px; }}
  </style>
</head>
<body>
  <header>
    <h1>{esc(title)}</h1>
    <div>Generated at {esc(generated_at)}</div>
    <nav>{nav(active)}</nav>
  </header>
  <main>{content}</main>
  <script>
    function cellText(row, index) {{
      return row.children[index].textContent.trim();
    }}
    document.querySelectorAll('th').forEach(function(header, index) {{
      header.addEventListener('click', function() {{
        const table = header.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const direction = header.dataset.sort === 'asc' ? -1 : 1;
        rows.sort(function(a, b) {{
          return cellText(a, index).localeCompare(cellText(b, index), undefined, {{ numeric: true }}) * direction;
        }});
        header.dataset.sort = direction === 1 ? 'asc' : 'desc';
        rows.forEach(row => tbody.appendChild(row));
      }});
    }});
    document.querySelectorAll('input[type="search"][data-table]').forEach(function(input) {{
      input.addEventListener('input', function() {{
        const table = document.getElementById(input.dataset.table);
        const query = input.value.toLowerCase();
        table.querySelectorAll('tbody tr').forEach(function(row) {{
          row.hidden = !row.textContent.toLowerCase().includes(query);
        }});
      }});
    }});
    document.querySelectorAll('button[data-export]').forEach(function(button) {{
      button.addEventListener('click', function() {{
        const table = document.getElementById(button.dataset.export);
        const rows = Array.from(table.querySelectorAll('tr')).filter(row => !row.hidden);
        const csv = rows.map(row => Array.from(row.children).map(cell => '"' + cell.textContent.split('"').join('""') + '"').join(',')).join('\\n');
        const blob = new Blob([csv], {{ type: 'text/csv' }});
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = button.dataset.export + '.csv';
        link.click();
        URL.revokeObjectURL(link.href);
      }});
    }});
    document.querySelectorAll('.vpc-tabs').forEach(function(tabs) {{
      tabs.addEventListener('click', function(event) {{
        const tab = event.target.closest('.vpc-tab');
        if (!tab) {{
          return;
        }}
        const group = tab.dataset.tabGroup;
        document.querySelectorAll('.vpc-tab[data-tab-group="' + group + '"]').forEach(function(item) {{
          item.classList.toggle('active', item === tab);
          item.setAttribute('aria-selected', item === tab ? 'true' : 'false');
        }});
        document.querySelectorAll('.vpc-panel[data-tab-group="' + group + '"]').forEach(function(panel) {{
          panel.classList.toggle('active', panel.id === tab.dataset.tabTarget);
        }});
      }});
    }});
  </script>
</body>
</html>
"""


def group_title(row):
    account = row.get("Account", "Unknown")
    env_name = row.get("Environment", "Unmapped")
    vpc_id = row.get("VpcId", "")
    name = row.get("VpcName", "")
    if vpc_id:
        suffix = f"{name} ({vpc_id})" if name else vpc_id
        return f"{account} / {env_name} / {suffix}"
    return f"{account} / {env_name}"


def slug(value):
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_").lower()
    return value or "table"


def vpc_label(vpc):
    name = vpc.get("Name", "")
    vpc_id = vpc.get("VpcId", "")
    return f"{name} ({vpc_id})" if name and vpc_id else name or vpc_id or "No VPC"


def vpc_tab_label(vpc):
    return vpc.get("Name", "") or vpc.get("VpcId", "") or "No VPC"


def vpc_sort_key(vpc):
    return (
        vpc.get("Account", ""),
        vpc.get("Environment", ""),
        vpc.get("Name", ""),
        vpc.get("VpcId", ""),
    )


def vpc_resource_sections(resource, columns, resource_rows, vpc_rows):
    resources_by_vpc = defaultdict(list)
    for row in resource_rows:
        resources_by_vpc[(row.get("Account", ""), row.get("VpcId", ""))].append(row)

    vpcs_by_key = {(row.get("Account", ""), row.get("VpcId", "")): row for row in vpc_rows}
    for key, rows in resources_by_vpc.items():
        if key not in vpcs_by_key:
            account, vpc_id = key
            first = rows[0]
            vpcs_by_key[key] = {
                "Account": account,
                "Environment": first.get("Environment", "Unmapped"),
                "VpcId": vpc_id,
                "Name": first.get("VpcName", ""),
                "Region": first.get("Region", ""),
                "CidrBlock": "",
                "State": "",
                "IsDefault": "",
                "InstanceTenancy": "",
            }

    if resource == "EC2":
        summary = ec2_summary(resource_rows)
        sections = [
            '<div class="summary">'
            f'<div class="metric"><span>Total EC2</span><strong>{len(resource_rows)}</strong></div>'
            f'<div class="metric"><span>Running</span><strong>{summary["running_count"]}</strong></div>'
            f'<div class="metric"><span>Stopped</span><strong>{summary["stopped_count"]}</strong></div>'
            f'<div class="metric"><span>Monthly Est.</span><strong>${summary["monthly_cost"]}</strong></div>'
            f'<div class="metric"><span>RI Coverage</span><strong>{summary["ri_coverage_pct"]}%</strong></div>'
            f'<div class="metric"><span>RI Gaps</span><strong>{summary["ri_gap_count"]}</strong></div>'
            f'<div class="metric"><span>VPCs</span><strong>{len(vpcs_by_key)}</strong></div>'
            '</div>'
        ]
    else:
        sections = [
            f'<div class="summary"><div class="metric"><span>Total {esc(resource)}</span><strong>{len(resource_rows)}</strong></div>'
            f'<div class="metric"><span>VPCs</span><strong>{len(vpcs_by_key)}</strong></div></div>'
        ]

    sorted_vpcs = sorted(vpcs_by_key.values(), key=vpc_sort_key)
    tab_group = f"{resource.lower()}_vpcs"
    tabs = []
    panels = []

    for index, vpc in enumerate(sorted_vpcs):
        key = (vpc.get("Account", ""), vpc.get("VpcId", ""))
        rows = resources_by_vpc.get(key, [])
        table_id = f"{resource.lower()}_{index}_{slug(vpc.get('VpcId', 'none'))}"
        vpc_table_id = f"vpc_{resource.lower()}_{index}_{slug(vpc.get('VpcId', 'none'))}"
        panel_id = f"{tab_group}_{index}_{slug(vpc.get('VpcId', 'none'))}"
        active_class = " active" if index == 0 else ""
        selected = "true" if index == 0 else "false"
        resource_table = table_html(table_id, columns, rows) if rows else f'<div class="empty">No {esc(resource)} found in this VPC.</div>'
        vpc_summary_html = ""
        if resource == "EC2":
            vpc_summary = ec2_summary(rows)
            vpc_summary_html = (
                '<div class="summary">'
                f'<div class="metric"><span>VPC Monthly Est.</span><strong>${vpc_summary["monthly_cost"]}</strong></div>'
                f'<div class="metric"><span>Running</span><strong>{vpc_summary["running_count"]}</strong></div>'
                f'<div class="metric"><span>Stopped</span><strong>{vpc_summary["stopped_count"]}</strong></div>'
                f'<div class="metric"><span>RI Coverage</span><strong>{vpc_summary["ri_coverage_pct"]}%</strong></div>'
                f'<div class="metric"><span>RI Gaps</span><strong>{vpc_summary["ri_gap_count"]}</strong></div>'
                '</div>'
            )
        tabs.append(
            f'<button type="button" class="vpc-tab{active_class}" data-tab-group="{tab_group}" '
            f'data-tab-target="{panel_id}" aria-selected="{selected}">{esc(vpc_tab_label(vpc))}</button>'
        )
        panels.append(
            f'<section id="{panel_id}" class="vpc-panel{active_class}" data-tab-group="{tab_group}">'
            f'<div class="vpc-title"><h2>{esc(vpc_label(vpc))}</h2>'
            f'<div class="vpc-meta">{esc(vpc.get("Account", ""))} / {esc(vpc.get("Environment", ""))} / {esc(vpc.get("Region", ""))}</div></div>'
            f'{vpc_summary_html}'
            f'<h3>VPC</h3>{table_html(vpc_table_id, VPC_COLUMNS, [vpc])}'
            f'<h3>{esc(resource)}</h3>{resource_table}'
            f'</section>'
        )

    if tabs:
        sections.append(f'<div class="vpc-tabs" role="tablist">{"".join(tabs)}</div>{"".join(panels)}')
    if not resource_rows and not vpcs_by_key:
        sections.append('<div class="empty">No resources found.</div>')
    return "".join(sections)


def grouped_sections(resource, columns, rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[group_title(row)].append(row)

    names = sorted(grouped)

    sections = []
    total = len(rows)
    sections.append(f'<div class="summary"><div class="metric"><span>Total {esc(resource)}</span><strong>{total}</strong></div></div>')
    for index, name in enumerate(names):
        env_rows = grouped.get(name, [])
        if not env_rows:
            continue
        sections.append(f"<section><h2>{esc(name)}</h2>{table_html(resource.lower() + '_' + str(index), columns, env_rows)}</section>")
    if total == 0:
        sections.append('<div class="empty">No resources found.</div>')
    return "".join(sections)


def add_finding(findings, severity, finding, account, region, vpc_id, resource_type, resource_id, details):
    findings.append(
        {
            "Severity": severity,
            "Finding": finding,
            "Account": account,
            "Region": region,
            "VpcId": vpc_id,
            "ResourceType": resource_type,
            "ResourceId": resource_id,
            "Details": details,
        }
    )


def port_range(permission):
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None or to_port is None:
        return "all"
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def security_findings(ec2_rows, rds_rows, vpc_rows, security_group_rows, stopped_red_days):
    findings = []

    for row in ec2_rows:
        if row.get("PublicIpAddress"):
            add_finding(
                findings,
                "Medium",
                "EC2 instance has a public IP address",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "EC2",
                row.get("InstanceId", ""),
                f"PublicIpAddress={row.get('PublicIpAddress')}",
            )
        if row.get("State") == "running" and row.get("RICoverage") == "Gap":
            add_finding(
                findings,
                "Medium",
                "Running EC2 instance has no RI coverage",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "EC2",
                row.get("InstanceId", ""),
                f'InstanceType={row.get("InstanceType", "")}, MonthlyEstimate=${row.get("EstimatedMonthlyCostUSD", 0)}',
            )
        if row.get("State") == "stopped" and isinstance(row.get("StoppedDays"), int) and row.get("StoppedDays") >= stopped_red_days:
            add_finding(
                findings,
                "Medium",
                "EC2 instance has been stopped beyond threshold",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "EC2",
                row.get("InstanceId", ""),
                f'StoppedDays={row.get("StoppedDays")}',
            )

    for row in rds_rows:
        if row.get("PubliclyAccessible") is True:
            add_finding(
                findings,
                "High",
                "RDS instance is publicly accessible",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "RDS",
                row.get("DBInstanceIdentifier", ""),
                "PubliclyAccessible=True",
            )
        if row.get("StorageEncrypted") is False:
            add_finding(
                findings,
                "High",
                "RDS storage is not encrypted",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "RDS",
                row.get("DBInstanceIdentifier", ""),
                "StorageEncrypted=False",
            )

    for row in vpc_rows:
        if row.get("IsDefault") is True:
            add_finding(
                findings,
                "Low",
                "Default VPC exists",
                row.get("Account", ""),
                row.get("Region", ""),
                row.get("VpcId", ""),
                "VPC",
                row.get("VpcId", ""),
                "IsDefault=True",
            )

    for group in security_group_rows:
        for permission in group.get("IpPermissions", []):
            open_ipv4 = any(item.get("CidrIp") == "0.0.0.0/0" for item in permission.get("IpRanges", []))
            open_ipv6 = any(item.get("CidrIpv6") == "::/0" for item in permission.get("Ipv6Ranges", []))
            if not open_ipv4 and not open_ipv6:
                continue
            ports = port_range(permission)
            severity = "High" if ports in {"22", "3389", "all"} else "Medium"
            add_finding(
                findings,
                severity,
                "Security group allows ingress from the internet",
                group.get("Account", ""),
                group.get("Region", ""),
                group.get("VpcId", ""),
                "SecurityGroup",
                group.get("GroupId", ""),
                f"GroupName={group.get('GroupName', '')}, Protocol={permission.get('IpProtocol', '')}, Ports={ports}",
            )

    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(findings, key=lambda item: (severity_order.get(item["Severity"], 9), item["Account"], item["Region"], item["Finding"]))


def findings_content(findings):
    counts = defaultdict(int)
    for finding in findings:
        counts[finding["Severity"]] += 1
    content = (
        '<div class="summary">'
        f'<div class="metric"><span>Total Findings</span><strong>{len(findings)}</strong></div>'
        f'<div class="metric"><span>High</span><strong>{counts["High"]}</strong></div>'
        f'<div class="metric"><span>Medium</span><strong>{counts["Medium"]}</strong></div>'
        f'<div class="metric"><span>Low</span><strong>{counts["Low"]}</strong></div>'
        '</div>'
    )
    return content + table_html("security_findings", FINDING_COLUMNS, findings)


def resource_state(ec2_rows, rds_rows, vpc_rows, findings):
    resources = {}
    for row in ec2_rows:
        key = f'EC2|{row.get("Account", "")}|{row.get("Region", "")}|{row.get("InstanceId", "")}'
        resources[key] = {
            "ResourceType": "EC2",
            "Account": row.get("Account", ""),
            "Region": row.get("Region", ""),
            "ResourceId": row.get("InstanceId", ""),
            "Details": json.dumps({
                "MonthlyCost": row.get("EstimatedMonthlyCostUSD", ""),
                "PublicIp": bool(row.get("PublicIpAddress", "")),
                "RICoverage": row.get("RICoverage", ""),
                "State": row.get("State", ""),
                "VpcId": row.get("VpcId", ""),
            }, sort_keys=True),
        }
    for row in rds_rows:
        key = f'RDS|{row.get("Account", "")}|{row.get("Region", "")}|{row.get("DBInstanceIdentifier", "")}'
        resources[key] = {
            "ResourceType": "RDS",
            "Account": row.get("Account", ""),
            "Region": row.get("Region", ""),
            "ResourceId": row.get("DBInstanceIdentifier", ""),
            "Details": json.dumps({
                "Encrypted": row.get("StorageEncrypted", ""),
                "Public": row.get("PubliclyAccessible", ""),
                "Status": row.get("DBInstanceStatus", ""),
                "VpcId": row.get("VpcId", ""),
            }, sort_keys=True),
        }
    for row in vpc_rows:
        key = f'VPC|{row.get("Account", "")}|{row.get("Region", "")}|{row.get("VpcId", "")}'
        resources[key] = {
            "ResourceType": "VPC",
            "Account": row.get("Account", ""),
            "Region": row.get("Region", ""),
            "ResourceId": row.get("VpcId", ""),
            "Details": json.dumps({
                "Default": row.get("IsDefault", ""),
                "Environment": row.get("Environment", ""),
            }, sort_keys=True),
        }
    for row in findings:
        key = f'Finding|{row.get("Account", "")}|{row.get("Region", "")}|{row.get("ResourceType", "")}|{row.get("ResourceId", "")}|{row.get("Finding", "")}'
        resources[key] = {
            "ResourceType": "Finding",
            "Account": row.get("Account", ""),
            "Region": row.get("Region", ""),
            "ResourceId": row.get("ResourceId", ""),
            "Details": json.dumps({
                "Finding": row.get("Finding", ""),
                "Severity": row.get("Severity", ""),
            }, sort_keys=True),
        }
    return resources


def load_previous_state(path):
    state_path = Path(path)
    if not state_path.exists():
        return {}
    with open(state_path) as handle:
        return json.load(handle).get("resources", {})


def change_rows(previous, current):
    rows = []
    for key in sorted(set(current) - set(previous)):
        row = dict(current[key])
        row["ChangeType"] = "New"
        rows.append(row)
    for key in sorted(set(previous) - set(current)):
        row = dict(previous[key])
        row["ChangeType"] = "Removed"
        rows.append(row)
    for key in sorted(set(current) & set(previous)):
        if current[key].get("Details") != previous[key].get("Details"):
            row = dict(current[key])
            row["ChangeType"] = "Changed"
            row["Details"] = f'{previous[key].get("Details", "")} -> {current[key].get("Details", "")}'
            rows.append(row)
    return rows


def write_state(path, generated_at, current):
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump({"generated_at": generated_at, "resources": current}, handle, indent=2, sort_keys=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--vpcs", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--environment-tag-key", default="Environment")
    parser.add_argument("--auto-discover-vpcs", default="true")
    parser.add_argument("--pricing-file", default="")
    parser.add_argument("--monthly-hours", type=float, default=730)
    parser.add_argument("--stopped-amber-days", type=int, default=7)
    parser.add_argument("--stopped-red-days", type=int, default=30)
    parser.add_argument("--state-file", default="")
    parser.add_argument("--redact-private-ips", default="false")
    parser.add_argument("--redact-public-ips", default="false")
    parser.add_argument("--redact-instance-names", default="false")
    parser.add_argument("--redact-db-names", default="false")
    parser.add_argument("--redact-vpc-cidrs", default="false")
    args = parser.parse_args()
    args.redact_private_ips = str_to_bool(args.redact_private_ips)
    args.redact_public_ips = str_to_bool(args.redact_public_ips)
    args.redact_instance_names = str_to_bool(args.redact_instance_names)
    args.redact_db_names = str_to_bool(args.redact_db_names)
    args.redact_vpc_cidrs = str_to_bool(args.redact_vpc_cidrs)
    args.auto_discover_vpcs = str_to_bool(args.auto_discover_vpcs)
    pricing = load_pricing(args.pricing_file)
    now = datetime.now(timezone.utc)

    env_by_vpc, configured_vpcs = read_vpc_map(args.vpcs)
    ec2_rows, rds_rows, reserved_rows, vpc_rows, security_group_rows = [], [], [], [], []

    for entry in read_manifest(args.manifest):
        if entry["resource"] == "vpc":
            vpc_rows.extend(load_vpcs(entry, env_by_vpc, args.environment_tag_key))
        elif entry["resource"] == "security_group":
            security_group_rows.extend(load_security_groups(entry))

    if not args.auto_discover_vpcs:
        configured_keys = set(configured_vpcs)
        vpc_rows = [row for row in vpc_rows if (row["Account"], row["VpcId"]) in configured_keys]

    vpc_details = {(row["Account"], row["VpcId"]): row for row in vpc_rows}
    for key, row in configured_vpcs.items():
        if key not in vpc_details:
            vpc_rows.append(row)
            vpc_details[key] = row

    for entry in read_manifest(args.manifest):
        if entry["resource"] == "ec2":
            ec2_rows.extend(load_ec2(entry, env_by_vpc, vpc_details, pricing, args.monthly_hours, now, args.stopped_amber_days, args.stopped_red_days))
        elif entry["resource"] == "rds":
            rds_rows.extend(load_rds(entry, env_by_vpc, vpc_details))
        elif entry["resource"] == "reserved":
            reserved_rows.extend(load_reserved(entry))

    apply_ri_coverage(ec2_rows, reserved_rows)
    findings = security_findings(ec2_rows, rds_rows, vpc_rows, security_group_rows, args.stopped_red_days)
    current_state = resource_state(ec2_rows, rds_rows, vpc_rows, findings)
    previous_state = load_previous_state(args.state_file) if args.state_file else {}
    changes = change_rows(previous_state, current_state)

    apply_redaction(ec2_rows, rds_rows, vpc_rows, findings, changes, args)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    old_vpc_page = output_dir / "vpcs.html"
    if old_vpc_page.exists():
        old_vpc_page.unlink()

    (output_dir / "findings.html").write_text(
        page(args.title, "Security Findings", args.generated_at, findings_content(findings)),
        encoding="utf-8",
    )
    (output_dir / "changes.html").write_text(
        page(args.title, "Changes", args.generated_at, table_html("changes", CHANGE_COLUMNS, changes)),
        encoding="utf-8",
    )
    (output_dir / "index.html").write_text(
        page(args.title, "EC2", args.generated_at, vpc_resource_sections("EC2", EC2_COLUMNS, ec2_rows, vpc_rows)),
        encoding="utf-8",
    )
    (output_dir / "rds.html").write_text(
        page(args.title, "RDS", args.generated_at, vpc_resource_sections("RDS", RDS_COLUMNS, rds_rows, vpc_rows)),
        encoding="utf-8",
    )
    (output_dir / "reserved.html").write_text(
        page(args.title, "Reserved Instances", args.generated_at, table_html("reserved", RESERVED_COLUMNS, reserved_rows)),
        encoding="utf-8",
    )
    if args.state_file:
        write_state(args.state_file, args.generated_at, current_state)


if __name__ == "__main__":
    main()
