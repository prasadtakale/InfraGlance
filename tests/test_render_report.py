import unittest
from datetime import datetime, timezone

import render_report


class RenderReportTests(unittest.TestCase):
    def test_parse_datetime_accepts_z_suffix(self):
        parsed = render_report.parse_datetime("2026-01-02T03:04:05Z")
        self.assertEqual(parsed, datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

    def test_estimated_monthly_uses_instance_price(self):
        pricing = {"default_hourly_usd": 1, "instance_hourly_usd": {"t3.micro": 0.01}}
        self.assertEqual(render_report.estimated_monthly("t3.micro", pricing, 730), 7.3)

    def test_estimated_monthly_falls_back_to_default_price(self):
        pricing = {"default_hourly_usd": 0.02, "instance_hourly_usd": {}}
        self.assertEqual(render_report.estimated_monthly("unknown.type", pricing, 100), 2.0)

    def test_security_group_open_ssh_is_high_severity(self):
        findings = render_report.security_findings(
            ec2_rows=[],
            rds_rows=[],
            vpc_rows=[],
            security_group_rows=[
                {
                    "Account": "Example",
                    "Region": "us-east-1",
                    "VpcId": "vpc-example",
                    "GroupId": "sg-example",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            "Ipv6Ranges": [],
                        }
                    ],
                }
            ],
            stopped_red_days=30,
        )
        self.assertEqual(findings[0]["Severity"], "High")
        self.assertIn("internet", findings[0]["Finding"])


if __name__ == "__main__":
    unittest.main()
