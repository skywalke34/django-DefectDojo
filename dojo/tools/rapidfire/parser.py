import csv
import io
import re
from dateutil import parser as dateutil_parser
from django.utils import timezone
from dojo.models import Finding, Endpoint

class RapidFireParser:
    def get_scan_types(self):
        return ["RapidFire Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "RapidFire Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import RapidFire vulnerability scan results in CSV format."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')

        csv_reader = csv.DictReader(io.StringIO(content))
        dupes = {}

        for row in csv_reader:
            finding = Finding(
                title=row.get('Issue', ''),
                severity=self.convert_severity(row.get('Severity', '')),
                description=self.get_description(row),
                test=test,
                unique_id_from_tool=row.get('OID', ''),
                static_finding=False,
                dynamic_finding=True,
            )

            # Handle date
            try:
                finding.date = dateutil_parser.parse(row.get('Last Detected', '')).date()
            except (ValueError, TypeError):
                finding.date = timezone.now().date()

            # Additional fields
            finding.mitigation = row.get('Solution', '')
            finding.impact = row.get('Vulnerability Insight', '')
            finding.references = row.get('References', '')

            # CVE
            if cve := row.get('CVE'):
                finding.unsaved_vulnerability_ids = [cve]

            # Known Exploited Vulnerability
            if row.get('Known Exploited Vulnerability', '').lower() == 'yes':
                finding.is_exploitable = True

            # Ransomware
            if row.get('Known to Be Used in Ransomware Campaigns', '').lower() == 'yes':
                finding.tags = ["ransomware"]

            # Create endpoint
            ip_address = row.get('IP Address', '')
            hostname = row.get('Hostname', '')
            ports = self.parse_ports(row.get('Ports', ''))
            
            finding.unsaved_endpoints = []
            for port in ports:
                endpoint = Endpoint(host=ip_address if ip_address else hostname)
                if port:
                    endpoint.port = port
                finding.unsaved_endpoints.append(endpoint)

            # Handle duplicate findings
            dupe_key = f"{finding.title}_{finding.unique_id_from_tool}"
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def get_description(self, row):
        description = f"**Summary**: {row.get('Summary', 'N/A')}\n\n"
        description += f"**Vulnerability Detection Result**: {row.get('Vulnerability Detection Result', 'N/A')}\n\n"
        description += f"**Vulnerability Insight**: {row.get('Vulnerability Insight', 'N/A')}\n\n"
        description += f"**Vulnerability Detection Method**: {row.get('Vulnerability Detection Method', 'N/A')}\n\n"
        description += f"**MAC Address**: {row.get('MAC Address', 'N/A')}\n\n"
        description += f"**Known Exploited Vulnerability**: {row.get('Known Exploited Vulnerability', 'N/A')}\n\n"
        description += f"**Known to Be Used in Ransomware Campaigns**: {row.get('Known to Be Used in Ransomware Campaigns', 'N/A')}"
        return description

    def convert_severity(self, severity):
        severity = severity.lower()
        if severity == 'high':
            return 'High'
        elif severity == 'medium':
            return 'Medium'
        elif severity == 'low':
            return 'Low'
        else:
            return 'Info'

    def parse_ports(self, ports_string):
        port_list = ports_string.split(',')
        parsed_ports = []
        for port in port_list:
            match = re.search(r'\d+', port.strip())
            if match:
                parsed_ports.append(match.group())
        return parsed_ports
