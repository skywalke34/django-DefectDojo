# RapidFire Parser

## Supported Format

The RapidFire parser supports CSV files exported from RapidFire vulnerability scans.

## File Format

The CSV file should contain the following columns:

1. IP Address
2. Hostname
3. MAC Address
4. Severity
5. Issue
6. Ports
7. OID
8. CVE
9. Last Detected (Date format: MM/DD/YYYY)
10. Known Exploited Vulnerability
11. Summary
12. Vulnerability Detection Result
13. Solution
14. Vulnerability Insight
15. Vulnerability Detection Method
16. References
17. Known to Be Used in Ransomware Campaigns

## Field Mappings

- **Title**: Derived from the 'Issue' field
- **Severity**: Mapped from the 'Severity' field (High/Medium/Low/Info)
- **Description**: Combines 'Summary', 'Vulnerability Detection Result', 'Vulnerability Insight', 'Vulnerability Detection Method', 'MAC Address', 'Known Exploited Vulnerability', and 'Known to Be Used in Ransomware Campaigns'
- **Date**: Parsed from the 'Last Detected' field (MM/DD/YYYY format)
- **Unique Identifier**: Uses the 'OID' field
- **CVE**: Taken from the 'CVE' field
- **Mitigation**: Uses the 'Solution' field
- **Impact**: Uses the 'Vulnerability Insight' field
- **References**: Taken from the 'References' field
- **Endpoints**: Created using 'IP Address' (or 'Hostname' if IP is not available) and 'Ports'
  - Multiple endpoints are created if multiple ports are specified
  - Ports can be in various formats (e.g., "80", "8080/tcp", "443 (https)")
- **Is Exploitable**: Set to True if 'Known Exploited Vulnerability' is 'Yes'
- **Tags**: 'ransomware' tag added if 'Known to Be Used in Ransomware Campaigns' is 'Yes'

## Port Handling

The parser can handle various port formats in the 'Ports' field:
- Single port numbers (e.g., "80")
- Ports with protocols (e.g., "8080/tcp")
- Ports with service names (e.g., "443 (https)")
- Multiple ports separated by commas (e.g., "80, 443, 8080")

The parser extracts the numeric port value and creates separate endpoints for each port.

## Example

An example of a RapidFire scan result:

```csv
IP Address,Hostname,MAC Address,Severity,Issue,Ports,OID,CVE,Last Detected,Known Exploited Vulnerability,Summary,Vulnerability Detection Result,Solution,Vulnerability Insight,Vulnerability Detection Method,References,Known to Be Used in Ransomware Campaigns
192.168.1.1,webserver.local,00:11:22:33:44:55,High,SQL Injection Vulnerability,"80, 8080/tcp (http-alt)",OID123,CVE-2023-1234,05/15/2023,Yes,Critical SQL Injection found,Successful SQL Injection,Update database access layer,Allows unauthorized data access,Penetration testing,https://example.com/sql-injection,Yes
```

## Importer Configuration

To import RapidFire scan results:

1. Navigate to the 'Import Scan Results' page
2. Select "RapidFire Scan" as the scan type
3. Upload the CSV file exported from RapidFire
4. Click "Submit" to start the import process

## Error Handling

The parser is designed to handle missing or malformed data gracefully:
- Missing fields will use default values where appropriate
- Invalid date formats will default to the current date
- Unrecognized severity levels will default to 'Info'
- If both IP Address and Hostname are missing, the endpoint will still be created with available information
