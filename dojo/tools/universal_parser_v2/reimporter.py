"""
Universal Parser V2 ReImporter.

This reimporter handles pre-normalized findings from the Universal Parser V2
microservice. Unlike traditional reimporters that parse raw scan files, this
reimporter receives structured finding data that has already been parsed and
validated by the microservice.

The microservice handles:
- YAML-based parser configuration
- File parsing (JSON, XML, CSV, etc.)
- Field extraction and mapping
- Data type transformation
- Initial validation

This reimporter handles:
- Converting normalized dicts to Finding objects
- Deduplication using DefectDojo's existing logic
- Closing old findings
- Reactivating findings
- Import statistics
"""

import logging
from datetime import date as date_type, datetime
from typing import Any

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Finding, Test, Test_Import

logger = logging.getLogger(__name__)


class UniversalParserV2ReImporter(DefaultReImporter):
    """
    ReImporter for Universal Parser V2.

    This class extends DefaultReImporter to handle pre-normalized findings
    from the microservice. It bypasses the file parsing step and directly
    processes structured finding data.

    Example:
        reimporter = UniversalParserV2ReImporter()
        test_import = reimporter.reimport_findings(
            test=test,
            findings_data=[
                {
                    'title': 'XSS Vulnerability',
                    'severity': 'High',
                    'description': 'Cross-site scripting found',
                    'unique_id_from_tool': 'xss-001'
                }
            ],
            scan_date=date.today()
        )
    """

    def __init__(self):
        """
        Initialize the Universal Parser V2 reimporter.

        Universal Parser V2 doesn't parse files, so it doesn't follow the
        standard importer initialization pattern. Instead, all configuration
        is provided when calling reimport_findings().
        """
        # Don't call parent __init__ since we don't have scan_type or test yet
        pass

    def reimport_findings(
        self,
        test: Test,
        findings_data: list[dict[str, Any]],
        scan_date: date_type,
        close_old_findings: bool = True,
        do_not_reactivate: bool = False,
        minimum_severity: str = 'Info',
        active: bool = True,
        verified: bool = False,
        push_to_jira: bool = False,
        version: str = None,
        tags: list = None,
        user = None,
        **kwargs
    ) -> Test_Import:
        """
        Reimport pre-normalized findings from Universal Parser V2 microservice.

        Args:
            test: DefectDojo Test instance to import into
            findings_data: List of normalized finding dictionaries from microservice
            scan_date: Date the scan was performed
            close_old_findings: Close findings not present in this scan
            do_not_reactivate: Do not reactivate previously closed findings
            minimum_severity: Minimum severity to import
            active: Mark new findings as active
            verified: Mark new findings as verified
            push_to_jira: Push findings to JIRA if configured
            version: Version string for the test
            tags: Tags to apply to findings
            user: User performing the import
            **kwargs: Additional parameters

        Returns:
            Test_Import object with statistics

        Example:
            >>> reimporter = UniversalParserV2ReImporter()
            >>> test_import = reimporter.reimport_findings(
            ...     test=test,
            ...     findings_data=[{
            ...         'title': 'SQL Injection',
            ...         'severity': 'Critical',
            ...         'description': 'SQL injection found',
            ...         'cwe': 89
            ...     }],
            ...     scan_date=date.today()
            ... )
            >>> test_import.new_findings_count
            1
        """
        logger.info(
            f"Starting Universal Parser V2 reimport for test {test.id}: "
            f"{len(findings_data)} findings"
        )

        # Convert date to datetime if needed (DefaultReImporter requires datetime)
        if isinstance(scan_date, date_type) and not isinstance(scan_date, datetime):
            scan_datetime = datetime.combine(scan_date, datetime.min.time())
        else:
            scan_datetime = scan_date

        # Create a DefaultReImporter instance for using its methods
        importer = DefaultReImporter(
            test=test,
            scan_type='Universal Parser V2',
            scan_date=scan_datetime,
            close_old_findings=close_old_findings,
            do_not_reactivate=do_not_reactivate,
            push_to_jira=push_to_jira,
            user=user,
            version=version,
            tags=tags if tags else [],
        )

        # Convert normalized findings to Finding objects
        parsed_findings = self._create_finding_objects(
            test=test,
            findings_data=findings_data,
            scan_date=scan_date,
            minimum_severity=minimum_severity,
            active=active,
            verified=verified
        )

        logger.debug(f"Created {len(parsed_findings)} Finding objects from normalized data")

        # Use importer's process_findings for deduplication
        (
            new_findings,
            reactivated_findings,
            findings_to_mitigate,
            untouched_findings,
        ) = importer.process_findings(parsed_findings)

        # Close old findings
        closed_findings = importer.close_old_findings(findings_to_mitigate)

        # Update test timestamps
        importer.update_timestamps()

        # Update test meta and tags
        importer.update_test_meta()
        if tags:
            importer.update_test_tags()

        # Save test and engagement
        test.save()
        test.engagement.save()

        # Create import history
        test_import = importer.update_import_history(
            new_findings=new_findings,
            closed_findings=closed_findings,
            reactivated_findings=reactivated_findings,
            untouched_findings=untouched_findings,
        )

        # Send notifications
        updated_count = len(closed_findings) + len(reactivated_findings) + len(new_findings)
        importer.notify_scan_added(
            test,
            updated_count,
            new_findings=new_findings,
            findings_reactivated=reactivated_findings,
            findings_mitigated=closed_findings,
            findings_untouched=untouched_findings,
        )

        # Update test progress
        importer.update_test_progress()

        logger.info(
            f"Universal Parser V2 reimport complete for test {test.id}: "
            f"created={len(new_findings)}, "
            f"updated={updated_count}, "
            f"closed={len(closed_findings)}, "
            f"reactivated={len(reactivated_findings)}, "
            f"untouched={len(untouched_findings)}"
        )

        return test_import

    def _create_finding_objects(
        self,
        test: Test,
        findings_data: list[dict[str, Any]],
        scan_date: date_type,
        minimum_severity: str,
        active: bool,
        verified: bool
    ) -> list[Finding]:
        """
        Convert normalized finding dictionaries to Finding objects.

        The microservice has already validated that required fields
        (title, description, severity) are present.

        Args:
            test: DefectDojo Test instance
            findings_data: List of normalized finding dictionaries
            scan_date: Scan date
            minimum_severity: Minimum severity to include
            active: Default active status
            verified: Default verified status

        Returns:
            List of Finding objects (not yet saved to database)
        """
        severity_order = {'Info': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        min_severity_value = severity_order.get(minimum_severity, 0)

        findings = []

        for data in findings_data:
            # Check severity filter
            finding_severity = data.get('severity', 'Info')
            if severity_order.get(finding_severity, 0) < min_severity_value:
                logger.debug(
                    f"Skipping finding '{data.get('title')}' "
                    f"(severity {finding_severity} below minimum {minimum_severity})"
                )
                continue

            # Create Finding object
            finding = Finding(
                test=test,
                date=data.get('date') or scan_date,

                # Required fields (already validated by microservice)
                title=data['title'],
                description=data['description'],
                severity=data['severity'],

                # Optional identification fields
                cwe=data.get('cwe'),
                unique_id_from_tool=data.get('unique_id_from_tool'),

                # CVSS fields
                cvssv3=data.get('cvssv3'),
                cvssv3_score=data.get('cvssv3_score'),
                cvssv4=data.get('cvssv4'),
                cvssv4_score=data.get('cvssv4_score'),

                # Additional details
                mitigation=data.get('mitigation'),
                impact=data.get('impact'),
                references=data.get('references'),

                # Location fields
                file_path=data.get('file_path'),
                line=data.get('line'),

                # Component fields
                component_name=data.get('component_name'),
                component_version=data.get('component_version'),

                # Status fields (use provided values or defaults)
                active=data.get('active', active),
                verified=data.get('verified', verified),
                false_p=data.get('false_p', False),
                duplicate=data.get('duplicate', False),
                out_of_scope=data.get('out_of_scope', False),
                risk_accepted=data.get('risk_accepted', False),

                # Static/Dynamic
                static_finding=data.get('static_finding', False),
                dynamic_finding=data.get('dynamic_finding', True),

                # Set numerical severity for sorting
                numerical_severity=self._get_numerical_severity(data['severity'])
            )

            findings.append(finding)

        return findings

    def _get_numerical_severity(self, severity: str) -> str:
        """
        Convert severity string to numerical value.

        Args:
            severity: Severity string (Critical, High, Medium, Low, Info)

        Returns:
            Numerical severity string for DefectDojo
        """
        severity_map = {
            'Critical': 'S0',
            'High': 'S1',
            'Medium': 'S2',
            'Low': 'S3',
            'Info': 'S4'
        }
        return severity_map.get(severity, 'S4')
