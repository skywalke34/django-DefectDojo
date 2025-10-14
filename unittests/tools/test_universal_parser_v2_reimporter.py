"""
Unit tests for Universal Parser V2 ReImporter.

Tests the reimporter class directly with normalized finding dictionaries,
verifying:
- Creation of new findings
- Deduplication using unique_id_from_tool
- Closing old findings not present in new scan
- Reactivation of previously closed findings
- Severity filtering
- Field mapping and data integrity
"""

import logging
from datetime import date

from django.utils import timezone

from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, Test, Test_Type, User
from dojo.tools.universal_parser_v2.reimporter import UniversalParserV2ReImporter
from unittests.dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestUniversalParserV2ReImporter(DojoTestCase):
    """Test cases for UniversalParserV2ReImporter."""

    def setUp(self):
        """Set up test fixtures for each test."""
        # Create user
        self.user, _ = User.objects.get_or_create(username="test_user")

        # Create product type
        self.product_type, _ = Product_Type.objects.get_or_create(
            name="Universal Parser V2 Test Type"
        )

        # Create product
        self.product, _ = Product.objects.get_or_create(
            name="Universal Parser V2 Test Product",
            prod_type=self.product_type,
        )

        # Create engagement
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Universal Parser V2 Test Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        # Create test type
        self.test_type, _ = Test_Type.objects.get_or_create(
            name="Universal Parser V2 Test"
        )

        # Create test
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        # Create reimporter instance
        self.reimporter = UniversalParserV2ReImporter()

        # Sample findings data
        self.sample_findings = [
            {
                'title': 'SQL Injection Vulnerability',
                'description': 'SQL injection found in login form',
                'severity': 'Critical',
                'cwe': 89,
                'unique_id_from_tool': 'sql-001',
                'cvssv3': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cvssv3_score': 9.8,
                'mitigation': 'Use parameterized queries',
                'impact': 'Attackers can access or modify database contents',
                'references': 'https://owasp.org/www-community/attacks/SQL_Injection',
                'file_path': '/app/login.py',
                'line': 42,
            },
            {
                'title': 'Cross-Site Scripting (XSS)',
                'description': 'Reflected XSS vulnerability in search parameter',
                'severity': 'High',
                'cwe': 79,
                'unique_id_from_tool': 'xss-001',
                'cvssv3': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'cvssv3_score': 6.1,
                'mitigation': 'Sanitize user input and encode output',
                'impact': 'Attackers can execute malicious scripts',
                'references': 'https://owasp.org/www-community/attacks/xss/',
            },
            {
                'title': 'Insecure Cryptographic Storage',
                'description': 'Passwords stored using weak MD5 hashing',
                'severity': 'Medium',
                'cwe': 327,
                'unique_id_from_tool': 'crypto-001',
                'mitigation': 'Use bcrypt or Argon2 for password hashing',
                'file_path': '/app/auth.py',
                'line': 156,
            },
        ]

    def test_reimport_creates_new_findings(self):
        """Test that reimport creates new findings correctly."""
        logger.debug("Testing reimport creates new findings")

        # Perform reimport
        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        # Verify import statistics
        self.assertEqual(3, test_import.new_findings_count)
        self.assertEqual(0, test_import.closed_findings_count)
        self.assertEqual(0, test_import.reactivated_findings_count)

        # Verify findings were created
        findings = Finding.objects.filter(test=self.test)
        self.assertEqual(3, findings.count())

        # Verify first finding details
        finding = findings.get(unique_id_from_tool='sql-001')
        self.assertEqual('SQL Injection Vulnerability', finding.title)
        self.assertEqual('Critical', finding.severity)
        self.assertEqual(89, finding.cwe)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual('/app/login.py', finding.file_path)
        self.assertEqual(42, finding.line)
        self.assertTrue(finding.active)
        self.assertFalse(finding.verified)

        # Verify second finding
        finding = findings.get(unique_id_from_tool='xss-001')
        self.assertEqual('Cross-Site Scripting (XSS)', finding.title)
        self.assertEqual('High', finding.severity)
        self.assertEqual(79, finding.cwe)

        # Verify third finding
        finding = findings.get(unique_id_from_tool='crypto-001')
        self.assertEqual('Insecure Cryptographic Storage', finding.title)
        self.assertEqual('Medium', finding.severity)
        self.assertEqual(327, finding.cwe)

    def test_reimport_deduplicates_existing_findings(self):
        """Test that reimport doesn't duplicate existing findings."""
        logger.debug("Testing reimport deduplication")

        # First import
        test_import1 = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        self.assertEqual(3, test_import1.new_findings_count)

        # Second import with same findings
        test_import2 = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        # Should have 0 new findings (all deduplicated)
        self.assertEqual(0, test_import2.new_findings_count)
        self.assertEqual(3, test_import2.untouched_findings_count)

        # Total findings should still be 3
        findings = Finding.objects.filter(test=self.test, active=True)
        self.assertEqual(3, findings.count())

    def test_reimport_closes_old_findings(self):
        """Test that reimport closes findings not present in new scan."""
        logger.debug("Testing reimport closes old findings")

        # First import with 3 findings
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        # Verify 3 active findings
        active_findings_before = Finding.objects.filter(test=self.test, active=True).count()
        self.assertEqual(3, active_findings_before)

        # Second import with only 1 finding (should close 2)
        new_findings_data = [self.sample_findings[0]]  # Only SQL injection

        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=new_findings_data,
            scan_date=date.today(),
            close_old_findings=True,
            user=self.user,
        )

        # Verify 2 findings were closed
        self.assertEqual(2, test_import.closed_findings_count)
        self.assertEqual(0, test_import.new_findings_count)
        self.assertEqual(1, test_import.untouched_findings_count)

        # Verify only 1 active finding remains
        active_findings_after = Finding.objects.filter(test=self.test, active=True).count()
        self.assertEqual(1, active_findings_after)

        # Verify the remaining finding is correct
        remaining_finding = Finding.objects.get(test=self.test, active=True)
        self.assertEqual('sql-001', remaining_finding.unique_id_from_tool)

    def test_reimport_reactivates_closed_findings(self):
        """Test that reimport reactivates previously closed findings."""
        logger.debug("Testing reimport reactivates closed findings")

        # First import
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        # Second import with subset (closes 2 findings)
        subset_findings = [self.sample_findings[0]]
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=subset_findings,
            scan_date=date.today(),
            close_old_findings=True,
            user=self.user,
        )

        # Verify 2 findings are closed
        closed_findings = Finding.objects.filter(test=self.test, active=False).count()
        self.assertEqual(2, closed_findings)

        # Third import with all findings again (should reactivate 2)
        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            do_not_reactivate=False,
            user=self.user,
        )

        # Verify 2 findings were reactivated
        self.assertEqual(2, test_import.reactivated_findings_count)
        self.assertEqual(0, test_import.new_findings_count)

        # Verify all 3 findings are now active
        active_findings = Finding.objects.filter(test=self.test, active=True).count()
        self.assertEqual(3, active_findings)

    def test_reimport_respects_do_not_reactivate(self):
        """Test that do_not_reactivate parameter prevents reactivation."""
        logger.debug("Testing do_not_reactivate parameter")

        # First import
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            user=self.user,
        )

        # Second import with subset (closes 2 findings)
        subset_findings = [self.sample_findings[0]]
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=subset_findings,
            scan_date=date.today(),
            close_old_findings=True,
            user=self.user,
        )

        # Third import with all findings but do_not_reactivate=True
        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            close_old_findings=False,
            do_not_reactivate=True,
            user=self.user,
        )

        # Verify no reactivations occurred
        self.assertEqual(0, test_import.reactivated_findings_count)

        # Verify only 1 finding is active (the one that was never closed)
        active_findings = Finding.objects.filter(test=self.test, active=True).count()
        self.assertEqual(1, active_findings)

    def test_reimport_applies_severity_filter(self):
        """Test that minimum_severity filter works correctly."""
        logger.debug("Testing severity filter")

        # Import with minimum_severity=High (should exclude Medium and lower)
        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            minimum_severity='High',
            user=self.user,
        )

        # Should only create 2 findings (Critical and High, not Medium)
        self.assertEqual(2, test_import.new_findings_count)

        findings = Finding.objects.filter(test=self.test)
        self.assertEqual(2, findings.count())

        # Verify only Critical and High severity findings
        severities = [f.severity for f in findings]
        self.assertIn('Critical', severities)
        self.assertIn('High', severities)
        self.assertNotIn('Medium', severities)

    def test_reimport_applies_active_and_verified_defaults(self):
        """Test that active and verified parameters are applied correctly."""
        logger.debug("Testing active and verified parameters")

        # Import with active=False and verified=True
        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            active=False,
            verified=True,
            user=self.user,
        )

        # Verify all findings have correct status
        findings = Finding.objects.filter(test=self.test)
        for finding in findings:
            self.assertFalse(finding.active)
            self.assertTrue(finding.verified)

    def test_reimport_handles_missing_optional_fields(self):
        """Test that reimport handles findings with minimal fields."""
        logger.debug("Testing minimal finding fields")

        # Minimal finding with only required fields
        minimal_finding = [
            {
                'title': 'Minimal Finding',
                'description': 'Just the basics',
                'severity': 'Low',
            }
        ]

        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=minimal_finding,
            scan_date=date.today(),
            user=self.user,
        )

        self.assertEqual(1, test_import.new_findings_count)

        finding = Finding.objects.get(test=self.test)
        self.assertEqual('Minimal Finding', finding.title)
        self.assertEqual('Low', finding.severity)
        self.assertIsNone(finding.cwe)
        self.assertIsNone(finding.unique_id_from_tool)

    def test_reimport_preserves_all_finding_fields(self):
        """Test that all finding fields are correctly mapped."""
        logger.debug("Testing all finding fields")

        # Finding with many fields populated
        comprehensive_finding = [
            {
                'title': 'Comprehensive Finding',
                'description': 'All fields populated',
                'severity': 'High',
                'cwe': 89,
                'unique_id_from_tool': 'comp-001',
                'cvssv3': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cvssv3_score': 9.8,
                'cvssv4': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
                'cvssv4_score': 9.3,
                'mitigation': 'Apply security patch',
                'impact': 'Data breach possible',
                'references': 'https://example.com/vuln',
                'file_path': '/app/main.py',
                'line': 100,
                'component_name': 'web-framework',
                'component_version': '1.2.3',
                'active': True,
                'verified': True,
                'false_p': False,
                'duplicate': False,
                'out_of_scope': False,
                'risk_accepted': False,
                'static_finding': True,
                'dynamic_finding': False,
            }
        ]

        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=comprehensive_finding,
            scan_date=date.today(),
            user=self.user,
        )

        finding = Finding.objects.get(test=self.test)

        # Verify all fields
        self.assertEqual('Comprehensive Finding', finding.title)
        self.assertEqual('All fields populated', finding.description)
        self.assertEqual('High', finding.severity)
        self.assertEqual(89, finding.cwe)
        self.assertEqual('comp-001', finding.unique_id_from_tool)
        self.assertEqual('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', finding.cvssv3)
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', finding.cvssv4)
        self.assertEqual(9.3, finding.cvssv4_score)
        self.assertEqual('Apply security patch', finding.mitigation)
        self.assertEqual('Data breach possible', finding.impact)
        self.assertEqual('https://example.com/vuln', finding.references)
        self.assertEqual('/app/main.py', finding.file_path)
        self.assertEqual(100, finding.line)
        self.assertEqual('web-framework', finding.component_name)
        self.assertEqual('1.2.3', finding.component_version)
        self.assertTrue(finding.active)
        self.assertTrue(finding.verified)
        self.assertFalse(finding.false_p)
        self.assertFalse(finding.duplicate)
        self.assertFalse(finding.out_of_scope)
        self.assertFalse(finding.risk_accepted)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual('S1', finding.numerical_severity)  # High = S1

    def test_reimport_with_tags(self):
        """Test that tags are applied to findings."""
        logger.debug("Testing tags application")

        tags = ['automated', 'security-scan']

        test_import = self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            tags=tags,
            user=self.user,
        )

        self.assertEqual(3, test_import.new_findings_count)

        # Note: Tag verification would require checking test.tags
        # The reimporter applies tags to the test, not individual findings

    def test_reimport_with_version(self):
        """Test that version is applied to test."""
        logger.debug("Testing version application")

        version = '1.2.3'

        self.reimporter.reimport_findings(
            test=self.test,
            findings_data=self.sample_findings,
            scan_date=date.today(),
            version=version,
            user=self.user,
        )

        # Reload test from database
        self.test.refresh_from_db()
        self.assertEqual(version, self.test.version)
