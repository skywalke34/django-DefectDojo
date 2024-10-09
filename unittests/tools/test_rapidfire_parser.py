from django.test import TestCase
from django.utils import timezone
from dojo.models import Test
from dojo.tools.rapidfire.parser import RapidFireParser
from datetime import datetime

class TestRapidFireParser(TestCase):
    def test_parse_no_findings(self):
        testfile = open("unittests/scans/rapidfire/no_vuln.csv")
        parser = RapidFireParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/rapidfire/many_vulns.csv")
        parser = RapidFireParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))  # Adjust this number based on the actual content of many_vulns.csv

    def test_parse_single_finding(self):
        testfile = open("unittests/scans/rapidfire/one_vuln.csv")
        parser = RapidFireParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_invalid_date(self):
        testfile = open("unittests/scans/rapidfire/invalid_date.csv")
        parser = RapidFireParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))  # Adjust this number based on the actual content of invalid_date.csv
        finding = findings[0]
        self.assertTrue((timezone.now().date() - finding.date).days < 1)

    def test_port_parsing(self):
        testfile = open("unittests/scans/rapidfire/complex_ports.csv")
        parser = RapidFireParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))  # Adjust this number based on the actual content of complex_ports.csv
        finding = findings[0]
        self.assertEqual(3, len(finding.unsaved_endpoints))
        ports = sorted([ep.port for ep in finding.unsaved_endpoints])
        self.assertEqual(['80', '443', '8080'], ports)
