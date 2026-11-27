# -*- coding: utf-8 -*-
import unittest
from unittest.mock import MagicMock

from spiderfoot.services.domain_export_service import (
    extract_domains_from_events,
    format_domain_tree,
    generate_domain_tree_export,
)


def _make_row(data, event_type, false_positive=0):
    row = [0] * 14
    row[1] = data
    row[4] = event_type
    row[13] = false_positive
    return tuple(row)


class TestDomainExportService(unittest.TestCase):
    def test_extract_domains_filters_and_normalizes(self):
        rows = [
            _make_row('Example.COM', 'DOMAIN_NAME'),
            _make_row('<SFURL>api.example.com</SFURL>', 'INTERNET_NAME'),
            _make_row('unresolved.example.com.', 'INTERNET_NAME_UNRESOLVED'),
            _make_row('parent.example.com', 'DOMAIN_NAME_PARENT'),
            _make_row('fp.example.com', 'INTERNET_NAME', false_positive=1),
            _make_row('1.2.3.4', 'IP_ADDRESS'),
            _make_row('other.org', 'AFFILIATE_DOMAIN_NAME'),
        ]
        domains = extract_domains_from_events(rows)
        self.assertEqual(
            domains,
            {'example.com', 'api.example.com', 'unresolved.example.com', 'parent.example.com'},
        )

    def test_format_domain_tree_alphabetical_hierarchy(self):
        domains = [
            'other.org',
            'www.other.org',
            'mail.example.com',
            'staging.api.example.com',
            'example.com',
            'blog.example.com',
            'dev.api.example.com',
            'api.example.com',
            'deep.sub.other.org',
        ]
        expected = '\n'.join([
            'example.com',
            '├── api.example.com',
            '│   ├── dev.api.example.com',
            '│   └── staging.api.example.com',
            '├── blog.example.com',
            '└── mail.example.com',
            'other.org',
            '├── deep.sub.other.org',
            '└── www.other.org',
        ]) + '\n'
        self.assertEqual(format_domain_tree(domains), expected)

    def test_format_domain_tree_empty(self):
        self.assertEqual(format_domain_tree([]), '')

    def test_generate_domain_tree_export(self):
        dbh = MagicMock()
        dbh.scanInstanceGet.return_value = ('My Scan!', 'example.com')
        dbh.scanResultEvent.return_value = [
            _make_row('example.com', 'DOMAIN_NAME'),
            _make_row('b.example.com', 'INTERNET_NAME'),
            _make_row('a.example.com', 'INTERNET_NAME'),
        ]
        text, fname = generate_domain_tree_export(dbh, 'scan123')
        self.assertEqual(fname, 'My_Scan-domains-tree.txt')
        self.assertEqual(
            text,
            'example.com\n├── a.example.com\n└── b.example.com\n',
        )


if __name__ == '__main__':
    unittest.main()
