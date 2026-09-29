"""Regression tests for publication redaction and input boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import export_security as export


class ExportTests(unittest.TestCase):
    def test_digest_and_identity_removed_without_removing_algorithm(self):
        raw = 'SHA256.HashData(data); "' + 'ab' * 32 + '"; user' + '@example.org'
        text, changes = export.sanitize('sample.cs', raw)
        self.assertIn('SHA256.HashData(data)', text)
        self.assertNotIn('ab' * 32, text)
        self.assertEqual(changes['digests'], 1)
        self.assertEqual(changes['identities'], 1)

    def test_credential_and_key_blocks_rejected(self):
        for value in ['ghp_' + 'x' * 32, '-----BEGIN ' + 'PRIVATE KEY-----',
                      '-----BEGIN ' + 'PUBLIC KEY-----', '\0']:
            with self.subTest(value=value[:8]), self.assertRaises(ValueError):
                export.sanitize('sample.cs', value)

    def test_paths_and_deployment_identifiers_removed(self):
        raw = 'root=C:' + '\\' + 'private\\project\nkey_name=private-alias\nknown_existing_nv_handles=hardware-id'
        text, changes = export.sanitize('sample.conf', raw)
        self.assertNotIn('private-alias', text)
        self.assertNotIn('hardware-id', text)
        self.assertEqual(changes['paths'], 1)
        self.assertEqual(changes['deployment_values'], 2)

    def test_recorded_digest_rejected_by_public_scan(self):
        with self.assertRaises(ValueError):
            export.validate_text('sample.json', 'cd' * 32)

    def test_new_source_missing_source_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / 'private'
            public = root / 'public'
            (private / 'src').mkdir(parents=True)
            (public / 'tools').mkdir(parents=True)
            source = private / 'src/Example.cs'
            source.write_text('class Example {}')
            manifest = public / 'tools/export-inputs.json'
            manifest.write_text(json.dumps({'files':['src/Example.cs']}))
            with patch.object(export, 'ROOT', public):
                first = export.prepare(private)
                self.assertEqual(first, export.prepare(private))
                extra = private / 'src/New.cs'
                extra.write_text('class New {}')
                with self.assertRaises(ValueError): export.prepare(private)
                extra.unlink()
                source.unlink()
                with self.assertRaises(ValueError): export.prepare(private)
                outside = root / 'outside.cs'
                outside.write_text('class Outside {}')
                source.symlink_to(outside)
                with self.assertRaises(ValueError): export.prepare(private)


if __name__ == '__main__':
    unittest.main()
