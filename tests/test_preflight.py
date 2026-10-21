import unittest
from unittest.mock import patch
from zog.archive_mirror.preflight import check_runtime


class PreflightTests(unittest.TestCase):
    def test_installed_runtime_runs_native_operations(self):
        self.assertTrue(check_runtime()['ready'])

    def test_missing_extension_fails_without_leaking_exception_text(self):
        import importlib
        original=importlib.import_module
        def missing(name):
            if name=='ssl':raise ImportError('private diagnostic')
            return original(name)
        with patch('zog.archive_mirror.preflight.importlib.import_module',side_effect=missing):
            report=check_runtime()
        self.assertFalse(report['ready'])
        self.assertEqual(next(x for x in report['checks'] if x['name']=='ssl')['error'],'ImportError')
        self.assertNotIn('private diagnostic',str(report))
