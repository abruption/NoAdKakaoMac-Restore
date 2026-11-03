"""독립 진단 스크립트의 인자 제한과 모듈 격리를 확인합니다."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DiagnosticScriptTests(unittest.TestCase):
    def setUp(self):
        root = Path('/tmp').resolve()
        if str(ROOT).startswith('/Volumes/'):
            root = Path('/Volumes') / ROOT.parts[2] / 'tmp'
            if not root.is_dir() or not os.access(root, os.W_OK):
                raise RuntimeError('프로젝트 볼륨의 임시 폴더가 필요합니다.')
        self.folder = Path(tempfile.mkdtemp(prefix='codex-diagnostic-script-', dir=root))
        self.addCleanup(shutil.rmtree, self.folder)

    def run_script(self, *args):
        return subprocess.run(['/bin/sh', str(ROOT / 'diagnose.sh'), *args],
                              cwd=self.folder, capture_output=True, text=True)

    def test_report_is_private_and_does_not_create_files(self):
        secret = 'private-user-token-example'
        (self.folder / 'gzip.py').write_text("raise RuntimeError('모듈 주입')\n")
        before = sorted(self.folder.iterdir())
        result = self.run_script('--app', str(self.folder / (secret + '.app')),
                                 '--backup-dir', str(self.folder / secret))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status']['state'], 'ERROR')
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(sorted(self.folder.iterdir()), before)

    def test_restore_command_is_rejected(self):
        result = self.run_script('restore', '--app', str(self.folder / 'missing.app'),
                                 '--backup-dir', str(self.folder / 'missing-backup'))
        self.assertEqual(result.returncode, 2)
        self.assertIn('오류:', result.stderr)
        self.assertEqual(result.stdout, '')
