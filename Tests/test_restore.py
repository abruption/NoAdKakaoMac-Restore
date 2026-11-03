"""실제 앱 대신 합성 파일과 Apple 명령 대역으로 복원 경계를 시험합니다."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'restore_kakaotalk.py'
spec = importlib.util.spec_from_file_location('restore_kakaotalk', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        # 외장 프로젝트에서는 같은 볼륨의 전용 임시 루트를 사용합니다.
        root = Path('/tmp').resolve()
        if str(SOURCE).startswith('/Volumes/'):
            root = Path('/Volumes') / SOURCE.parts[2] / 'tmp'
            if not root.is_dir() or not os.access(root, os.W_OK):
                raise RuntimeError('프로젝트 볼륨의 임시 폴더가 필요합니다.')
        self.root = Path(tempfile.mkdtemp(prefix='codex-restore-test-', dir=root))
        self.app = self.root / 'KakaoTalk.app'
        self.backup = self.root / 'backup'
        self.backup.mkdir(mode=0o700)
        self.fake_calls = []
        self.patches = [patch.object(m, 'run', self.fake_run), patch.object(m, 'require_host', lambda: None)]
        for item in self.patches:
            item.start()
        self.addCleanup(self.cleanup)
        self.make_backup('100.20', '7001')

    def cleanup(self):
        for item in reversed(self.patches):
            item.stop()
        shutil.rmtree(self.root)

    def make_app(self, app, version, build, modified=False):
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/_CodeSignature').mkdir()
        (app / m.INFO).write_bytes(plistlib.dumps({'CFBundleIdentifier': m.BUNDLE_ID,
            'CFBundleShortVersionString': version, 'CFBundleVersion': build}))
        (app / m.EXE).write_bytes(('changed-' if modified else 'original-').encode() + version.encode())
        (app / m.EXE).chmod(0o755)
        (app / 'Contents/_CodeSignature/CodeResources').write_text('changed' if modified else 'official')
        for path in (app, *app.rglob('*')):
            if path.is_dir():
                path.chmod(0o755)

    def make_backup(self, version, build):
        for path in (self.app, self.backup / 'original.app'):
            if path.exists():
                shutil.rmtree(path)
        self.make_app(self.backup / 'original.app', version, build)
        self.make_app(self.app, version, build, modified=True)
        original = self.backup / 'original.app'
        self.record = {'schema': 1, 'tool_version': 'old-version', 'app_path': str(self.app),
                       'version': version, 'build': build, 'source_sha256': m.digest(original / m.EXE),
                       'original_tree': m.tree_manifest(original), 'patched_tree': m.tree_manifest(self.app),
                       'entitlements': {'sample': True}, 'state': 'PATCHED', 'architecture': 'arm64'}
        m.atomic_json(self.backup / 'manifest.json', self.record)

    def fake_run(self, *args):
        self.fake_calls.append(tuple(str(arg) for arg in args))
        if args[0] == '/bin/ps':
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args[0] == '/usr/bin/ditto':
            target = Path(args[-1])
            mode = target.stat().st_mode & 0o777
            shutil.copytree(args[-2], target, dirs_exist_ok=True, symlinks=True)
            target.chmod(mode)
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if args[0] != '/usr/bin/codesign':
            raise AssertionError(args)
        app = Path(args[-1])
        marker = (app / 'Contents/_CodeSignature/CodeResources').read_text()
        if marker == 'invalid':
            raise m.RestoreError('서명 불일치', 'SIGNATURE_INVALID')
        if '--verify' in args:
            return subprocess.CompletedProcess(args, 0, b'', b'')
        if '--entitlements' in args:
            return subprocess.CompletedProcess(args, 0, plistlib.dumps({'sample': True}), b'')
        detail = ('TeamIdentifier=' + m.TEAM_ID + '\nAuthority=Apple Root CA\nflags=0x10000(runtime)\n'
                  if marker == 'official' else 'TeamIdentifier=not set\nSignature=adhoc\n')
        return subprocess.CompletedProcess(args, 0, b'', detail.encode())

    def tool(self):
        return m.Restorer(self.app, self.backup)

    def assert_code(self, code, call):
        with self.assertRaises(m.RestoreError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_two_unregistered_versions_restore_and_preserve_previous(self):
        for version, build in [('100.20', '7001'), ('2.444', '89')]:
            with self.subTest(version=version):
                # 각 앱 경로는 동일하므로 이전 시험의 보존 파일만 시험 소유자로 정리합니다.
                tool = self.tool()
                if tool.previous.exists():
                    shutil.rmtree(tool.previous)
                self.make_backup(version, build)
                self.assertEqual(self.tool().status()['state'], 'RESTORABLE')
                result = self.tool().restore()
                self.assertEqual(result['state'], 'RESTORED')
                self.assertEqual(m.tree_manifest(self.app), self.record['original_tree'])
                self.assertEqual(m.tree_manifest(self.tool().previous), self.record['patched_tree'])
                self.assertEqual(m.load_json(self.backup / 'manifest.json')['state'], 'ORIGINAL')
                self.assertEqual(self.tool().restore()['state'], 'ORIGINAL')
                self.assertTrue((self.backup / 'original.app').is_dir())

    def test_newer_official_app_not_replaced_by_old_backup(self):
        shutil.rmtree(self.app)
        self.make_app(self.app, '999.8', '123456')
        before = m.tree_manifest(self.app)
        self.assertEqual(self.tool().restore()['state'], 'ORIGINAL')
        self.assertEqual(before, m.tree_manifest(self.app))
        self.assertFalse(self.tool().stage.exists())

    def test_updated_modified_app_refused(self):
        shutil.rmtree(self.app)
        self.make_app(self.app, '999.8', '123456', modified=True)
        self.assert_code('APP_MISMATCH', self.tool().restore)

    def test_corrupt_backup_refused(self):
        (self.backup / 'original.app' / m.EXE).write_bytes(b'corrupt')
        self.assert_code('BACKUP_MISMATCH', self.tool().restore)
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])

    def test_invalid_signature_backup_refused_even_with_matching_tree(self):
        (self.backup / 'original.app/Contents/_CodeSignature/CodeResources').write_text('invalid')
        self.record['original_tree'] = m.tree_manifest(self.backup / 'original.app')
        m.atomic_json(self.backup / 'manifest.json', self.record)
        self.assert_code('SIGNATURE_INVALID', self.tool().restore)

    def test_invalid_app_extension_refused(self):
        self.assert_code('INVALID_APP_PATH', lambda: m.Restorer(self.root / 'not-an-app', self.backup))

    def test_overlapping_explicit_paths_refused(self):
        for folder in (self.app, self.app / 'backup', self.root):
            with self.subTest(folder=folder):
                self.assert_code('OVERLAPPING_PATHS', lambda: m.Restorer(self.app, folder))

    def test_overlapping_discovered_path_refused(self):
        with patch.object(m, 'discover_backup', return_value=self.app / 'backup'):
            self.assert_code('OVERLAPPING_PATHS', m.Restorer(self.app).restore)
            self.assert_code('OVERLAPPING_PATHS', m.Restorer(self.app).status)

    def test_official_backup_without_runtime_flag_is_accepted(self):
        normal = self.fake_run
        def old_official(*args):
            result = normal(*args)
            if args[0] == '/usr/bin/codesign' and '-dv' in args:
                return subprocess.CompletedProcess(args, 0, result.stdout,
                    result.stderr.replace(b'flags=0x10000(runtime)\n', b'flags=0x0(none)\n'))
            return result
        with patch.object(m, 'run', old_official):
            self.assertEqual(self.tool().restore()['state'], 'RESTORED')

    def test_native_official_requirement_is_enforced(self):
        normal = self.fake_run
        def rejected(*args):
            if '--test-requirement' in args:
                raise m.RestoreError('공식 인증서 정책 불일치', 'OFFICIAL_REQUIREMENT_FAILED')
            return normal(*args)
        with patch.object(m, 'run', rejected):
            self.assert_code('OFFICIAL_REQUIREMENT_FAILED', self.tool().restore)
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])
        self.assertTrue(m.OFFICIAL_REQUIREMENT.startswith('= '))

    def test_current_invalid_signature_refused(self):
        (self.app / 'Contents/_CodeSignature/CodeResources').write_text('invalid')
        self.record['patched_tree'] = m.tree_manifest(self.app)
        m.atomic_json(self.backup / 'manifest.json', self.record)
        self.assert_code('SIGNATURE_INVALID', self.tool().restore)

    def test_legacy_interruption_is_not_resumed(self):
        m.atomic_json(self.backup / 'transaction.json', {'phase': 'SWAPPING'})
        self.assert_code('LEGACY_OPERATION_PENDING', self.tool().restore)
        self.assertTrue((self.backup / 'transaction.json').exists())

    def test_missing_backup_refuses_changes(self):
        tool = m.Restorer(self.app, self.root / 'absent')
        with self.assertRaises((m.RestoreError, OSError)):
            tool.restore()
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])

    def test_external_symlink_refused(self):
        (self.backup / 'original.app/Contents/escape').symlink_to('/etc/passwd')
        with self.assertRaises(m.RestoreError):
            self.tool().restore()

    def test_hardlink_refused(self):
        os.link(self.backup / 'original.app' / m.EXE, self.root / 'linked-exe')
        with self.assertRaises(m.RestoreError):
            self.tool().restore()

    def test_copy_failure_preserves_app_and_partial_stage(self):
        normal = self.fake_run
        def failed(*args):
            if args[0] == '/usr/bin/ditto':
                (Path(args[-1]) / 'partial').write_text('incomplete')
                raise m.RestoreError('복사 실패')
            return normal(*args)
        with patch.object(m, 'run', failed):
            with self.assertRaises(m.RestoreError):
                self.tool().restore()
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])
        self.assertTrue(self.tool().stage.exists())
        self.assertTrue((self.backup / 'restore-only-transaction.json').exists())
        self.assert_code('INCOMPLETE_PREPARATION', self.tool().status)
        with self.assertRaises(m.RestoreError):
            self.tool().restore()

    def test_interruption_between_renames_resumes_original_only(self):
        tool = self.tool()
        normal = tool._move
        def interrupted(source, target):
            normal(source, target)
            if target == tool.previous:
                raise KeyboardInterrupt()
        with patch.object(tool, '_move', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                tool.restore()
        self.assertFalse(self.app.exists())
        self.assertEqual(self.tool().status()['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(self.tool().restore()['state'], 'RESTORED')
        self.assertEqual(m.tree_manifest(self.app), self.record['original_tree'])

    def test_interruption_after_install_finishes_metadata(self):
        tool = self.tool()
        with patch.object(tool, '_finish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                tool.restore()
        self.assertEqual(m.tree_manifest(self.app), self.record['original_tree'])
        self.assertEqual(self.tool().status()['state'], 'RECOVERY_REQUIRED')
        self.assertEqual(self.tool().restore()['state'], 'RESTORED')
        self.assertFalse((self.backup / 'restore-only-transaction.json').exists())

    def test_changed_stage_inode_refused_on_resume(self):
        tool = self.tool()
        with patch.object(tool, '_resume', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                tool.restore()
        held = self.root / 'held-stage'
        tool.stage.rename(held)
        shutil.copytree(held, tool.stage)
        self.assert_code('ARTIFACT_CHANGED', self.tool().restore)

    def test_failed_install_rename_rolls_back_and_retry_restores(self):
        tool = self.tool()
        normal = tool._move
        def failed(source, target):
            if source == tool.stage:
                raise OSError('합성 이름 변경 실패')
            return normal(source, target)
        with patch.object(tool, '_move', failed):
            with self.assertRaises(OSError):
                tool.restore()
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])
        self.assertFalse(tool.previous.exists())
        self.assertEqual(self.tool().restore()['state'], 'RESTORED')

    def test_journal_tampering_refused(self):
        tool = self.tool()
        with patch.object(tool, '_resume', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                tool.restore()
        journal_path = self.backup / 'restore-only-transaction.json'
        journal = m.load_json(journal_path)
        journal['original_tree'] = {'unrelated': {}}
        m.atomic_json(journal_path, journal)
        self.assert_code('INVALID_JOURNAL', self.tool().restore)
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])

    def test_running_process_refused(self):
        normal = self.fake_run
        def running(*args):
            if args[0] == '/bin/ps':
                return subprocess.CompletedProcess(args, 0, ('42 ' + str(self.app / m.EXE)).encode(), b'')
            return normal(*args)
        with patch.object(m, 'run', running):
            self.assert_code('APP_RUNNING', self.tool().restore)

    def test_app_started_during_copy_is_preserved(self):
        normal = self.fake_run
        started = False
        def run(*args):
            nonlocal started
            if args[0] == '/bin/ps' and started:
                return subprocess.CompletedProcess(args, 0, ('42 ' + str(self.app / m.EXE)).encode(), b'')
            result = normal(*args)
            if args[0] == '/usr/bin/ditto':
                started = True
            return result
        with patch.object(m, 'run', run):
            self.assert_code('APP_RUNNING', self.tool().restore)
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])
        self.assertFalse(self.tool().previous.exists())
        self.assertEqual(self.tool().restore()['state'], 'RESTORED')

    def test_process_check_error_after_move_rolls_back(self):
        normal = self.fake_run
        ps_calls = 0
        def run(*args):
            nonlocal ps_calls
            if args[0] == '/bin/ps':
                ps_calls += 1
                if ps_calls == 3:
                    raise m.RestoreError('프로세스 조회 실패', 'PROCESS_CHECK_FAILED')
            return normal(*args)
        with patch.object(m, 'run', run):
            self.assert_code('PROCESS_CHECK_FAILED', self.tool().restore)
        self.assertEqual(m.tree_manifest(self.app), self.record['patched_tree'])
        self.assertFalse(self.tool().previous.exists())
        self.assertEqual(self.tool().restore()['state'], 'RESTORED')

    def test_unknown_user_returns_structured_failure(self):
        with patch.object(m.pwd, 'getpwuid', side_effect=KeyError):
            self.assert_code('INVALID_USER', m.user_backup_root)

    def test_entitlements_mismatch_refused(self):
        self.record['entitlements'] = {'different': True}
        m.atomic_json(self.backup / 'manifest.json', self.record)
        self.assert_code('BACKUP_MISMATCH', self.tool().restore)

    def test_status_has_no_filesystem_mutations(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        self.assertEqual(self.tool().status()['state'], 'RESTORABLE')
        after = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        self.assertEqual(before, after)
        self.assertFalse(self.tool().lock.exists())

    def test_diagnostic_is_read_only_and_omits_private_paths(self):
        before = m.tree_manifest(self.root)
        result = m.diagnose(self.app, self.backup)
        text = json.dumps(result)
        self.assertEqual(result['status']['state'], 'RESTORABLE')
        self.assertEqual(result['record']['tool_version'], None)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn(str(self.app), text)
        self.assertEqual(m.tree_manifest(self.root), before)

    def test_diagnostic_error_hides_external_command_and_paths(self):
        secret = 'secret-user-token-PRIVATE'
        with patch.object(m.Restorer, 'status', side_effect=m.RestoreError('/Users/' + secret, 'ARTIFACT_CHANGED')):
            result = m.diagnose(self.app, self.backup)
        self.assertEqual(result['status'], {'state': 'ERROR', 'code': 'ARTIFACT_CHANGED'})
        self.assertNotIn(secret, json.dumps(result))

    def test_diagnostic_filters_record_and_app_strings(self):
        secret = 'private-user-and-credential'
        self.record['tool_version'] = secret
        self.record['state'] = secret
        m.atomic_json(self.backup / 'manifest.json', self.record)
        info = plistlib.loads((self.app / m.INFO).read_bytes())
        info['CFBundleShortVersionString'] = secret
        (self.app / m.INFO).write_bytes(plistlib.dumps(info))
        result = m.diagnose(self.app, self.backup)
        self.assertIsNone(result['app']['version'])
        self.assertEqual(result['record']['state'], 'other')
        self.assertNotIn(secret, json.dumps(result))

    def test_diagnostic_reports_missing_backup_and_permissions(self):
        with patch.object(m.Restorer, 'status', side_effect=PermissionError(13, 'private-path')):
            result = m.diagnose(self.app, self.root / 'missing-backup')
        self.assertEqual(result['status'], {'state': 'ERROR', 'code': 'IO_ERROR', 'errno': 13})
        self.assertFalse(result['backup']['original.app']['exists'])
        self.assertNotIn('private-path', json.dumps(result))

    def test_diagnostic_unexpected_error_has_no_traceback_or_secret(self):
        with patch.object(m.Restorer, 'status', side_effect=RuntimeError('/Users/private-secret')):
            result = m.diagnose(self.app, self.backup)
        self.assertEqual(result['status']['code'], 'UNEXPECTED_DIAGNOSTIC_ERROR')
        self.assertNotIn('private-secret', json.dumps(result))

    def test_sudo_backup_home_and_multiple_backups(self):
        fakehome = self.root / 'other-home'
        expected = fakehome / 'Library/Application Support/NoAdKakaoMac/backups'
        with patch.object(m.os, 'geteuid', return_value=0), patch.dict(os.environ, {'SUDO_UID': '501'}), \
                patch.object(m.pwd, 'getpwuid', return_value=type('User', (), {'pw_dir': str(fakehome)})()):
            self.assertEqual(m.user_backup_root(), expected)
        root = self.root / 'discovery'
        root.mkdir(mode=0o700)
        for name in ('a', 'b'):
            folder = root / name
            folder.mkdir(mode=0o700)
            m.atomic_json(folder / 'manifest.json', self.record)
        with patch.object(m, 'user_backup_root', return_value=root):
            self.assert_code('AMBIGUOUS_BACKUP', lambda: m.discover_backup(self.app))


if __name__ == '__main__':
    unittest.main()
