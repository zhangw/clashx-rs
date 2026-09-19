"""Exercise the package transaction without touching real launchd or proxy settings."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SELECTED = {"🚀 group's $HOME `node`\nnext": "🇸🇬 node' $(touch NEVER)"}


@unittest.skipUnless(sys.platform == 'darwin', 'Uses macOS plutil and JavaScript for Automation')
class MacOSPackageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'
        self.app = self.home / 'Library/Application Support/clashx-rs'
        self.binary = self.app / 'bin/clashx-rs'
        self.config = self.home / '.config/clashx-rs/config.yaml'
        self.plist = self.home / 'Library/LaunchAgents/com.vincent.clashx-rs.plist'
        self.stage = self.root / 'stage'
        self.payload = self.stage / 'payload'
        (self.payload / 'config').mkdir(parents=True)
        self.commands = self.root / 'commands'
        self.commands.mkdir()
        self.state = self.root / 'state.json'
        self.state.write_text(json.dumps({'loaded': False, 'disabled': False, 'selections': SELECTED}))
        self.log = self.root / 'calls.jsonl'
        self.log.touch()
        self.driver = f'#!{sys.executable}\n' + '''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
state_path = pathlib.Path(os.environ['TEST_STATE'])
data = json.loads(state_path.read_text())
args = sys.argv[1:]
snapshot = pathlib.Path(os.environ['HOME']) / '.config/clashx-rs/sysproxy-snapshot.json'
proxy_case = os.environ.get('TEST_PROXY_CASE', 'crash')
with open(os.environ['TEST_LOG'], 'a') as stream:
    stream.write(json.dumps([name] + args) + '\\n')
failure = os.environ.get('TEST_FAIL', '')
if name == 'id':
    print('501')
elif name == 'sleep':
    pass
elif name == 'launchctl':
    if args[0] == 'print':
        sys.exit(0 if data['loaded'] else 1)
    elif args[0] == 'bootout':
        data['loaded'] = False
        if proxy_case == 'graceful' and snapshot.exists():
            data['proxy'] = json.loads(snapshot.read_text())['proxy']
            snapshot.unlink()
    elif args[0] == 'bootstrap':
        content = pathlib.Path(os.environ['TEST_BINARY']).read_text()
        if failure == 'rollback' or (failure == 'bootstrap' and "VERSION = 'new'" in content.splitlines()):
            sys.exit(1)
        data['loaded'] = True
        data['selections'] = {key: 'default node' for key in data['selections']}
        if failure == 'ready':
            snapshot.write_text(json.dumps({'proxy': data.get('proxy', 'original')}))
            data['proxy'] = 'other-new-proxy' if proxy_case == 'changed' else 'clashx'
            runtime = pathlib.Path(os.environ['HOME']) / '.config/clashx-rs'
            (runtime / 'clashx-rs-7890.pid').write_text('123')
            (runtime / 'clashx-rs-7890.sock').touch()
    elif args[0] == 'enable':
        data['disabled'] = False
else:
    if '--version' in args:
        print('clashx-rs ' + VERSION)
    elif 'sysproxy' in args:
        if args[-1] == 'off':
            data['proxy'] = 'off'
            snapshot.unlink(missing_ok=True)
        elif args[-1] == 'restore' and snapshot.exists():
            if proxy_case == 'restore-failure':
                sys.exit(1)
            if data.get('proxy') == 'clashx':
                data['proxy'] = json.loads(snapshot.read_text())['proxy']
            snapshot.unlink()
        print('proxy state')
    elif 'status' in args:
        if not data['loaded'] or (failure == 'ready' and VERSION == 'new'):
            sys.exit(1)
        print(json.dumps({'selections': data['selections']}))
    elif 'switch' in args:
        if failure == 'selections' and VERSION == 'new':
            sys.exit(1)
        data['selections'][args[-2]] = args[-1]
state_path.write_text(json.dumps(data))
'''
        for name in ('id', 'launchctl', 'sleep'):
            self.write_executable(self.commands / name, self.driver)
        self.write_executable(self.payload / 'clashx-rs', self.versioned('new'))
        shutil.copy(ROOT / 'scripts/local-service.sh', self.payload / 'local-service.sh')
        (self.payload / 'config/config.yaml').write_text('source config\n')
        (self.payload / 'config/Country.mmdb').write_bytes(b'database')
        (self.payload / 'config/subscriptions.yaml').write_text('source subscriptions\n')
        (self.payload / 'package-info.txt').write_text('new package\n')
        (self.payload / 'macos-major').write_text('27\n')
        (self.payload / 'launchagent.plist').write_bytes(plistlib.dumps({
            'Label': 'com.vincent.clashx-rs',
            'ProgramArguments': [str(self.binary), '--config', str(self.config), 'run', '--sysproxy'],
        }))
        self.checksums()
        source = (ROOT / 'scripts/macos-pkg/install-user.sh').read_text()
        # Only adapt the fixed user home; real commands run against temporary files.
        (self.stage / 'install-user.sh').write_text(source.replace('/Users/vincent', str(self.home)))
        shutil.copy(ROOT / 'scripts/macos-pkg/selections.js', self.stage / 'selections.js')
        self.env = dict(os.environ, HOME=str(self.home),
                        PATH=str(self.commands) + ':' + os.environ['PATH'],
                        TEST_STATE=str(self.state), TEST_LOG=str(self.log), TEST_BINARY=str(self.binary))

    def versioned(self, version):
        return self.driver.replace('import json,', f'VERSION = {version!r}\nimport json,')

    def write_executable(self, path, text):
        path.write_text(text)
        path.chmod(0o755)

    def checksums(self):
        files = sorted(p for p in self.payload.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
        (self.payload / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(self.payload)) + '\n'
            for p in files))

    def existing(self, loaded=True, disabled=False):
        self.binary.parent.mkdir(parents=True)
        self.write_executable(self.binary, self.versioned('old'))
        (self.app / 'local-service.sh').write_text('old helper\n')
        (self.app / 'package-info.txt').write_text('old package\n')
        self.config.parent.mkdir(parents=True)
        self.config.write_text('target custom config\n')
        (self.config.parent / 'subscriptions.yaml').write_text('target subscriptions\n')
        self.plist.parent.mkdir(parents=True)
        self.plist.write_bytes((self.payload / 'launchagent.plist').read_bytes())
        self.state.write_text(json.dumps({'loaded': loaded, 'disabled': disabled, 'selections': SELECTED}))

    def run_install(self, fail='', success=True):
        result = subprocess.run(['/bin/bash', str(self.stage / 'install-user.sh')],
                                env=dict(self.env, TEST_FAIL=fail), cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def assert_preserved(self):
        self.assertEqual(self.config.read_text(), 'target custom config\n')
        self.assertEqual((self.config.parent / 'subscriptions.yaml').read_text(), 'target subscriptions\n')
        self.assertEqual(self.plist.read_bytes(), (self.payload / 'launchagent.plist').read_bytes())

    def test_first_install(self):
        self.run_install()
        self.assertEqual(self.config.read_text(), 'source config\n')
        self.assertTrue(json.loads(self.state.read_text())['loaded'])
        self.assertIn("VERSION = 'new'", self.binary.read_text().splitlines())
        self.assertFalse((self.app / '.pkg-install').exists())
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_upgrade_preserves_configuration_and_unicode_selections(self):
        self.existing()
        self.run_install()
        self.assert_preserved()
        data = json.loads(self.state.read_text())
        # launchd resets choices; restore must produce exactly the saved mapping.
        self.assertEqual(data['selections'], SELECTED)
        self.assertIn("VERSION = 'old'", (self.binary.parent / 'clashx-rs.previous').read_text().splitlines())
        self.assertFalse((self.root / 'NEVER').exists())

    def test_upgrade_preserves_disabled_and_stopped_state(self):
        self.existing(loaded=False, disabled=True)
        self.run_install()
        self.assert_preserved()
        data = json.loads(self.state.read_text())
        self.assertFalse(data['loaded'])
        self.assertTrue(data['disabled'])
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertFalse(any(c[:2] in [['launchctl', 'enable'], ['launchctl', 'bootstrap']] for c in calls))

    def test_bootstrap_failure_rolls_back(self):
        self.existing()
        result = self.run_install(fail='bootstrap', success=False)
        self.assert_preserved()
        self.assertIn("VERSION = 'old'", self.binary.read_text().splitlines())
        self.assertEqual(json.loads(self.state.read_text())['selections'], SELECTED)
        self.assertIn('Previous installation state restored.', result.stderr)

    def test_selection_failure_rolls_back(self):
        self.existing()
        self.run_install(fail='selections', success=False)
        self.assert_preserved()
        self.assertIn("VERSION = 'old'", self.binary.read_text().splitlines())
        self.assertEqual((self.app / 'local-service.sh').read_text(), 'old helper\n')
        self.assertEqual((self.app / 'package-info.txt').read_text(), 'old package\n')
        self.assertEqual(json.loads(self.state.read_text())['selections'], SELECTED)

    def test_failed_rollback_keeps_backup_and_blocks_retry(self):
        self.existing()
        result = self.run_install(fail='rollback', success=False)
        backup = self.app / '.pkg-install/old-binary'
        self.assertTrue(backup.is_file())
        self.assertIn('Rollback incomplete.', result.stderr)
        self.assert_preserved()
        self.run_install(success=False)
        self.assertTrue(backup.is_file())

    def test_failed_first_start_cleans_up_and_can_retry(self):
        self.run_install(fail='ready', success=False)
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.plist.exists())
        self.assertFalse(json.loads(self.state.read_text())['loaded'])
        self.run_install()

    def test_fresh_bootstrap_failure_preserves_existing_proxy(self):
        data = json.loads(self.state.read_text())
        data['proxy'] = 'original'
        self.state.write_text(json.dumps(data))
        self.run_install(fail='bootstrap', success=False)
        self.assertEqual(json.loads(self.state.read_text())['proxy'], 'original')
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertFalse(any(call[-2:] == ['sysproxy', 'off'] for call in calls))

    def test_fresh_rollback_restores_snapshot(self):
        self.run_install(fail='ready', success=False)
        self.assertEqual(json.loads(self.state.read_text())['proxy'], 'original')
        self.assertFalse((self.config.parent / 'sysproxy-snapshot.json').exists())

    def test_fresh_rollback_leaves_gracefully_restored_proxy_alone(self):
        self.env['TEST_PROXY_CASE'] = 'graceful'
        self.run_install(fail='ready', success=False)
        self.assertEqual(json.loads(self.state.read_text())['proxy'], 'original')

    def test_fresh_rollback_preserves_later_proxy_change(self):
        self.env['TEST_PROXY_CASE'] = 'changed'
        self.run_install(fail='ready', success=False)
        self.assertEqual(json.loads(self.state.read_text())['proxy'], 'other-new-proxy')

    def test_fresh_proxy_restore_failure_keeps_recovery_files(self):
        self.env['TEST_PROXY_CASE'] = 'restore-failure'
        result = self.run_install(fail='ready', success=False)
        self.assertIn('Rollback incomplete.', result.stderr)
        self.assertTrue((self.config.parent / 'sysproxy-snapshot.json').is_file())
        self.assertTrue(self.binary.is_file())
        self.assertTrue(self.config.is_file())
        self.assertTrue((self.app / '.pkg-install').is_dir())

    def test_incomplete_install_is_left_untouched(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text('keep me')
        self.run_install(success=False)
        self.assertEqual(self.config.read_text(), 'keep me')
        self.assertFalse(self.binary.exists())

    def test_tampered_payload_does_not_stop_service(self):
        self.existing()
        (self.payload / 'config/config.yaml').write_text('changed after packaging')
        self.run_install(success=False)
        self.assertTrue(json.loads(self.state.read_text())['loaded'])
        self.assertIn("VERSION = 'old'", self.binary.read_text().splitlines())

    def test_wrapper_preflight_and_user_dispatch(self):
        wrapper = (ROOT / 'scripts/macos-pkg/postinstall').read_text()
        wrapper = wrapper.replace('export PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                                  'export PATH="$TEST_WRAPPER_PATH"')
        (self.stage / 'postinstall').write_text(wrapper)
        driver = f'#!{sys.executable}\n' + '''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['TEST_LOG'], 'a') as stream:
    stream.write(json.dumps([name] + args) + '\\n')
if name == 'id':
    print('501' if 'vincent' in args else '0')
elif name == 'uname': print(os.environ.get('TEST_ARCH', 'arm64'))
elif name == 'sw_vers': print(os.environ.get('TEST_OS', '27.2'))
elif name == 'stat': print(os.environ.get('TEST_CONSOLE', 'vincent'))
elif name == 'dscl': print('NFSHomeDirectory: /Users/vincent')
# chown and launchctl are recorded, never performed (including asuser).
'''
        for name in ('id', 'uname', 'sw_vers', 'stat', 'dscl', 'chown', 'launchctl'):
            self.write_executable(self.commands / name, driver)
        env = dict(self.env, TEST_WRAPPER_PATH=str(self.commands) + ':/usr/bin:/bin:/usr/sbin:/sbin')
        for settings, volume, success in [({}, '/', True), ({'TEST_ARCH': 'x86_64'}, '/', False),
                                          ({'TEST_OS': '26.1'}, '/', False),
                                          ({'TEST_CONSOLE': 'other'}, '/', False),
                                          ({}, '/Volumes/Other', False)]:
            with self.subTest(settings=settings, volume=volume):
                self.log.write_text('')
                result = subprocess.run(['/bin/bash', str(self.stage / 'postinstall'),
                                         'test.pkg', '/', volume], env=dict(env, **settings),
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                dispatch = [json.loads(line) for line in self.log.read_text().splitlines()
                            if json.loads(line)[:2] == ['launchctl', 'asuser']]
                self.assertEqual(len(dispatch), 1 if success else 0)
                if success:
                    self.assertEqual(dispatch[0][2:8], ['501', '/usr/bin/sudo', '-H', '-u', 'vincent', '/usr/bin/env'])
                    self.assertFalse(Path(dispatch[0][-1]).exists(), 'Wrapper must clean up staging files')


if __name__ == '__main__':
    unittest.main()
