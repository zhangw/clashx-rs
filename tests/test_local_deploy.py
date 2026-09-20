"""Exercise deployment with fake Cargo/launchd; never touch the real service."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LocalDeploymentTest(unittest.TestCase):
    def test_custom_artifact_and_selection_restore(self):
        self.run_deployment(False)

    def test_rollback_restores_selections(self):
        self.run_deployment(True)

    def run_deployment(self, fail_restore):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / 'home'
            install = home / 'Library/Application Support/clashx-rs/bin'
            install.mkdir(parents=True)
            binary = install / 'clashx-rs'
            config = home / '.config/clashx-rs/config.yaml'
            config.parent.mkdir(parents=True)
            config.touch()
            plist = home / 'Library/LaunchAgents/org.clashx-rs.agent.plist'
            plist.parent.mkdir(parents=True)
            plist.touch()
            commands = root / 'commands'
            commands.mkdir()
            state = root / 'state.json'
            selected = {'🚀 group with spaces': '🇸🇬 changed node'}
            state.write_text(json.dumps({'selections': selected}))
            artifact = root / 'custom target/release/clashx-rs'
            artifact.parent.mkdir(parents=True)
            driver = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
state = pathlib.Path(os.environ['TEST_STATE'])
if name == 'uname': print('Darwin')
elif name == 'PlistBuddy':
    command = sys.argv[2]
    if command == 'Print :ProgramArguments:0': print(os.environ['TEST_BINARY'])
    elif command == 'Print :Label': print('org.clashx-rs.agent')
    elif command.startswith('Print :'): print('8192')
elif name == 'cargo':
    if 'build' in sys.argv:
        print(json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'clashx-rs', 'kind': ['bin']}, 'executable': os.environ['TEST_ARTIFACT']}))
elif name == 'launchctl':
    data = json.loads(state.read_text())
    if sys.argv[1] == 'print': sys.exit(0 if data.get('loaded', True) else 1)
    if sys.argv[1] == 'bootout':
        data['loaded'] = False
        state.write_text(json.dumps(data))
    if sys.argv[1] == 'bootstrap':
        state.write_text(json.dumps({'loaded': True, 'selections': {'🚀 group with spaces': 'default'}}))
else:
    if '--version' in sys.argv: print(VERSION)
    elif 'switch' in sys.argv:
        if VERSION == 'new' and os.environ['TEST_FAIL'] == 'yes': sys.exit(1)
        data = json.loads(state.read_text())
        data['selections'][sys.argv[-2]] = sys.argv[-1]
        state.write_text(json.dumps(data))
    elif 'status' in sys.argv: print(state.read_text())
'''
            for name in ('uname', 'PlistBuddy', 'cargo', 'launchctl'):
                path = commands / name
                path.write_text(driver)
                path.chmod(0o755)
            for path, version in ((binary, 'old'), (artifact, 'new')):
                path.write_text(driver.replace('import json,', f'VERSION = {version!r}\nimport json,'))
                path.chmod(0o755)
            scripts = root / 'scripts'
            scripts.mkdir()
            script = scripts / 'deploy-local-macos.sh'
            source = (ROOT / 'scripts/deploy-local-macos.sh').read_text()
            # Exclude unrelated cleanup of machine-wide command directories.
            source = source.split('# Remove only clashx-rs links')[0]
            script.write_text(source.replace('/usr/libexec/PlistBuddy', str(commands / 'PlistBuddy')))
            env = dict(os.environ, HOME=str(home), PATH=str(commands) + ':' + os.environ['PATH'],
                       TEST_STATE=str(state), TEST_BINARY=str(binary), TEST_ARTIFACT=str(artifact),
                       TEST_FAIL='yes' if fail_restore else 'no', CARGO_TARGET_DIR=str(artifact.parent.parent))
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1 if fail_restore else 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(state.read_text())['selections'], selected)
            self.assertIn("VERSION = 'old'" if fail_restore else "VERSION = 'new'", binary.read_text())
            if fail_restore:
                self.assertIn('Previous binary and selections restored', result.stderr)


if __name__ == '__main__':
    unittest.main()
