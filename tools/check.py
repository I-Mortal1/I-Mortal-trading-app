"""Build and verify the curated public library; no credentials or hardware needed."""
import base64
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import sys
from export_security import validate_text

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_publication():
    allowed = set(json.loads((ROOT / 'docs/publication-files.json').read_text()))
    actual = {str(p.relative_to(ROOT)).replace(os.sep, '/') for p in ROOT.rglob('*')
              if p.is_file() and not {'.git', 'bin', 'obj', '__pycache__'}.intersection(p.relative_to(ROOT).parts)}
    require(actual == allowed, 'Publication file set differs from reviewed allowlist: ' + str(sorted(actual ^ allowed)))
    for name in sorted(allowed):
        path = ROOT / name
        require(not path.is_symlink() and not any(p.is_symlink() for p in path.parents),
                'Symlink in publication: ' + name)
        validate_text(name, path.read_text(encoding='utf-8'))
    for entry in json.loads((ROOT / 'docs/source-manifest.json').read_text())['components']:
        require((ROOT / entry['path']).read_text() == (ROOT / entry['upstream']).read_text(),
                'Public utility differs from exported source: ' + entry['path'])
    print('PUBLICATION_FILE_AND_HEURISTIC_SECRET_CHECK=PASS')
    print('PUBLICATION_FILES=' + str(len(allowed)))


def main():
    check_publication()
    subprocess.run([sys.executable, str(ROOT / 'tools/test_export_security.py')], check=True, cwd=ROOT)
    with tempfile.TemporaryDirectory(prefix='imortal-check-') as temporary:
        env = dict(os.environ, DOTNET_CLI_HOME=temporary, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
        def run(project):
            print("BUILD=" + project, flush=True)
            result = subprocess.run(['dotnet', 'build', str(ROOT / project),
                                     '--configuration', 'Release', '--verbosity', 'quiet',
                                     '-p:SelfContained=false', '-p:PublishTrimmed=false', '-p:PublishSingleFile=false'],
                                    cwd=ROOT, env=env, text=True, capture_output=True, timeout=180)
            require(result.returncode == 0, result.stdout + result.stderr)
            assembly = ROOT / Path(project).parent / 'bin/Release/net10.0' / (Path(project).stem + '.dll')
            result = subprocess.run(['dotnet', str(assembly)], cwd=ROOT, env=env,
                                    text=True, capture_output=True, timeout=180)
            require(result.returncode == 0, result.stdout + result.stderr)
            return result.stdout
        export = run('tests/PublicExport/PublicExport.csproj')
        require('PUBLIC_EXPORT_BEHAVIOR=PASS' in export, 'Public export behavior did not pass')
        print(export, end='')
        policy = run('tests/AlgorithmPolicy/AlgorithmPolicy.csproj')
        require('ALLOWLIST_BEHAVIOR=PASS' in policy, 'Algorithm suite did not pass')
        print(policy, end='')
        result = json.loads(run('tests/Challenges/Challenges.csproj').strip().splitlines()[-1])
        cases = {
            'normal': (1700000000, 1700000300, 'audit-account'),
            'zero': (0, 0, 'audit-account'), 'negative': (-2, -1, 'audit-account'),
            'maximum_convertible': (9223372036854775, 9223372036854775, 'audit-account'),
            'minimum_convertible': (-9223372036854775, -9223372036854775, 'audit-account'),
            'nfc': (1700000000, 1700000300, 'caf\u00e9'),
            'multibyte': (1700000000, 1700000300, '\u8d26\u6237\U0001f512'),
            'maximum_string': (1700000000, 1700000300, 'x' * 16384),
            'maximum_multibyte_string': (1700000000, 1700000300, '\u00e9' * 8192),
        }
        require(set(result['Vectors']) == set(cases), 'Serialization case set differs')
        domain = 'I-MORTAL/USER-DEVICE-PROOF-OF-POSSESSION/CHALLENGE/CANONICAL/V1'
        for name, (issued, expires, account) in cases.items():
            fields = [domain, '1', 'audit-protocol', 'audit-challenge', 'audit-nonce', account, 'a' * 64, 'audit-purpose']
            expected = b''.join(struct.pack('>I', len(s.encode('utf-8'))) + s.encode('utf-8') for s in fields)
            expected += struct.pack('>qq', issued * 1000, expires * 1000)
            require(base64.b64decode(result['Vectors'][name], validate=True) == expected, 'Byte mismatch: ' + name)
        rejected = {'issued_positive_overflow', 'issued_negative_overflow', 'expiry_positive_overflow',
                    'expiry_negative_overflow', 'null_challenge', 'null_field', 'empty_field',
                    'decomposed_unicode', 'invalid_unicode', 'oversized_ascii', 'oversized_utf8'}
        require(set(result['Rejections']) == rejected and len(result['Rejections']) == 11, 'Rejection case set differs')
        print('SERIALIZATION_VECTORS=9; REJECTION_CASES=11; RESULT=PASS')
    check_publication()
    print('PUBLIC_RELEASE_CHECK=PASS')


if __name__ == '__main__':
    main()
