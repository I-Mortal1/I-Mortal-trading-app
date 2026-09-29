"""Build and verify the curated public library; no credentials or hardware needed."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_publication():
    allowed = set(json.loads((ROOT / 'docs/publication-files.json').read_text()))
    actual = {str(p.relative_to(ROOT)).replace(os.sep, '/') for p in ROOT.rglob('*')
              if p.is_file() and not {'.git', 'bin', 'obj', '__pycache__'}.intersection(p.relative_to(ROOT).parts)}
    require(actual == allowed, 'Publication file set differs from reviewed allowlist: ' + str(sorted(actual ^ allowed)))
    patterns = [
        rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----',
        rb'gh[pousr]_[A-Za-z0-9]{20,}', rb'github_pat_[A-Za-z0-9_]{20,}',
        rb'AKIA[0-9A-Z]{16}', rb'sk-[A-Za-z0-9_-]{20,}',
        rb'(?i)(?:password|api_key|access_token|client_secret)\s*[:=]\s*["\x27][^"\x27\s]{8,}["\x27]',
    ]
    for name in sorted(allowed):
        data = (ROOT / name).read_bytes()
        require(b'\0' not in data, 'Unexpected binary file: ' + name)
        for pattern in patterns:
            require(re.search(pattern, data) is None, 'Potential credential found in: ' + name)
    for entry in json.loads((ROOT / 'docs/source-manifest.json').read_text())['components']:
        require(hashlib.sha256((ROOT / entry['path']).read_bytes()).hexdigest() == entry['sha256'],
                'Reviewed source hash changed: ' + entry['path'])
    print('PUBLICATION_FILE_AND_HEURISTIC_SECRET_CHECK=PASS')
    print('PUBLICATION_FILES=' + str(len(allowed)))


def main():
    check_publication()
    with tempfile.TemporaryDirectory(prefix='imortal-check-') as temporary:
        env = dict(os.environ, DOTNET_CLI_HOME=temporary, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1')
        def run(project):
            result = subprocess.run(['dotnet', 'run', '--project', str(ROOT / project),
                                     '--configuration', 'Release', '--verbosity', 'quiet'],
                                    cwd=ROOT, env=env, text=True, capture_output=True, timeout=180)
            require(result.returncode == 0, result.stdout + result.stderr)
            return result.stdout
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
