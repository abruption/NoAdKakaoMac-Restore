#!/usr/bin/env python3
"""배포용 복원·진단 스크립트와 체크섬을 만듭니다."""
import argparse
import ast
import base64
import gzip
import hashlib
from pathlib import Path
import textwrap

parser = argparse.ArgumentParser(description='복원·진단 배포 파일을 생성합니다.')
parser.add_argument('--update-diagnostic', action='store_true', help='저장소의 diagnose.sh도 갱신')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = (root / 'restore_kakaotalk.py').read_bytes()
ast.parse(source.decode(), feature_version=(3, 9))
sha = hashlib.sha256(source).hexdigest()
payload = '\n'.join(textwrap.wrap(base64.b64encode(gzip.compress(source, mtime=0)).decode(), 100))
# 셸에서는 임시 파일을 만들지 않고, 검증한 소스를 Python 메모리에서 실행합니다.
shell = '''#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 abruption
# NoAdKakaoMac-Restore: 공식 전체 백업 복원 전용. MIT 고지는 아래에 포함됩니다.
set -eu
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\\n' 'Python 3.9 이상을 설치한 뒤 다시 실행해 주세요.' >&2
    exit 1
fi
exec python3 -I - "$@" <<'NOAD_RESTORE_PYTHON'
import base64, gzip, hashlib, sys
if sys.version_info < (3, 9):
    sys.exit('Python 3.9 이상이 필요합니다.')
source = gzip.decompress(base64.b64decode("""PAYLOAD""", validate=False))
if hashlib.sha256(source).hexdigest() != 'SOURCE_SHA':
    sys.exit('내장 복원 코드의 무결성 검사에 실패했습니다.')
sys.argv[0] = 'SCRIPT_NAME'
namespace = {'__name__': 'embedded_script'}
exec(compile(source, 'restore_kakaotalk.py', 'exec'), namespace)
sys.exit(namespace['ENTRYPOINT']())
NOAD_RESTORE_PYTHON
'''.replace('PAYLOAD', payload).replace('SOURCE_SHA', sha)
notices = (root / 'LICENSE').read_text(encoding='utf-8') + '\n' + (root / 'NOTICE').read_text(encoding='utf-8')
shell = shell.replace('# SPDX-License-Identifier: MIT', '# SPDX-License-Identifier: MIT\n' + '\n'.join(('# ' + line).rstrip() for line in notices.splitlines()))
out = root / 'build' / 'release'
out.mkdir(parents=True, exist_ok=True)
checksums = []
for name in ('restore.sh', 'diagnose.sh'):
    entrypoint = 'diagnostic_main' if name == 'diagnose.sh' else 'main'
    content = shell.replace('SCRIPT_NAME', name).replace('ENTRYPOINT', entrypoint)
    if name == 'diagnose.sh':
        content = content.replace('공식 전체 백업 복원 전용.', '읽기 전용 복구 진단.')
    (out / name).write_bytes(content.encode('utf-8'))
    (out / name).chmod(0o755)
    checksums.append(hashlib.sha256((out / name).read_bytes()).hexdigest() + '  ' + name)
(out / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
# 진단만 실행하는 같은 파일을 소스에서도 제공합니다.
if args.update_diagnostic:
    (root / 'diagnose.sh').write_bytes((out / 'diagnose.sh').read_bytes())
print('생성 완료: build/release/restore.sh, diagnose.sh, SHA256SUMS')
