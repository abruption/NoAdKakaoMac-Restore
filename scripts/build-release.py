#!/usr/bin/env python3
"""배포용 단일 복원 스크립트와 체크섬을 만듭니다."""
import ast
import base64
import gzip
import hashlib
from pathlib import Path
import textwrap

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
sys.argv[0] = 'restore.sh'
exec(compile(source, 'restore_kakaotalk.py', 'exec'), {'__name__': '__main__'})
NOAD_RESTORE_PYTHON
'''.replace('PAYLOAD', payload).replace('SOURCE_SHA', sha)
notices = (root / 'LICENSE').read_text(encoding='utf-8') + '\n' + (root / 'NOTICE').read_text(encoding='utf-8')
shell = shell.replace('# SPDX-License-Identifier: MIT', '# SPDX-License-Identifier: MIT\n' + '\n'.join('# ' + line for line in notices.splitlines()))
out = root / 'build' / 'release'
out.mkdir(parents=True, exist_ok=True)
(out / 'restore.sh').write_bytes(shell.encode('utf-8'))
(out / 'restore.sh').chmod(0o755)
(out / 'SHA256SUMS').write_text(hashlib.sha256((out / 'restore.sh').read_bytes()).hexdigest() + '  restore.sh\n', encoding='utf-8')
print('생성 완료: build/release/restore.sh, build/release/SHA256SUMS')
