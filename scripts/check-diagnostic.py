#!/usr/bin/env python3
"""압축기 차이를 제외하고 내장 소스와 실행 코드가 일치하는지 확인합니다."""
import base64
import gzip
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
source = (root / 'restore_kakaotalk.py').read_bytes()
wrappers = []
for path in (root / 'diagnose.sh', root / 'build/release/diagnose.sh'):
    wrapper = path.read_text(encoding='utf-8')
    match = re.search(r'base64\.b64decode\("""([A-Za-z0-9+/=\n]+)""", validate=False\)', wrapper)
    if match is None or gzip.decompress(base64.b64decode(match[1])) != source:
        raise SystemExit('진단 스크립트의 내장 소스가 현재 소스와 다릅니다.')
    wrappers.append(wrapper[:match.start(1)] + '<PAYLOAD>' + wrapper[match.end(1):])
if wrappers[0] != wrappers[1]:
    raise SystemExit('진단 스크립트의 실행 부분이 생성 결과와 다릅니다.')
print('진단 스크립트의 내장 소스·실행 부분이 일치합니다.')
