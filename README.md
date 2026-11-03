<div align="center">

# NoAdKakaoMac Restore

NoAdKakaoMac의 전체 원본 백업으로 카카오톡을 공식 앱으로 되돌립니다.

[다운로드](https://github.com/abruption/NoAdKakaoMac-Restore/releases/tag/v0.1.0-rc.1) · [사용법](docs/사용법.md)

</div>

macOS와 Python 3.9 이상이 필요합니다. NoAdKakaoMac RC1~RC3에서 만든 `manifest.json`과 `original.app`이 있는 정상 백업을 사용합니다. 카카오톡 버전 목록을 두지 않지만, 백업 없이 복원하는 도구는 아닙니다.

1. 터미널에서 복원 스크립트와 확인용 파일을 내려받습니다.

```sh
curl -fLO https://github.com/abruption/NoAdKakaoMac-Restore/releases/download/v0.1.0-rc.1/restore.sh
curl -fLO https://github.com/abruption/NoAdKakaoMac-Restore/releases/download/v0.1.0-rc.1/SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

2. `restore.sh: OK`를 확인합니다. 실패하면 실행하지 말고 다시 내려받습니다.
3. 카카오톡을 완전히 종료한 뒤 상태를 확인하고 복원합니다.

```sh
sh restore.sh status
sh restore.sh restore
```

권한이 부족하다는 오류가 나면 해당 명령 앞에 `sudo`를 붙여 다시 실행합니다(예: `sudo sh restore.sh restore`). 백업을 찾지 못하거나 여러 개라면 [백업 폴더 지정 방법](docs/사용법.md)을 확인하세요.

이미 공식 앱이면 그대로 둡니다. 기록과 다른 앱이나 기존 작업의 중단 파일이 있으면 덮어쓰지 않습니다. 복원 전 앱과 원본 백업은 보존하며 자동으로 삭제하지 않습니다.

원본 백업이 없다면 카카오톡을 공식 배포처에서 다시 설치하세요. 대화 자료나 사용자 데이터 폴더를 삭제하지 마세요.

이 저장소에는 광고 제거 기능과 카카오톡 앱 파일이 포함되어 있지 않습니다. [MIT 라이선스](LICENSE) · [재사용 고지](NOTICE)
