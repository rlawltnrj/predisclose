# predisclose (한국어 안내)

**취약점을 제보하기 전에, 이미 공개된 것이 있는지 1분만 확인하세요.**

`predisclose`는 공개 데이터만 사용해 오픈소스 프로젝트에 대해 네 가지를 알려 줍니다.

1. **공개 기록**: 내 발견과 비슷한 공개 권고가 이미 있나요? (OSV, GitHub Advisory Database)
2. **공개 수정**: 내가 시험한 버전 이후 해당 코드가 바뀌었나요?
3. **최근 활동**: 이 영역에 최근 권고가 많았나요? 그런 곳엔 비슷한 제보가 몰립니다.
4. **제보 창구**: 프로젝트가 원하는 제보 경로는 어디인가요? (SECURITY.md, GitHub 비공개 제보, security.txt)

보낸 제보를 기록하는 **로컬 원장**도 있습니다. 마감일을 알려 주고, 포트폴리오용으로 내보낼 때 공개되지 않은 건은 자동으로 가립니다.

## 하지 않는 일

- "새로운 취약점"이라고 판정하지 않습니다. 다른 사람이 비공개로 먼저 낸 제보는 누구도 볼 수 없기 때문입니다.
- 재현, 스캔, 시험을 하지 않습니다. 공개 정보만 읽습니다.
- 제보를 대신 보내거나 어디에 글을 올리지 않습니다.
- 발견 내용 설명은 내 컴퓨터 밖으로 나가지 않습니다. 밖으로 나가는 요청은 `--show-queries`로 모두 볼 수 있습니다.

## 설치와 사용

```bash
pipx install predisclose
export GITHUB_TOKEN=$(gh auth token)   # 선택 사항이지만 권장 (토큰이 없으면 시간당 60회 제한)

predisclose check --pkg pypi:jinja2 --version 2.10 --cwe CWE-693 --file sandbox.py
predisclose route owner/name
predisclose ledger add owner/name "제목" --channel github-pvr
```

자세한 내용은 [README.md](README.md)(영문), [동작 방식](docs/how-it-works.md), [개인정보](docs/privacy.md), [한계](docs/limitations.md)를 보세요.
