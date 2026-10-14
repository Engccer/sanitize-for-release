# sanitize-for-release

개인용으로 만든 저장소를 외부 공개로 전환하기 전에, 개인정보와 개인 흔적을 제거하는 정제 절차를 담은 [Agent Skill](https://github.com/anthropics/skills)입니다.

## 무엇을 해결하나

개인용으로 시작한 것을 공개하는 순간 두 종류의 사고가 열립니다.

- **개인정보 유출**: 실명, 연락처, 주소, 크리덴셜, 소속 기관
- **자기완결성 붕괴**: 저자 컴퓨터에만 존재하는 경로·스킬·계정을 가리켜, 외부 사용자에게는 아무것도 동작하지 않음

기성 도구는 이 중 일부만 봅니다. gitleaks와 trufflehog는 크리덴셜만, PII 도구는 사람 이름만 봅니다. `C:\Users\<name>` 이 README에 박혀 있는 것은 둘 다 놓치지만, 외부 사용자에게는 그 저장소가 동작하지 않는다는 뜻입니다.

이 스킬은 기존 도구가 잘하는 축은 그대로 위임하고, 그 사이에 남는 축을 채웁니다.

## 설치

```bash
npx skills add Engccer/sanitize-for-release -g
```

또는 스킬 디렉터리에 직접 연결합니다.

```bash
ln -s /path/to/sanitize-for-release ~/.claude/skills/sanitize-for-release  # sanitize: allow 설치 예시
```

스캐너는 단독으로도 씁니다. 의존성 없이 Python 3.10+ 표준 라이브러리만 필요합니다.

```bash
python scripts/scan_traces.py <저장소 경로>
```

## 설계

### 저장소 유형을 먼저 가른다

정제 절차는 유형에 따라 완전히 달라지므로 하나의 체크리스트로 뭉개지 않습니다. 판정 질문은 하나입니다: **민감한 것이 이 저장소에서 무엇인가?**

| 답 | 유형 | 절차 |
|---|---|---|
| 사고로 섞인 흔적 | **동일 파일 공개형** | 그 자리에서 제거하고, 이후 편집마다 상시 점검 |
| 정본의 정당한 내용 | **정본/반출본 분리형** | 비공개 정본은 그대로 두고, 치환한 사본만 공개 |
| 코드가 먹는 입력 데이터 | **원본 격리형** | 원본을 저장소 밖으로 옮기고 익명화 fixture만 커밋 |

### 축마다 정본 도구가 다르다

| 축 | 정본 도구 | 이 스킬의 역할 |
|---|---|---|
| 크리덴셜 | `gitleaks` / `trufflehog` | 없을 때의 폴백 규칙 |
| 한국어 실명·주소 | [`ko-pii`](https://github.com/Marker-Inc-Korea/ko-pii) | 체크섬으로 확정되는 형식만 자체 검증 |
| 머신 로컬 흔적 | 없음 | **자체 구현** |
| 개인 도구 결합 | 없음 | **자체 구현** |
| git 히스토리 | `git filter-repo` | **자체 구현** (재작성 필요 판정과 역검증) |
| 플랫폼 종속 (선택 축) | 없음 | **자체 구현** (특정 에이전트 전용 도구 이름 탐지 + 중립 서술 대응표) |
| 릴리스 준비도 | [`trailofbits/skills@open-sourcing`](https://github.com/trailofbits/skills) | 위임 |

### 실제 식별자는 이 저장소에 없다

정제 도구가 실명 예시를 담고 그것을 공개 저장소에 커밋하는 것이 이 영역에서 가장 흔한 자충수입니다. 그래서 패턴은 언제나 **대상 저장소의 gitignored 파일**(`.sanitize.local.md`)에 두고, 스킬은 그 파일을 찾아 읽기만 합니다.

이 저장소 자신도 같은 규칙으로 관리됩니다.

## 스캐너

```bash
python scripts/scan_traces.py .                      # 전 축
python scripts/scan_traces.py . --axes local,coupling
python scripts/scan_traces.py . --format json
python scripts/scan_traces.py . --staged             # pre-commit 훅용
python scripts/scan_traces.py <반출본> --apply --yes  # 치환표 적용
python scripts/scan_traces.py . --emit-replace-text <저장소 밖>/replace-text.txt
```

종료 코드는 발견 0건이면 `0`, 있으면 `1`, 실행 오류면 `2`입니다. 공개 전환 게이트로 그대로 이어 붙일 수 있습니다.

```bash
python scripts/scan_traces.py . && gh repo edit --visibility public
```

### 축

| 축 | 찾는 것 |
|---|---|
| `local` | 사용자 홈 절대경로, 시스템 외 드라이브 문자, 클라우드 드라이브, 사용자 데이터 디렉터리(AppData·Application Support), UNC, 버전 박힌 설치 경로 |
| `coupling` | 에이전트 설정 참조, 저자 개인 지침 파일, 이 컴퓨터에만 설치된 스킬 이름 |
| `pii` | 주민등록번호·사업자등록번호(체크섬 검증), 카드번호(Luhn), 전화번호, 이메일 |
| `secret` | AWS·Google·OpenAI·Anthropic·GitHub·GitLab·Slack·ElevenLabs 토큰, 개인키 블록, JWT, 코드에 대입된 크리덴셜. **리포트에서 값은 가려 출력한다** |
| `custom` | `.sanitize.local.md` 에 적은 패턴 |

체크섬 검증은 형식만 맞는 숫자열을 걸러 냅니다. Luhn은 임의 숫자열의 약 10%를 통과시키므로 카드번호는 줄에 카드 문맥이 있을 때만 봅니다.

읽지 못한 파일(크기 상한 초과, 바이너리 판정, 인코딩 미판정)은 리포트 맨 앞에 따로 나옵니다. 게이트가 참이려면 발견 0건뿐 아니라 이 목록도 비어 있어야 합니다.

`coupling` 축의 로컬 스킬 이름 대조는 **스캔한 컴퓨터의 설치 목록**을 읽으므로 CI에서 재현되지 않습니다. 사람이 편집하는 자리에서의 보조 신호로 쓰고, 게이트의 근거로 삼지 마세요(`--no-skill-scan`으로 끕니다). 사전에 의존하는 이름·주소 탐지는 재구현하지 않고 `ko-pii` 에 맡깁니다.

### 오탐 억제

남기기로 판단한 것은 지우지 말고 근거와 함께 표시합니다.

```python
API_DOC = "https://example.com/G:/legacy"   # sanitize: allow 문서 링크
```

```markdown
~/.claude/skills/my-skill  <!-- sanitize: allow 설치 예시 -->
```

파일 전체를 제외하려면 앞부분 8줄 안에 `sanitize: allow-file <근거>` 를 둡니다. 테스트 픽스처, 샘플 데이터, vendored 코드에 씁니다. 저장소 전체에 걸친 반복 오탐은 `.sanitize.local.md` 의 `## 허용` 절에 모읍니다.

## 히스토리 판정

트리에서 지운 것이 이력에 남아 있는지는 정보의 성질이 아니라 실측으로 가릅니다. 같은 명령이 재작성 **전**에는 "재작성이 필요한가"의 판정으로, **후**에는 "재작성이 끝났는가"의 역검증으로 읽힙니다.

```bash
python scripts/history_check.py <저장소> --local
python scripts/history_check.py <저장소> --replace-text <저장소 밖>/replace-text.txt --path 'logs/*.log'
```

항목마다 파일 내용(`git log -S`)·HEAD 트리(`git grep`)·커밋 메시지 셋을 세고, 지운 경로는 따로 셉니다. 메시지 열이 곧 `--replace-message` 필요 여부입니다. 입력이 실명·주소가 든 치환표이므로 **실제 값은 출력하지 않고** 자리 번호와 가린 형태로만 보고합니다.

검증할 수 없는 항목은 0건이 아니라 **모름**으로 보고하고 깨끗 판정을 막습니다. `git log -S`는 바이트 단위 POSIX ERE라 `서울[가-힣]{2,4}중학교` 같은 패턴에 오류가 아니라 0건을 돌려주는데(실측), 한국어 정제에서 가장 관용적인 패턴 형태가 정확히 이것이라 특별히 막습니다. 대안은 표기 변형마다 리터럴 한 줄이고, 그것이 이 스킬이 권하는 기본형입니다.

절차 전체는 [references/history-rewrite.md](references/history-rewrite.md)에 있습니다.

## 테스트

```bash
python tests/test_rules.py
```

체크섬 검증기(주민등록번호·사업자등록번호·Luhn), 드라이브 문자 오탐 차단, 글롭 폴백과 버전 하드코딩의 구분을 확인합니다.

## 라이선스

MIT
