# 축별 도구: 설치, 호출, 폴백

이 스킬은 성숙한 기존 도구가 있는 축을 재발명하지 않는다. 축마다 정본 도구가 다르고, 없을 때 무엇으로 대신할지가 여기 있다.

## 축 1. 크리덴셜

### gitleaks (권장)

작업 트리와 **git 히스토리 전체**를 한 번에 본다. 히스토리를 보는 것이 핵심 가치라 다른 도구로 대체하기 어렵다.

```bash
# 설치
winget install gitleaks              # Windows
brew install gitleaks                # macOS

# 히스토리까지 스캔
gitleaks git . --report-format json --report-path "$TMPDIR/gitleaks-report.json"

# 작업 트리만 (git 아닌 폴더에도 됨)
gitleaks dir . --no-banner
```

**리포트를 저장소 안에 쓰지 않는다.** 발견 내역이 담긴 파일이 정제 대상 트리에 생기면 그 자체가 다음 커밋에 딸려 들어갈 후보다.

오탐이 나오면 `.gitleaksignore`에 fingerprint를 등록한다(리포트의 `Fingerprint` 필드를 그대로 붙여넣는다). 파일 전체를 무시하는 대신 발견 단위로 무시하는 편이 안전하다.

### trufflehog (대안)

발견한 크리덴셜이 **실제로 살아 있는지 검증**한다. 이미 폐기된 키인지 아직 유효한지가 대응 우선순위를 가른다.

```bash
trufflehog git file://. --only-verified
```

### 폴백

둘 다 없으면 스캐너의 내장 규칙을 쓴다. AWS·Google·OpenAI·Anthropic·Slack·GitHub 토큰 형식, PEM 개인키 헤더, 일반 `api_key = "..."` 대입을 본다.

```bash
python scripts/scan_traces.py . --axes secret
```

내장 규칙은 **작업 트리만** 본다. 히스토리 축은 이 폴백으로 커버되지 않으므로, 히스토리가 있는 저장소에서는 gitleaks를 설치하거나 SKILL.md 3단계의 "새 저장소 재생성"으로 간다.

## 축 2. 한국어 개인 식별자

### ko-pii (권장)

한국어 PII를 룰 기반으로 잡는다. ML 모델이 필요 없어 오프라인에서 결정적으로 동작하고, 주민등록번호·사업자등록번호·카드번호는 **체크섬을 검증**한다. HWP·HWPX·DOCX·PDF를 직접 입력으로 받는 것이 이 도구의 큰 이점이다.

```bash
pip install ko-pii
pip install "ko-pii[file]"     # HWP/HWPX/DOCX/PDF 직접 입력
```

```bash
# 정제 대상이 문서 파일일 때
ko-pii report.hwpx --mode STRICT --strategy tokenize -o report.anon.md --report report.html

# 디렉터리 일괄
ko-pii ./docs/ --batch --workers 4 --output-dir ./anonymized/
```

```python
from ko_pii import Anonymizer, ProcessingMode

result = Anonymizer(mode=ProcessingMode.STRICT, strategy="tokenize").process(text)
print(result.text)                                # 신청인 <PERSON_1> (<RRN_1>) 연락처 <PHONE_1>
print(result.combined_risk.combined_risk.name)    # CRITICAL
```

`strategy="tokenize"`는 **같은 인물을 같은 토큰으로** 바꾸므로 문서의 문맥이 살아남는다. 정제의 목적이 "삭제가 아니라 일반화"라는 점과 맞는 전략이라 기본값으로 쓴다.

**한글 문서(HWPX·DOCX·PDF)가 저장소에 커밋돼 있으면 반드시 이 축을 돌린다.** 텍스트 스캐너는 압축된 문서 안을 보지 못하는데, 실명이 가장 많이 들어 있는 곳이 바로 그 안이다.

#### 한계 (결과를 반드시 사람이 읽어야 하는 이유)

`PERSON` 검출은 **도메인 의존이 크다.** 제작자 실측으로 행정·서식체 문서에서는 F1 0.79지만, 신문기사체 인명(KLUE-NER)에서는 **0.42**로 떨어진다. 성씨 글자로 시작하는 일반명사·외래어가 사람 이름으로 잡히는 과탐도 같은 원인이다.

정제 작업에서 이 방향의 오차는 **덜 위험한 쪽**이다. 과탐은 사람이 걸러 내면 되지만 미탐은 그대로 공개된다. 다만 산문·기사 인용이 많은 저장소에서는 결과가 길어지니, 그때는 `exclude={"PERSON"}`으로 확정 식별자만 보고 이름은 `.sanitize.local.md`의 리터럴로 잡는 편이 실용적이다.

### 폴백

`.sanitize.local.md`에 적은 리터럴과 정규식으로 스윕한다. 사전이 없으므로 저자가 아는 이름만 잡힌다. 그래서 패턴 파일에 등장인물을 빠짐없이 적는 것이 중요하다.

```bash
python scripts/scan_traces.py . --axes custom   # .sanitize.local.md 가 있어야 한다
```

### 왜 Presidio나 일반 PII 도구가 아닌가

Presidio는 spaCy NER 기반이라 한국어 전용 recognizer가 없다. `PII-Shield`·`noirdoc`·redaction hook 계열은 **LLM이 읽기 전에 컨텍스트에서 가리는** 목적이라 방향이 반대다. 이 스킬의 요구는 디스크에 남아 공개될 산출물에서의 **영구 제거**다.

## 축 3~5. 로컬 흔적·결합·저장소 고유

자작 스캐너가 담당한다. 의존성 없이 Python 3.10+ 표준 라이브러리만 쓴다.

```bash
python scripts/scan_traces.py <경로>                    # 기본 축(선택 축 제외)
python scripts/scan_traces.py <경로> --axes local,coupling
python scripts/scan_traces.py <경로> --axes all,platform  # 선택 축 더하기 (platform-neutral.md)
python scripts/scan_traces.py <경로> --format json      # 스크립트에서 소비
python scripts/scan_traces.py <경로> --apply --yes      # 치환 (반출본에서만)
```

종료 코드: 0 = 발견 없음, 1 = 발견 있음, 2 = 실행 오류(디렉터리 아님·알 수 없는 축·`--apply`에 `--yes` 없음·예기치 못한 예외). `&&`로 이어 공개 전환 게이트로 쓴다.

**읽지 못한 파일은 리포트 맨 앞에 따로 나온다**(상한 초과·바이너리 판정·인코딩 미판정). 스캔이 0건이어도 그 목록이 비어 있는지 확인해야 게이트가 참이다.

오탐은 세 방법으로 억제한다. 줄 끝 `sanitize: allow <근거>`, 파일 앞부분 `sanitize: allow-file <근거>`, 그리고 `.sanitize.local.md`의 `## 허용` 절이다. 앞의 둘은 근거가 그 자리에 남고, 셋째는 여러 파일에 흩어진 같은 오탐을 한 번에 처리한다.

`.gitignore`에 걸린 파일과 바이너리는 건너뛴다. `--all`로 무시 목록까지 볼 수 있는데, 정제 대상이 아니어도 "이런 게 여기 있었나"를 확인할 때 쓸모가 있다.

## 축 6. 히스토리

### history_check.py (판정과 역검증)

같은 명령이 재작성 **전**에는 "재작성이 필요한가"의 판정으로, **후**에는 "재작성이 끝났는가"의 역검증으로 읽힌다.

```bash
python scripts/history_check.py <repo> --local                       # 패턴 파일에서 항목을 읽는다
python scripts/history_check.py <repo> --replace-text <격리폴더>/replace-text.txt --path 'logs/*.log'
python scripts/history_check.py <repo> --local --format json
```

종료 코드: 0 = 전부 0건, 1 = 잔존 있음, 2 = 실행 오류.

**실제 값은 출력하지 않는다.** 입력이 실명·주소가 든 치환표이므로, 결과를 그대로 찍으면 검증 도구 자신이 유출 경로가 된다. 항목은 자리 번호와 가린 형태로만 나오므로 치환표를 옆에 놓고 대조한다. 번호는 주석·빈 줄을 뺀 **항목 순서**라(검증 불가로 빠진 항목도 자리를 지킨다) `--emit-replace-text` 산출물에서는 물리 줄 번호와 그대로 일치한다.

`--local`은 `## 치환` 좌변과 `## 삭제 경로`만 읽는다. `## 탐지` 절은 후보를 넓게 잡는 용도라 정당한 공개 문맥에서도 맞고, 그것이 일상 판정에 상시 걸리면 판정이 꺼진다. 제외한 개수는 출력에 한 줄 남는다.

**되돌릴 수 없는 실행 직전에는 `--with-detect`를 붙인다**(SKILL.md 5단계 게이트). 요구 수준이 다르기 때문이다. 판정은 "재작성이 필요한가"를 묻는 자리라 후보까지 세면 흐려지지만, `&&` 체인의 마지막 항이 `gh repo edit --visibility public`인 자리에서는 "N개를 검사하지 않음"이라는 고지가 찍혀도 사람이 멈출 지점이 없다.

**검증하지 못한 항목은 0건이 아니라 "모름"으로 보고하고 깨끗 판정을 막는다.** 정규식은 층마다 방언이 다르다.

| 층 | 방언 | 함정 |
|---|---|---|
| `git log -S --pickaxe-regex` | POSIX ERE, **바이트 단위** | `\d`·룩어라운드에 오류가 아니라 0건. `--perl-regexp`를 붙여도 무시된다 |
| `git grep` | ERE(`-E`) 또는 고정 문자열(`-F`) | 리터럴에 `-F`를 안 붙이면 주소의 `.`·`(`가 정규식이 된다 |
| 커밋 메시지 | Python `re`, 문자 단위 | 같은 패턴이 여기서는 맞고 위에서는 안 맞는다 |
| `git filter-repo --replace-text` | Python `re`이지만 **바이트로 컴파일** | 치환 자체가 다르게 동작한다 |

**한글이 든 정규식이 가장 위험하다.** 실측(git 2.51): 저장소에 대상 문자열이 있어도 아래는 전부 git에서 0건이다. 바이트를 세므로 한글 한 글자가 3바이트로 갈린다.

| 형태 | 예 | 왜 |
|---|---|---|
| 문자 클래스 안의 비-ASCII | `서울[가-힣]{2,4}중학교` | 클래스가 문자 범위가 아니라 바이트 범위가 된다 |
| `.` | `서울.{2,4}중학교` | `.`는 바이트 하나라 다중바이트 문자를 쪼갠다 |
| **부정 클래스** | `서울[^0-9]{2}중학교` | 부정은 UTF-8 선행·연속 바이트에도 맞는다 |
| **대문자 부정 축약** | `서울\D{2}중학교`·`\S`·`\W` | 같은 기전. `\d`만 막고 `\D`를 놓치는 것이 전형적인 구멍이다 |
| 비-ASCII에 붙은 수량자 | `동{2}` | 마지막 바이트만 반복된다 |

한국어 정제에서 가장 관용적인 패턴 형태가 정확히 이것들이라 스크립트가 전부 검증 불가로 막는다. 한글을 리터럴로만 쓴 `[0-9]{3}동`·`(강동|서초)중학교`는 양쪽에서 같은 뜻이라 통과한다. **대안은 표기 변형마다 리터럴 한 줄이고, 그것이 이 스킬이 권하는 기본형이다.**

`glob:` 줄도 검증 불가로 막는다. filter-repo에서 `glob:`은 경로 글롭이 아니라 **내용** 글롭이라(`glob_to_regex`를 거친다) 경로로 오해하면 실제 치환 대상을 통째로 놓친 채 0건이 나온다.

### 치환표 내보내기

```bash
python scripts/scan_traces.py <repo> --emit-replace-text <격리폴더>/replace-text.txt
```

`.sanitize.local.md`의 `## 치환` 표를 filter-repo의 `원문==>치환` 형식으로 내보낸다. `re:` 항목은 `regex:`로 나가고, 바이트 처리에서 뜻이 달라지는 패턴에는 경고가 붙는다. 실값이 담기므로 **git work tree 안 경로는 거부한다**(스캔 루트가 아니라 `git rev-parse --show-toplevel` 기준이라, 하위 디렉터리에서 `..`로 빠져나가도 막힌다).

### git-filter-repo

```bash
pip install git-filter-repo
git filter-repo --path <민감파일> --invert-paths --force
git filter-repo --replace-text <표> --replace-message <표>     # 파일 내용 + 커밋 메시지
```

`--replace-message`를 함께 쓰는 이유는 커밋 메시지가 독립된 오염원이기 때문이다. 실측에서 한 주소가 파일 35개 커밋과 커밋 메시지 10회에 있었다. `--replace-text`만 쓰면 메시지에 그대로 남는다.

부수 효과: **원격이 자동 제거되고**(사고 방지 설계다) **태그도 재작성되며 reflog가 만료된다.** 되돌릴 수단은 사전에 뜬 번들뿐이다. 확인 후 원격을 직접 되붙이고 강제 push하는데, **강제 push는 되돌릴 수 없으므로 사용자 확인을 받는다.**

한계를 분명히 알고 쓴다: fork, 이미 배포된 클론, CI 로그와 아티팩트, 릴리스 자산, issue·PR 본문, 위키에는 닿지 않는다. 저장소를 public으로 뒤집으면 그것들도 함께 공개된다.

절차 전체(백업 번들 위치, 치환표 두 벌, 실행 명령 기록, 역검증, 재발 방지 층)는 [history-rewrite.md](history-rewrite.md)에 있다.

### 새 저장소 재생성 (더 안전한 기본값)

```bash
cp -r <원본트리> ../<name>-public && rm -rf ../<name>-public/.git
cd ../<name>-public && git init && git add <의도 파일들> && git commit -m "initial public release"
```

옛 저장소는 비공개로 보관한다. 히스토리를 잃는 대신 "빠뜨린 것이 없다"는 확실성을 얻는다. 개인 프로젝트에서 히스토리의 가치는 대개 이 확실성보다 작다.

## 축 7. 릴리스 준비도

`trailofbits/skills@open-sourcing`으로 위임한다. 라이선스 선택·README·SECURITY.md·CI·언어별 패키징을 다룬다.

```bash
npx skills add trailofbits/skills@open-sourcing -g
```

없으면 SKILL.md 4단계의 최소 체크리스트로 대신한다.

## pre-commit 훅 (유형 A의 상시 게이트)

`.git/hooks/pre-commit`:

```sh
#!/bin/sh
SKILL_DIR="${SKILL_DIR:-$HOME/.claude/skills/sanitize-for-release}"  # sanitize: allow 훅 설치 예시
python "$SKILL_DIR/scripts/scan_traces.py" . --staged || {
  echo "정제 스캔에서 발견이 있습니다. 확인 후 커밋하세요 (건너뛰려면 --no-verify)."
  exit 1
}
```

`--staged`는 staged 파일만 본다. 저장소 전체를 매 커밋마다 훑으면 느려서 결국 꺼 버리게 되고, 꺼진 게이트는 없는 게이트다.

치환 대상 좌변이 있는 저장소라면 텍스트 가드를 한 줄 더한다. `.gitignore`는 파일 단위만 막아서 문서 본문에 문장으로 들어오는 텍스트에는 아무 소용이 없다.

```sh
LIST="${SANITIZE_TERMS:-$HOME/<project>-private/terms.txt}"   # sanitize: allow 훅 설치 예시
[ -f "$LIST" ] || { echo "좌변 목록이 없습니다: $LIST"; exit 1; }
if git diff --cached | grep -F -f "$LIST" -q; then
  echo "정제 대상 문자열이 staged 변경에 있습니다."
  exit 1
fi
```

**목록이 없으면 통과가 아니라 차단이다.** 격리 폴더를 옮기거나 다른 머신에서 클론하면 `[ -f ]`만 있는 가드는 아무 말 없이 사라지고, 조용히 사라진 게이트는 없는 게이트다. `grep -F -f`를 `&&`로만 이어 쓰는 형태도 같은 함정이다. 목록 파일이 없으면 grep이 종료 코드 2로 끝나 뒤가 실행되지 않는다.

`terms.txt`는 `replace-text.txt`에서 좌변만 뽑은 것이다(`sed 's/==>.*//' replace-text.txt > terms.txt`. `cut -d'='` 은 좌변에 `=` 가 있으면 잘린다). 목록 파일 자체가 실값이므로 저장소에 두지 않는다.
