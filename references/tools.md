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
python scripts/scan_traces.py <경로>                    # 전 축
python scripts/scan_traces.py <경로> --axes local,coupling
python scripts/scan_traces.py <경로> --format json      # 스크립트에서 소비
python scripts/scan_traces.py <경로> --apply --yes      # 치환 (반출본에서만)
```

종료 코드: 0 = 발견 없음, 1 = 발견 있음, 2 = 실행 오류(디렉터리 아님·알 수 없는 축·`--apply`에 `--yes` 없음·예기치 못한 예외). `&&`로 이어 공개 전환 게이트로 쓴다.

**읽지 못한 파일은 리포트 맨 앞에 따로 나온다**(상한 초과·바이너리 판정·인코딩 미판정). 스캔이 0건이어도 그 목록이 비어 있는지 확인해야 게이트가 참이다.

오탐은 세 방법으로 억제한다. 줄 끝 `sanitize: allow <근거>`, 파일 앞부분 `sanitize: allow-file <근거>`, 그리고 `.sanitize.local.md`의 `## 허용` 절이다. 앞의 둘은 근거가 그 자리에 남고, 셋째는 여러 파일에 흩어진 같은 오탐을 한 번에 처리한다.

`.gitignore`에 걸린 파일과 바이너리는 건너뛴다. `--all`로 무시 목록까지 볼 수 있는데, 정제 대상이 아니어도 "이런 게 여기 있었나"를 확인할 때 쓸모가 있다.

## 축 6. 히스토리

### git-filter-repo

```bash
pip install git-filter-repo
git filter-repo --path <민감파일> --invert-paths --force
git filter-repo --replace-text replacements.txt      # 값 단위 치환
```

실행하면 원격이 자동 제거된다(사고 방지 설계다). 확인 후 직접 되붙이고 강제 push한다. **강제 push는 되돌릴 수 없으므로 사용자 확인을 받는다.**

한계를 분명히 알고 쓴다: fork, 이미 배포된 클론, CI 로그와 아티팩트, 릴리스 자산, issue·PR 본문, 위키에는 닿지 않는다. 저장소를 public으로 뒤집으면 그것들도 함께 공개된다.

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
