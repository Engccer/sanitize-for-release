#!/usr/bin/env python3
"""scan_traces 단위·회귀 테스트.   sanitize: allow-file 규칙 픽스처

실행: python tests/test_rules.py   (실패가 하나라도 있으면 종료 코드 1)

여기 등장하는 번호·경로·주소는 전부 합성이며 실재 식별자는 하나도 없다. 그래서
위 파일 단위 억제가 무엇도 가리지 않는다. 식별자처럼 보이는 값을 런타임 체크섬으로
만들어 쓰는 이유가 이것이다. 실재 번호를 소스에 박고 억제로 덮으면, 정제 도구가
스스로 유출원이 되면서 동시에 자기 게이트에 사각지대를 만든다.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "scripts" / "scan_traces.py"

spec = importlib.util.spec_from_file_location("scan_traces", SCANNER)
m = importlib.util.module_from_spec(spec)
sys.modules["scan_traces"] = m
spec.loader.exec_module(m)

FAILED: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    if not ok:
        FAILED.append(label)
    print(f"  [{'OK ' if ok else 'FAIL'}] {label}" + ("" if ok else f"  got={got!r} want={want!r}"))


# --------------------------------------------------------------------------
# 합성 식별자 생성 (실재 번호를 쓰지 않기 위해)
# --------------------------------------------------------------------------

def make_rrn() -> str:
    body = "900101" + "1" + "23456"
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    s = sum(int(a) * b for a, b in zip(body, w))
    return body + str((11 - s % 11) % 10)


def make_bizno() -> str:
    body = "000000000"
    w = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(int(a) * b for a, b in zip(body, w)) + (int(body[8]) * 5) // 10
    return body + str((10 - s % 10) % 10)


def make_card() -> str:
    body = "400000000000000"
    total, alt = 0, True
    for ch in reversed(body):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
        alt = not alt
    return body + str((10 - total % 10) % 10)


RRN, BIZNO, CARD = make_rrn(), make_bizno(), make_card()

rules = m.builtin_rules()
by_name = {r.name: r for r in rules}


def hits(rule, text: str) -> list[str]:
    r = by_name[rule]
    if r.line_require and not r.line_require.search(text):
        return []
    if r.line_veto and r.line_veto.search(text):
        return []
    return [x.group(0) for x in r.pattern.finditer(text)
            if not r.validator or m.VALIDATORS[r.validator](x.group(0))]


print(f"규칙 {len(rules)}개 컴파일")

print("\n체크섬 검증기")
check("RRN 유효값 통과", m.valid_rrn(RRN), True)
check("RRN 체크섬 불일치 차단", m.valid_rrn(RRN[:12] + str((int(RRN[12]) + 1) % 10)), False)
check("RRN 임의 숫자열 차단", m.valid_rrn("123456-7890123"), False)
check("사업자번호 유효값 통과", m.valid_bizno(BIZNO), True)
check("사업자번호 임의값 차단", m.valid_bizno("123-45-67890"), False)
check("카드 Luhn 통과", m.valid_luhn(CARD), True)
check("카드 임의값 차단", m.valid_luhn("1234567890123456"), False)
check("예시 도메인 이메일 제외", m.valid_email("a@example.com"), False)
check("실도메인 이메일 탐지", m.valid_email("someone@nonexistent-fixture.invalid"), True)
check("하드코딩 경로 탐지", m.not_glob("C:/Tools/jdk-21.0.1/bin"), True)
check("글롭 폴백 제외", m.not_glob("C:/Program Files/X/jdk-21*"), False)
check("플레이스홀더 제외", m.not_placeholder("your-api-key-here"), False)

print("\n경로 규칙")
check("정규식 문자클래스는 드라이브가 아니다",
      hits("non-system-drive", r'RE = re.compile(r"^\s*\|?[\s:\-|]+\|?\s*$")'), [])
check("실제 드라이브 경로 탐지", bool(hits("non-system-drive", r'p = "G:\내 드라이브\x"')), True)
check("드라이브 경로가 unix-user-home 으로 이중 계상되지 않음",
      hits("unix-user-home", "path = C:/Users/someone/proj"), [])
check("글롭 폴백 사슬 제외",
      hits("program-files-abs", r'for /d %%D in ("C:\Program Files\E A\jdk-21*") do'), [])
check("버전 하드코딩 탐지",
      bool(hits("program-files-abs", r'J="C:\Program Files\E A\jdk-21.0.10\bin\java.exe"')), True)

print("\n결합 규칙 (S9 회귀: ~ 이외의 홈 표기)")
for spelling in ("~", "$HOME", "${HOME}", "%USERPROFILE%"):
    check(f"에이전트 설정 참조 탐지 [{spelling}]",
          bool(hits("agent-config-home", f'{spelling}/.claude/skills/x/y.py')), True)
check("스킬 경로 참조 탐지 [$HOME]",
      bool(hits("agent-skills-path", '"$HOME/.claude/skills/foo/bar.py"')), True)

print("\n카드 문맥 (오탐 억제)")
check("문맥 없는 숫자열은 카드로 보지 않음", hits("credit-card", f"order_id = {CARD}"), [])
check("카드 문맥이 있으면 탐지", bool(hits("credit-card", f"card_number = {CARD}")), True)

print("\n크리덴셜 리댁션")
key = "AKIA" + "A" * 16
check("리포트에 원문이 그대로 남지 않음", key in m.redact(key), False)
check("리댁션이 길이는 알려 줌", str(len(key)) in m.redact(key), True)


# --------------------------------------------------------------------------
# 통합 회귀: 실제 파일 트리에 스캐너를 돌린다
# --------------------------------------------------------------------------

def run_scanner(cwd: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, str(SCANNER), *args],
        cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout, proc.stderr


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t.invalid",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t.invalid"})


print("\n통합 회귀")
with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"
    (repo / "sub").mkdir(parents=True)
    git(repo, "init", "-q")

    # B2: 비ASCII 파일명이 스캔에서 빠지지 않는가
    (repo / "한글파일.md").write_text("path = C:\\Users\\someone\\x", encoding="utf-8")
    (repo / "ascii.md").write_text("path = C:\\Users\\someone\\y", encoding="utf-8")
    code, out, _ = run_scanner(repo, ".", "--axes", "local", "--no-skill-scan")
    check("B2 한글 파일명도 스캔된다", "한글파일.md" in out, True)
    check("B2 발견 시 종료 코드 1", code, 1)

    # B3: 하위 디렉터리에서 --staged 가 조용히 통과하지 않는가
    (repo / "sub" / "s.md").write_text("path = C:\\Users\\someone\\z", encoding="utf-8")
    git(repo, "add", "-A")
    code, out, _ = run_scanner(repo / "sub", ".", "--staged", "--axes", "local", "--no-skill-scan")
    check("B3 하위 디렉터리 --staged 가 파일을 본다", "s.md" in out, True)
    check("B3 발견 시 종료 코드 1", code, 1)

    # S6: --all 과 --staged 동시 지정은 오류
    code, _, err = run_scanner(repo, ".", "--all", "--staged")
    check("S6 --all 과 --staged 는 배타", code, 2)

    # S1: 읽지 못한 파일을 보고하는가
    big = repo / "big.log"
    big.write_text("x" * (m.MAX_BYTES + 10), encoding="utf-8")
    code, out, _ = run_scanner(repo, ".", "--axes", "local", "--no-skill-scan", "--all")
    check("S1 상한 초과 파일을 보고", "big.log" in out and "보지 못한" in out, True)

with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "export"
    repo.mkdir(parents=True)
    (repo / ".sanitize.local.md").write_text(
        "repo_type: export\n\n"
        "## 치환\n\n"
        "설명 산문은 규칙이 아니다.\n"
        "| 패턴 | 대체 |\n|---|---|\n"
        "| OLDROOT | C:\\Users\\generic\\proj |\n"
        "| 이름자리 | ○○담당관 |\n\n"
        "## 허용\n\n"
        "이 절에 적힌 산문은 허용 규칙이 아니다.\n"
        "- path:keepme.md\n",
        encoding="utf-8")
    # S2: 역슬래시가 든 대체값
    (repo / "a.md").write_text("root = OLDROOT\r\nname = 이름자리\r\n", encoding="utf-8",
                               newline="")
    # B4: cp949 파일이 인코딩·줄바꿈을 유지하는가
    (repo / "cp949.txt").write_bytes("이름자리 한글\r\n".encode("cp949"))
    # B5: 억제 표시가 치환에서도 존중되는가
    (repo / "fixture.md").write_text("sanitize: allow-file 픽스처\n이름자리\n", encoding="utf-8")
    (repo / "inline.md").write_text("이름자리 <!-- sanitize: allow 근거 -->\n", encoding="utf-8")
    (repo / "keepme.md").write_text("이름자리\n", encoding="utf-8")

    before_a = (repo / "a.md").read_bytes()
    code, out, err = run_scanner(repo, ".", "--axes", "custom", "--apply", "--yes")
    after_a = (repo / "a.md").read_bytes()

    check("S2 역슬래시 대체값이 크래시하지 않음", "Traceback" not in err, True)
    check("S2 대체값이 리터럴로 들어감", b"C:\\Users\\generic\\proj" in after_a, True)
    check("B4 CRLF 가 증식하지 않음", b"\r\r\n" not in after_a, True)
    check("B4 CRLF 가 보존됨", after_a.count(b"\r\n"), before_a.count(b"\r\n"))
    check("B4 cp949 인코딩 유지",
          (repo / "cp949.txt").read_bytes().decode("cp949").startswith("○○담당관"), True)
    check("B5 allow-file 파일은 치환하지 않음",
          "이름자리" in (repo / "fixture.md").read_text(encoding="utf-8"), True)
    check("B5 inline allow 줄은 치환하지 않음",
          "이름자리" in (repo / "inline.md").read_text(encoding="utf-8"), True)
    check("B5 path 허용 파일은 치환하지 않음",
          "이름자리" in (repo / "keepme.md").read_text(encoding="utf-8"), True)
    check("S3 산문이 치환 규칙으로 승격되지 않음", "치환 2" in out, True)
    check("S3 산문이 허용 규칙으로 승격되지 않음", "허용 1" in out, True)

    # S5: --apply 와 --format json 을 함께 써도 JSON 이 유효한가
    code, out, _ = run_scanner(repo, ".", "--axes", "custom", "--apply", "--yes", "--format", "json")
    import json
    try:
        json.loads(out)
        ok = True
    except ValueError:
        ok = False
    check("S5 --apply --format json 이 유효한 JSON", ok, True)

# 종료 코드 계약
with tempfile.TemporaryDirectory() as td:
    clean = Path(td) / "clean"
    clean.mkdir()
    (clean / "ok.md").write_text("nothing here\n", encoding="utf-8")
    check("계약 깨끗하면 0", run_scanner(clean, ".", "--no-skill-scan")[0], 0)
    check("계약 없는 디렉터리는 2", run_scanner(clean, "no-such-dir")[0], 2)
    check("계약 알 수 없는 축은 2", run_scanner(clean, ".", "--axes", "nope")[0], 2)
    check("계약 --apply 에 --yes 없으면 2",
          run_scanner(clean, ".", "--axes", "custom", "--apply")[0], 2)

print(f"\n{'실패 %d건: %s' % (len(FAILED), ', '.join(FAILED)) if FAILED else '전부 통과'}")
sys.exit(1 if FAILED else 0)
