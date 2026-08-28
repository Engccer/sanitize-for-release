#!/usr/bin/env python3
"""공개 전환 정제 스캐너.

저장소를 외부 공개로 전환하기 전에, 기성 도구가 놓치는 축을 훑는다.

  local    머신 로컬 흔적 (사용자 홈, 드라이브 문자, 클라우드 드라이브, 버전 박힌 절대경로)
  coupling 개인 도구 결합 (이 컴퓨터에만 있는 스킬·설정 참조)
  pii      형식으로 확정 가능한 개인 식별자 (주민번호·사업자번호는 체크섬 검증)
  secret   크리덴셜 (gitleaks가 없을 때의 폴백. 작업 트리만 본다)
  custom   대상 저장소의 .sanitize.local.md 에 적힌 패턴

이름·주소 같은 사전 의존 탐지는 ko-pii 에 맡긴다. 여기서는 체크섬이나
형식만으로 확정되는 것, 그리고 기성 도구의 관심 밖에 있는 것만 다룬다.

이 스캐너가 게이트로 쓰이므로(`scan_traces.py . && gh repo edit --visibility public`)
"조용히 건너뛰고 0을 반환하는 것"이 가장 위험한 실패다. 읽지 못한 파일은 반드시
보고하고, 스캔 범위를 좁히는 선택은 전부 눈에 보이게 만든다.

의존성 없음 (Python 3.10+ 표준 라이브러리).
종료 코드: 0 발견 없음 / 1 발견 있음 / 2 실행 오류
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

LOCAL_FILE = ".sanitize.local.md"
MAX_BYTES = 2 * 1024 * 1024
MAX_LINE = 4000
CONTEXT_CHARS = 160

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", ".turbo", "target", "vendor", ".gradle", ".idea",
}
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".svgz",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".tar", ".rar", ".jar", ".war",
    ".mp3", ".mp4", ".wav", ".m4a", ".mov", ".avi", ".mkv", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyd", ".class",
    ".hwp", ".hwpx", ".docx", ".xlsx", ".pptx", ".odt",  # 압축 문서: ko-pii[file] 담당
    ".db", ".sqlite", ".sqlite3", ".lock",
}

# 남기기로 판단한 것을 그 자리에 표시한다. 문구 뒤는 자유 서술이라 근거를 함께 적을 수 있다.
#   sanitize: allow <근거>       그 줄만
#   sanitize: allow-file <근거>  파일 전체 (테스트 픽스처·샘플 데이터·vendored 코드)
INLINE_ALLOW = re.compile(r"sanitize:\s*allow(?!-file)\b")
FILE_ALLOW = re.compile(r"sanitize:\s*allow-file\b")
FILE_ALLOW_HEAD_LINES = 8

PLACEHOLDER_HINT = re.compile(
    r"(?i)(your[-_ ]?|example|dummy|sample|placeholder|changeme|redacted|xxxx"
    r"|\.\.\.|\*\*\*|<[a-z_ -]+>|\$\{|process\.env|os\.environ|getenv)"
)


@dataclass
class Rule:
    axis: str
    name: str
    pattern: re.Pattern
    note: str = ""
    validator: str = ""
    # 줄 전체를 보고 거르는 문맥 조건. 매치 문자열만으로는 가를 수 없는 오탐에 쓴다.
    line_veto: re.Pattern | None = None
    line_require: re.Pattern | None = None
    redact: bool = False


@dataclass
class Finding:
    path: str
    line: int
    axis: str
    rule: str
    match: str
    context: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.path, "line": self.line, "axis": self.axis,
            "rule": self.rule, "match": self.match,
            "context": self.context, "note": self.note,
        }


@dataclass
class Skipped:
    path: str
    reason: str


def redact(text: str) -> str:
    """크리덴셜을 리포트·로그·터미널 스크롤백에 그대로 남기지 않는다.

    발견 사실과 위치만으로 조치는 충분하고, 값을 찍으면 게이트가 유출 경로가 된다.
    """
    text = text.strip()
    keep = min(4, max(0, len(text) - 4))
    return f"{text[:keep]}…[{len(text)}자]"


# --------------------------------------------------------------------------
# 내장 규칙
# --------------------------------------------------------------------------

HTTP_CONTEXT = re.compile(
    r"(?i)\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP|endpoint|route|router"
    r"|api|url|uri|href|fetch|curl)\b|https?://")
CARD_CONTEXT = re.compile(
    r"(?i)card|카드|결제|payment|visa|master|amex|pan\b|계좌|번호")

# Windows 경로는 내부 공백이 흔하다(Program Files, Eclipse Adoptium). 공백에서 잘리면
# 뒤에 붙은 글롭을 못 보고 폴백 사슬을 하드코딩으로 오판한다. 공백 뒤에 경로 문자가
# 이어질 때만 계속 먹는다.
PATH_TAIL = r"(?:[^\s\"'`<>|,;)]|[ ](?=[^\s\"'`<>|,;)]))"
# 홈 디렉터리를 가리키는 표기는 셸·OS마다 다르다. 한 형태만 잡으면 나머지가 샌다.
HOME_PREFIX = r"(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%)"


def builtin_rules() -> list[Rule]:
    r: list[Rule] = []

    def add(*a, **k):
        r.append(Rule(*a, **k))

    # --- local: 저자 컴퓨터에만 존재하는 경로 ---------------------------------
    add("local", "windows-user-home",
        re.compile(r"[A-Za-z]:[\\/]Users[\\/](?!\s)[A-Za-z0-9._-]+"),
        "사용자 홈 절대경로. 인자나 환경변수로 받게 한다")
    add("local", "unix-user-home",
        re.compile(r"(?<![\w.:])/(?:Users|home)/(?!runner\b|user\b|<)[a-z][a-z0-9._-]{1,31}"),
        "사용자 홈 절대경로. ~ 또는 $HOME 으로 바꾼다")
    add("local", "non-system-drive",
        re.compile(r"(?<![\w:\\])[D-Zd-z]:[\\/](?![\\/])"),
        "시스템 외 드라이브 문자. 저자 컴퓨터의 마운트에만 존재한다")
    add("local", "cloud-drive",
        re.compile(r"내\s?드라이브|공유\s?드라이브|My\s?Drive|Google\s?Drive|OneDrive|iCloud\s?Drive|Dropbox[\\/]"),  # sanitize: allow 규칙 정의 자신
        "클라우드 드라이브 경로")
    add("local", "user-data-dir",
        re.compile(r"AppData[\\/](?:Local|Roaming|LocalLow)|Library[\\/]Application\s?Support"),
        "사용자별 데이터 디렉터리")
    add("local", "unc-path",
        re.compile(r"\\\\[A-Za-z0-9._-]{2,}\\[A-Za-z0-9._$-]+"),
        "UNC 네트워크 경로")
    add("local", "versioned-abs-path",
        re.compile(rf"[A-Za-z]:[\\/]{PATH_TAIL}*?(?:jdk|jre|python|node|ruby|go)[-_]?\d+{PATH_TAIL}*",
                   re.IGNORECASE),
        "버전이 박힌 절대경로. 환경변수 > 글롭 > PATH 폴백으로 바꾼다", validator="not_glob")
    add("local", "program-files-abs",
        re.compile(rf"[A-Za-z]:[\\/]Program\s?Files(?:\s?\(x86\))?[\\/]{PATH_TAIL}+"),
        "설치 경로 하드코딩", validator="not_glob")

    # --- coupling: 이 컴퓨터의 개인 에이전트 설정 -----------------------------
    add("coupling", "agent-config-home",
        re.compile(rf"{HOME_PREFIX}[\\/]\.(?:claude|codex|gemini|agents|cursor|aider)\b[^\s\"'`)]*"),
        "저자 에이전트 설정 참조. 외부 사용자에게는 존재하지 않는다")
    add("coupling", "global-instruction-file",
        re.compile(rf"(?:글로벌|전역|global|user-level)\s*(?:CLAUDE|AGENTS|GEMINI)\.md"
                   rf"|{HOME_PREFIX}[\\/]\.claude[\\/](?:CLAUDE|AGENTS)\.md"),
        "저자 개인 지침 파일 참조. 호출 인자로 일반화한다")
    add("coupling", "agent-skills-path",
        re.compile(rf"(?:{HOME_PREFIX}[\\/])?\.(?:claude|agents)[\\/]skills[\\/][A-Za-z0-9._-]+"),
        "스킬 디렉터리 참조. README 설치 예시라면 허용에 등록한다")

    # --- pii: 형식·체크섬으로 확정되는 식별자 --------------------------------
    add("pii", "kr-rrn", re.compile(r"\b\d{6}[-\s]?[1-8]\d{6}\b"),
        "주민등록번호 형식 (체크섬 통과)", validator="rrn")
    add("pii", "kr-biz-no", re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{5}\b"),
        "사업자등록번호 형식 (체크섬 통과)", validator="bizno")
    add("pii", "kr-mobile", re.compile(r"\b01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}\b"),
        "휴대전화번호")
    add("pii", "kr-landline", re.compile(r"\b0(?:2|[3-6][1-5])[-\s.]\d{3,4}[-\s.]\d{4}\b"),
        "유선전화번호")
    add("pii", "email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "이메일 주소. 저자 공개 연락처면 허용에 등록한다", validator="email")
    # Luhn 은 임의 숫자열의 약 10%를 통과시킨다. 주문번호·통계 열이 많은 저장소에서
    # 그대로 두면 오탐이 쏟아지므로 줄에 카드 문맥이 있을 때만 본다.
    add("pii", "credit-card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        "카드번호 형식 (Luhn 통과 + 줄에 카드 문맥)", validator="luhn",
        line_require=CARD_CONTEXT)

    # --- secret: gitleaks 폴백 ----------------------------------------------
    for name, pat, note in [
        ("aws-access-key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b", "AWS 액세스 키"),
        ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API 키"),
        ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{24,}", "Anthropic API 키"),
        ("openai-key", r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{24,}", "OpenAI API 키"),
        ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", "GitHub 토큰"),
        ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", "GitLab 토큰"),
        ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack 토큰"),
        ("elevenlabs-key", r"\bsk_[a-f0-9]{40,}\b", "ElevenLabs API 키"),
        ("private-key-block", r"-----BEGIN(?:\s+[A-Z]+)*\s+PRIVATE KEY-----", "개인키 블록"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    ]:
        add("secret", name, re.compile(pat), note, redact=True)
    add("secret", "assigned-secret",
        re.compile(r"""(?ix)\b(?:api[_-]?key|secret[_-]?key|secret|token|password|passwd|
                       access[_-]?key|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*
                       (['"])([^'"\s]{12,})\1"""),
        "코드에 대입된 크리덴셜", validator="not_placeholder", redact=True)
    return r


# --------------------------------------------------------------------------
# 검증기: 형식만 맞는 숫자열을 걸러 낸다
# --------------------------------------------------------------------------

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def valid_rrn(text: str) -> bool:
    d = _digits(text)
    if len(d) != 13:
        return False
    mm, dd = int(d[2:4]), int(d[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(a) * b for a, b in zip(d[:12], weights))
    return (11 - total % 11) % 10 == int(d[12])


def valid_bizno(text: str) -> bool:
    d = _digits(text)
    if len(d) != 10:
        return False
    weights = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    total = sum(int(a) * b for a, b in zip(d[:9], weights))
    total += (int(d[8]) * 5) // 10
    return (10 - total % 10) % 10 == int(d[9])


def valid_luhn(text: str) -> bool:
    d = _digits(text)
    if not 13 <= len(d) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def valid_email(text: str) -> bool:
    # 문서에 흔한 비실존 도메인은 개인정보가 아니다
    return not re.search(
        r"(?i)@(?:example|test|localhost|domain|email|mail)\.(?:com|org|net|kr)$", text)


def not_placeholder(text: str) -> bool:
    return not PLACEHOLDER_HINT.search(text)


def not_glob(text: str) -> bool:
    """글롭이 든 경로는 하드코딩이 아니라 탐색 패턴이다(권장 폴백 사슬의 일부)."""
    return "*" not in text and "?" not in text


VALIDATORS = {
    "rrn": valid_rrn, "bizno": valid_bizno, "luhn": valid_luhn,
    "email": valid_email, "not_placeholder": not_placeholder, "not_glob": not_glob,
}


# --------------------------------------------------------------------------
# .sanitize.local.md 파싱
# --------------------------------------------------------------------------

@dataclass
class LocalConfig:
    repo_type: str = ""
    replacements: list[tuple[re.Pattern, str, str]] = field(default_factory=list)
    detects: list[tuple[re.Pattern, str]] = field(default_factory=list)
    allow_literals: list[str] = field(default_factory=list)
    allow_regexes: list[re.Pattern] = field(default_factory=list)
    allow_paths: list[str] = field(default_factory=list)
    found: bool = False


SECTION_ALIASES = {
    "치환": "replace", "replace": "replace", "replacements": "replace",
    "탐지": "detect", "detect": "detect", "patterns": "detect",
    "허용": "allow", "allow": "allow", "allowlist": "allow", "ignore": "allow",
}


def _compile(raw: str, label: str) -> re.Pattern | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        if raw.startswith("re:"):
            return re.compile(raw[3:].strip())
        return re.compile(re.escape(raw))
    except re.error as exc:
        print(f"경고: {label} 의 정규식을 건너뜁니다 ({raw}): {exc}", file=sys.stderr)
        return None


def load_local_config(root: Path) -> LocalConfig:
    """패턴 파일을 읽는다.

    설명 산문이 규칙으로 승격되면 엉뚱한 것을 지우거나(치환) 진짜 발견을 덮어 버린다
    (허용은 그 줄 전체를 침묵시킨다). 그래서 목록 항목과 표 행만 규칙으로 받고,
    나머지 줄은 전부 설명으로 취급해 버린다.
    """
    cfg = LocalConfig()
    path = root / LOCAL_FILE
    if not path.is_file():
        return cfg
    cfg.found = True
    source = read_source(path)
    section = ""
    for raw_line in (source.text if source else "").split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            section = SECTION_ALIASES.get(line.lstrip("#").strip().lower(), "")
            continue
        m = re.match(r"^repo[_ ]?type\s*[:=]\s*(\w+)", line, re.IGNORECASE)
        if m:
            cfg.repo_type = m.group(1).lower()
            continue
        # 주석은 설명이지 규칙이 아니다
        line = re.sub(r"<!--.*?-->", "", line).strip()
        if not line or line.startswith("<!--") or line.startswith("-->"):
            continue
        if section == "replace":
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 2 or set(cells[0]) <= set("-: ") or not cells[0]:
                continue
            if cells[0].lower() in ("패턴", "pattern", "from"):
                continue
            if not cells[1]:
                print(f"경고: 치환 대체값이 비어 있어 건너뜁니다 ({cells[0]}). "
                      f"삭제가 필요하면 대체값을 명시하세요.", file=sys.stderr)
                continue
            pat = _compile(cells[0], "치환")
            if pat:
                cfg.replacements.append((pat, cells[1], cells[0]))
        elif section in ("detect", "allow"):
            m = re.match(r"^[-*+]\s+(.+)$", line)
            if not m:                       # 산문은 규칙이 아니다
                continue
            item = m.group(1).strip()
            if not item:
                continue
            if section == "detect":
                pat = _compile(item, "탐지")
                if pat:
                    cfg.detects.append((pat, item))
            elif item.startswith("path:"):
                cfg.allow_paths.append(item[5:].strip().replace("\\", "/"))
            elif item.startswith("re:"):
                pat = _compile(item, "허용")
                if pat:
                    cfg.allow_regexes.append(pat)
            else:
                cfg.allow_literals.append(item)
    return cfg


# --------------------------------------------------------------------------
# 로컬 스킬 목록 (coupling 축 보강)
# --------------------------------------------------------------------------

def local_skill_names(skills_root: Path | None) -> list[str]:
    roots = [skills_root] if skills_root else [
        Path.home() / ".claude" / "skills",
        Path.home() / ".agents" / "skills",
    ]
    names: set[str] = set()
    for root in roots:
        if root and root.is_dir():
            try:
                names.update(p.name for p in root.iterdir()
                             if p.is_dir() and not p.name.startswith("."))
            except OSError as exc:
                print(f"경고: 스킬 목록을 읽지 못했습니다 ({root}): {exc}", file=sys.stderr)
        elif skills_root is not None:
            print(f"경고: --skills-root 가 디렉터리가 아닙니다 ({root}). "
                  f"로컬 스킬 참조 검사를 건너뜁니다.", file=sys.stderr)
    return sorted(names)


def skill_reference_rules(names: list[str], own: set[str]) -> list[Rule]:
    """설치된 스킬 이름이 문서에 등장하는지 본다.

    결과가 스캔한 머신에 의존한다는 것이 이 규칙의 한계다. CI에서 재현되지 않으므로
    게이트의 근거로 삼지 말고, 사람이 편집하는 자리에서의 보조 신호로 쓴다.
    """
    targets = [n for n in names if n not in own and len(n) >= 4]
    if not targets:
        return []
    alt = "|".join(re.escape(n) for n in sorted(targets, key=len, reverse=True))
    return [
        Rule("coupling", "local-skill-path",
             re.compile(rf"(?<![\w-])skills[\\/](?:{alt})(?![\w-])"),
             "이 컴퓨터에 설치된 스킬의 디렉터리 참조"),
        Rule("coupling", "local-skill-command",
             re.compile(rf"(?<![\w./-])/(?:{alt})(?![\w-])"),
             "슬래시 명령으로 보이는 개인 스킬 참조. URL 경로면 허용에 등록한다",
             line_veto=HTTP_CONTEXT),
    ]


def own_skill_names(root: Path) -> set[str]:
    """대상 저장소가 스스로 정의하는 스킬 이름은 결합이 아니다."""
    names = {root.name}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "SKILL.md" in filenames:
            names.add(Path(dirpath).name)
    return names


# --------------------------------------------------------------------------
# 파일 수집과 읽기
# --------------------------------------------------------------------------

def _run_git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                             timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", errors="replace")


def git_files(root: Path, staged: bool) -> list[Path] | None:
    """git 이 아는 파일 목록.

    `-z` 를 쓰는 이유는 기본 출력이 비ASCII 경로를 C 인용(`"\\355\\225\\234..."`)으로
    이스케이프해 내보내기 때문이다. 그 문자열을 그대로 경로로 쓰면 파일이 존재하지
    않는 것으로 판정돼 한글 파일명이 통째로 스캔에서 빠진다.

    `--relative` 를 쓰는 이유는 `diff --cached` 가 저장소 루트 기준 경로를 내보내
    (`ls-files` 와 달리) 하위 디렉터리에서 실행하면 전부 빗나가기 때문이다.
    """
    args = (["diff", "--cached", "--name-only", "--relative", "-z", "--diff-filter=ACMR"]
            if staged else ["ls-files", "-co", "--exclude-standard", "-z"])
    out = _run_git(args, root)
    if out is None:
        return None
    return [root / name for name in out.split("\0") if name]


def walk_files(root: Path) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
        for name in filenames:
            out.append(Path(dirpath) / name)
    return out


def collect_files(root: Path, staged: bool, include_ignored: bool
                  ) -> tuple[list[Path], list[Skipped]]:
    skipped: list[Skipped] = []
    files = None
    if not include_ignored:
        files = git_files(root, staged)
        if files is None:
            print("경고: git 목록을 가져오지 못해 디렉터리를 직접 훑습니다. "
                  ".gitignore 가 반영되지 않습니다.", file=sys.stderr)
    if files is None:
        files = walk_files(root)

    keep = []
    for p in files:
        rel = p.name
        try:
            rel = p.relative_to(root).as_posix()
        except ValueError:
            pass
        if not p.is_file():
            continue
        if p.name == LOCAL_FILE:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            size = p.stat().st_size
        except OSError as exc:
            skipped.append(Skipped(rel, f"읽기 실패: {exc}"))
            continue
        if size > MAX_BYTES:
            skipped.append(Skipped(rel, f"{size // 1024}KB, 상한 {MAX_BYTES // 1024}KB 초과"))
            continue
        keep.append(p)
    return keep, skipped


@dataclass
class Source:
    text: str
    encoding: str
    lossy: bool


BOMS = [(b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be")]


def read_source(path: Path) -> Source | None:
    """텍스트로 읽고 원래 인코딩을 함께 돌려준다.

    인코딩을 기억하는 이유는 --apply 가 같은 인코딩으로 되써야 하기 때문이다.
    cp949 파일을 utf-8 로 되쓰면 그 파일을 읽는 .bat·.csv 소비자가 깨진다.
    되돌릴 수 없이 깨진 디코딩(lossy)은 표시해 두고 쓰기 대상에서 제외한다.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if not data:
        return Source("", "utf-8", False)
    for bom, enc in BOMS:
        if data.startswith(bom):
            try:
                return Source(data.decode(enc), enc, False)
            except UnicodeDecodeError:
                return None
    if b"\x00" in data[:8192]:
        # BOM 없는 UTF-16 (PowerShell 리다이렉션의 기본 출력)
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                text = data.decode(enc)
            except UnicodeDecodeError:
                continue
            if "\x00" not in text[:4096]:
                return Source(text, enc, False)
        return None                                     # 진짜 바이너리
    for enc in ("utf-8", "cp949", "euc-kr"):
        try:
            return Source(data.decode(enc), enc, False)
        except UnicodeDecodeError:
            continue
    return Source(data.decode("utf-8", errors="replace"), "utf-8", True)


# --------------------------------------------------------------------------
# 스캔
# --------------------------------------------------------------------------

def is_allowed(cfg: LocalConfig, rel: str, line_text: str) -> bool:
    for allowed in cfg.allow_paths:
        if rel == allowed or rel.startswith(allowed.rstrip("/") + "/"):
            return True
    if any(literal in line_text for literal in cfg.allow_literals):
        return True
    return any(pat.search(line_text) for pat in cfg.allow_regexes)


def file_allowed(lines: list[str]) -> bool:
    return any(FILE_ALLOW.search(ln) for ln in lines[:FILE_ALLOW_HEAD_LINES])


def scan_file(path: Path, root: Path, rules: list[Rule], cfg: LocalConfig
              ) -> tuple[list[Finding], Skipped | None]:
    rel = path.relative_to(root).as_posix()
    source = read_source(path)
    if source is None:
        return [], Skipped(rel, "바이너리로 판정되어 읽지 않음")
    if source.lossy:
        return [], Skipped(rel, "인코딩을 판정하지 못해 손실 디코딩됨. 결과를 신뢰하지 말 것")
    # split("\n") 을 쓰는 이유: splitlines() 는 \v \f \u2028 에서도 끊어 보고한
    # 줄 번호가 grep·편집기와 어긋난다.
    lines = source.text.split("\n")
    if file_allowed(lines):
        return [], None

    findings: list[Finding] = []
    truncated = False
    seen: set[tuple[int, int, str]] = set()
    for lineno, raw in enumerate(lines, 1):
        line = raw
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE]
            truncated = True
        if INLINE_ALLOW.search(line) or is_allowed(cfg, rel, line):
            continue
        for rule in rules:
            if rule.line_veto and rule.line_veto.search(line):
                continue
            if rule.line_require and not rule.line_require.search(line):
                continue
            for m in rule.pattern.finditer(line):
                matched = m.group(0)
                if rule.validator and not VALIDATORS[rule.validator](matched):
                    continue
                key = (lineno, m.start(), rule.axis)
                if key in seen:
                    continue
                seen.add(key)
                lo = max(0, m.start() - CONTEXT_CHARS // 2)
                shown = redact(matched) if rule.redact else matched.strip()[:200]
                ctx = line[lo:lo + CONTEXT_CHARS].strip()
                findings.append(Finding(
                    path=rel, line=lineno, axis=rule.axis, rule=rule.name,
                    match=shown,
                    context="(생략)" if rule.redact else ctx,
                    note=rule.note))
    skip = Skipped(rel, f"{MAX_LINE}자를 넘는 줄이 있어 뒷부분을 보지 못함") if truncated else None
    return findings, skip


def apply_replacements(files: list[Path], root: Path, cfg: LocalConfig,
                       out=sys.stdout) -> tuple[int, int, list[Skipped]]:
    """패턴 파일의 치환표를 적용한다.

    스캔과 같은 억제 규칙을 따른다. 남기기로 판단해 표시해 둔 것을 치환이 덮어 쓰면
    허용 표시가 무의미해지고, 픽스처가 기대하는 문자열이 조용히 바뀐다.
    """
    changed_files = changed_hits = 0
    skipped: list[Skipped] = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        source = read_source(path)
        if source is None:
            continue
        if source.lossy:
            skipped.append(Skipped(rel, "인코딩 미판정. 되쓰면 깨지므로 건드리지 않음"))
            continue
        lines = source.text.split("\n")
        if file_allowed(lines) or is_allowed(cfg, rel, ""):
            continue
        hits = 0
        for i, line in enumerate(lines):
            if INLINE_ALLOW.search(line) or is_allowed(cfg, rel, line):
                continue
            for pat, repl, _raw in cfg.replacements:
                # 함수 대체를 쓰는 이유: 문자열 대체는 \1 \n 같은 시퀀스를 해석하고,
                # Windows 경로처럼 역슬래시가 든 값에서는 re.error 로 죽는다.
                line, n = pat.subn(lambda _m, v=repl: v, line)
                hits += n
            lines[i] = line
        if not hits:
            continue
        try:
            # newline="" 은 줄바꿈을 변환하지 않는다. 기본값이면 CRLF 파일의 \r\n 이
            # \r\r\n 으로 불어나고, 돌릴 때마다 누적된다.
            with open(path, "w", encoding=source.encoding, newline="") as fh:
                fh.write("\n".join(lines))
        except OSError as exc:
            skipped.append(Skipped(rel, f"쓰기 실패: {exc}"))
            continue
        changed_files += 1
        changed_hits += hits
        print(f"  치환 {hits:>3}건  {rel}", file=out)
    return changed_files, changed_hits, skipped


def origin_url(root: Path) -> str:
    return (_run_git(["remote", "get-url", "origin"], root) or "").strip()


# --------------------------------------------------------------------------
# 출력
# --------------------------------------------------------------------------

AXIS_LABEL = {
    "local": "머신 로컬 흔적", "coupling": "개인 도구 결합",
    "pii": "개인 식별자", "secret": "크리덴셜", "custom": "저장소 고유 패턴",
}


def report_text(findings: list[Finding], skipped: list[Skipped], root: Path,
                cfg: LocalConfig, scanned: int) -> None:
    print(f"\n대상: {root}    파일 {scanned}개 스캔")
    if cfg.found:
        extra = f", 유형 {cfg.repo_type}" if cfg.repo_type else ""
        n_allow = len(cfg.allow_literals) + len(cfg.allow_regexes) + len(cfg.allow_paths)
        print(f"패턴 파일: {LOCAL_FILE} (치환 {len(cfg.replacements)}"
              f" · 탐지 {len(cfg.detects)} · 허용 {n_allow}{extra})")
    else:
        print(f"패턴 파일: 없음. 저장소 고유 식별자를 잡으려면 {LOCAL_FILE} 을 만든다")

    if skipped:
        print(f"\n── 보지 못한 파일 {len(skipped)}개 (직접 확인할 것)")
        for s in skipped[:15]:
            print(f"    {s.path}  ({s.reason})")
        if len(skipped) > 15:
            print(f"    ... 외 {len(skipped) - 15}개")

    if not findings:
        print("\n발견 없음.\n")
        return

    by_axis: dict[str, list[Finding]] = {}
    for f in findings:
        by_axis.setdefault(f.axis, []).append(f)

    for axis in ("secret", "pii", "custom", "local", "coupling"):
        items = by_axis.get(axis)
        if not items:
            continue
        print(f"\n── {AXIS_LABEL.get(axis, axis)} ({len(items)}건)")
        by_rule: dict[str, list[Finding]] = {}
        for f in items:
            by_rule.setdefault(f.rule, []).append(f)
        for rule, group in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
            print(f"\n  [{rule}] {group[0].note}")
            for f in group[:12]:
                print(f"    {f.path}:{f.line}  {f.match}")
            if len(group) > 12:
                print(f"    ... 외 {len(group) - 12}건")

    print(f"\n합계 {len(findings)}건.")
    print("남겨야 하는 항목은 지우지 말고 근거와 함께 표시한다: 줄 끝 `sanitize: allow <근거>`,")
    print(f"파일 앞부분 `sanitize: allow-file <근거>`, 또는 {LOCAL_FILE} 의 '## 허용' 절.\n")


# --------------------------------------------------------------------------

AXES = ("local", "coupling", "pii", "secret", "custom")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="공개 전환 전 개인정보·개인 흔적 스캔",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="종료 코드: 0 발견 없음 / 1 발견 있음 / 2 실행 오류")
    ap.add_argument("path", nargs="?", default=".", help="스캔할 저장소 경로 (기본: 현재 디렉터리)")
    ap.add_argument("--axes", default="all",
                    help=f"쉼표 구분. {','.join(AXES)} 또는 all (기본: all)")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--staged", action="store_true",
                    help="staged 파일만 스캔 (pre-commit 훅용). 내용은 인덱스가 아니라 "
                         "작업 트리에서 읽으므로 부분 스테이징은 미스테이지 내용으로 판정된다")
    ap.add_argument("--all", action="store_true", dest="include_ignored",
                    help="gitignore 된 파일까지 스캔 (--staged 와 함께 쓸 수 없음)")
    ap.add_argument("--skills-root", type=Path, default=None,
                    help="로컬 스킬 디렉터리 (coupling 축 보강용)")
    ap.add_argument("--no-skill-scan", action="store_true",
                    help="로컬 스킬 목록을 읽지 않는다")
    ap.add_argument("--apply", action="store_true",
                    help="패턴 파일의 치환표를 적용한다 (반출본에서만 쓸 것)")
    ap.add_argument("--yes", action="store_true", help="--apply 확인 생략")
    return ap


def run(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"오류: 디렉터리가 아닙니다: {root}", file=sys.stderr)
        return 2
    if args.include_ignored and args.staged:
        print("오류: --all 과 --staged 는 함께 쓸 수 없습니다 "
              "(무시 목록까지 보는 것과 staged 만 보는 것은 서로 배타적입니다).",
              file=sys.stderr)
        return 2

    cfg = load_local_config(root)

    selected = set(AXES) if args.axes == "all" else {
        a.strip() for a in args.axes.split(",") if a.strip()}
    unknown = selected - set(AXES)
    if unknown:
        print(f"오류: 알 수 없는 축: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2

    rules = [r for r in builtin_rules() if r.axis in selected]
    if "custom" in selected:
        for pat, raw in cfg.detects:
            rules.append(Rule("custom", "local-detect", pat, f"패턴 파일 항목: {raw}"))
        for pat, repl, raw in cfg.replacements:
            rules.append(Rule("custom", "local-replace", pat, f"치환 대상: {raw} → {repl}"))
    if "coupling" in selected and not args.no_skill_scan:
        rules += skill_reference_rules(local_skill_names(args.skills_root),
                                       own_skill_names(root))

    if not rules:
        print(f"오류: 적용할 규칙이 없습니다. --axes custom 만 골랐다면 {LOCAL_FILE} 이 "
              f"있어야 합니다(SKILL.md 1단계).", file=sys.stderr)
        return 2

    files, skipped = collect_files(root, args.staged, args.include_ignored)
    progress = sys.stderr if args.format == "json" else sys.stdout

    if args.apply:
        if not cfg.replacements:
            print(f"오류: {LOCAL_FILE} 의 '## 치환' 절이 비어 있어 적용할 것이 없습니다.",
                  file=sys.stderr)
            return 2
        print(f"치환 대상: {root}", file=progress)
        remote = origin_url(root)
        if remote:
            print(f"원격: {remote}", file=progress)
        print("이 트리의 파일을 직접 수정합니다. 정본이 아니라 반출본인지 확인하세요.",
              file=progress)
        if not args.yes:
            print("확인하려면 --yes 를 붙여 다시 실행하세요.", file=sys.stderr)
            return 2
        n_files, n_hits, apply_skipped = apply_replacements(files, root, cfg, progress)
        skipped.extend(apply_skipped)
        print(f"\n파일 {n_files}개에서 {n_hits}건 치환. 이어서 스캔합니다.", file=progress)

    findings: list[Finding] = []
    for path in files:
        got, skip = scan_file(path, root, rules, cfg)
        findings.extend(got)
        if skip:
            skipped.append(skip)
    findings.sort(key=lambda f: (f.axis, f.path, f.line))

    if args.format == "json":
        json.dump({
            "root": str(root), "scanned": len(files),
            "repo_type": cfg.repo_type, "local_config": cfg.found,
            "axes": sorted(selected), "count": len(findings),
            "findings": [f.as_dict() for f in findings],
            "skipped": [{"path": s.path, "reason": s.reason} for s in skipped],
        }, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        report_text(findings, skipped, root, cfg, len(files))

    return 1 if findings else 0


def main() -> int:
    args = build_parser().parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        return 2
    except Exception as exc:                        # 종료 코드 계약을 지킨다
        # 예기치 못한 예외로 1을 반환하면 호출자가 "발견 있음"으로 오해한다.
        print(f"오류: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
