#!/usr/bin/env python3
"""히스토리 판정과 역검증.

같은 명령이 재작성 **전**에는 판정으로, **후**에는 역검증으로 읽힌다.

    재작성 전 : 하나라도 >0 이면 트리에서 지운 것이 이력에 남아 있다는 뜻 → 재작성 필요
                (또는 공개 포기)
    재작성 후 : 전부 0 이어야 한다. 하나라도 >0 이면 재작성이 덜 끝난 것이다

항목마다 셋을 센다. 셋이 다른 층이라 하나로 갈음되지 않는다.

    파일 내용   git log --all -S<항목>            과거 커밋의 파일 안
    HEAD 트리   git grep -F -I -e <항목> HEAD      지금 체크아웃되는 파일 안
    커밋 메시지 git log --all --format=%B          --replace-message 필요 여부를 여기서 정한다

경로는 따로 센다: git log --all -- <경로> 가 0이 아니면 "지금 없다"와 "이력에 없다"가
다르다는 뜻이다.

**실제 값은 출력하지 않는다.** 이 스크립트의 입력은 실명·주소가 든 치환표이므로,
결과를 터미널·로그·리포트에 그대로 찍으면 검증 도구 자신이 유출 경로가 된다.
항목은 자리 번호와 가린 형태로만 표시한다.

의존성 없음 (Python 3.10+ 표준 라이브러리). git 이 PATH 에 있어야 한다.
종료 코드: 0 전부 0건 / 1 잔존 있음 / 2 실행 오류
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_traces as st  # noqa: E402

MIN_NEEDLE = 2

# 정규식은 층마다 방언이 다르다. `git log -S --pickaxe-regex` 는 POSIX ERE 만 이해하고
# (`--perl-regexp` 를 붙여도 무시한다), 커밋 메시지 쪽은 Python re 이며, git-filter-repo 는
# 치환표를 **바이트로** 읽어 컴파일한다. 방언이 갈리면 오류가 아니라 **0건**이 나오므로
# "검증했더니 깨끗함"과 "검증하지 못함"이 구분되지 않는다. 그래서 세 층에서 같은 뜻인
# 부분집합만 받고 나머지는 전부 검증 불가로 막는다.
# 대문자 축약을 빠뜨리면 `\d` 는 막히는데 `\D`·`\S`·`\W` 는 새어 나간다. 부정 축약은
# UTF-8 선행·연속 바이트에도 맞아서 수량자가 문자가 아니라 바이트를 세므로 더 위험하다.
ERE_UNSAFE = re.compile(r"\\[dwsbBAZDSW]|\\p\{|\(\?|[*+?]\?")
PY_UNSAFE = re.compile(r"\[\[:")
PORTABLE_HINT = ("세 층에서 같은 뜻인 표기만 씁니다 (\\d 대신 [0-9], [[:alpha:]] 대신 명시"
                 " 문자류, 룩어라운드·비탐욕 금지, 한글은 정규식 조각이 아니라 리터럴로)")


@dataclass
class Item:
    index: int
    raw: str
    is_regex: bool
    source: str
    content: int = 0
    head: int = 0
    message: int = 0
    error: bool = False

    @property
    def total(self) -> int:
        return self.content + self.head + self.message


@dataclass
class PathItem:
    index: int
    spec: str
    source: str
    commits: int = 0
    error: bool = False
    sensitive: bool = False        # 패턴 파일에서 온 경로는 폴더명 자체가 실명일 수 있다

    @property
    def shown(self) -> str:
        return mask(self.spec) if self.sensitive else self.spec


@dataclass
class Result:
    items: list[Item] = field(default_factory=list)
    paths: list[PathItem] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def mask(text: str) -> str:
    """길이만 남긴다. 무엇이 걸렸는지는 자리 번호로 치환표와 대조한다.

    첫 글자를 남기지 않는 이유는 한국어 실명·지명에서 첫 음절이 성씨나 지명 머리글자라
    그 한 글자가 곧 식별 단서이기 때문이다.

    scan_traces 가 매치 문자열을 그대로 찍는 것과 다른 정책인데, 쓰임이 달라서다.
    저쪽은 "이 줄을 고쳐라"라서 문자열이 곧 조치 대상이고, 여기는 숫자만으로 조치가
    끝나므로(치환표의 그 줄을 고친다) 원문을 찍을 이유가 없다.
    """
    return f"…({len(text.strip())}자)"


def git(args: list[str], cwd: Path) -> tuple[int, str]:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"오류: git 실행 실패: {exc}", file=sys.stderr)
        raise SystemExit(2)
    return out.returncode, out.stdout.decode("utf-8", errors="replace")


def parse_replace_text(path: Path) -> list[tuple[str, str]]:
    """git-filter-repo 의 --replace-text 파일을 읽는다.

    형식: `원문==>치환`. 접두어 `regex:`·`glob:`·`literal:` 은 filter-repo 와 같은 뜻이다.
    우변이 없는 줄(filter-repo 는 ***REMOVED*** 로 바꾼다)도 좌변만 쓰면 되므로 받는다.

    자르는 방식을 filter-repo 와 맞춘다(`rsplit`, 줄바꿈만 제거). 앞뒤 공백을 임의로
    털면 실제 치환되는 문자열과 검증하는 문자열이 갈리고, 그 틈이 곧 미검출이다.
    """
    items: list[tuple[str, str]] = []
    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        print(f"오류: 치환표를 UTF-8 로 읽지 못했습니다 ({path}): {exc}. "
              f"git-filter-repo 는 바이트로 읽으므로 표를 UTF-8 로 저장하세요.",
              file=sys.stderr)
        raise SystemExit(2)
    for raw in source.split("\n"):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        left = line.rsplit("==>", 1)[0] if "==>" in line else line
        if not left:
            continue
        if left.startswith("glob:"):
            items.append(("glob", left[5:]))
        elif left.startswith("regex:"):
            items.append(("regex", left[6:]))
        elif left.startswith("literal:"):
            items.append(("literal", left[8:]))
        else:
            items.append(("literal", left))
    return items


def collect_inputs(root: Path, args) -> tuple[list[Item], list[PathItem], list[str], list[str]]:
    items: list[Item] = []
    paths: list[PathItem] = []
    skipped: list[str] = []
    notes: list[str] = []
    seq = 0

    def add_needle(kind: str, raw: str, source: str) -> None:
        # 번호는 items 순서가 아니라 **입력 순서**로 매긴다. 검증 불가로 빠진 항목을
        # 건너뛰고 번호를 이어 붙이면 `#5` 가 치환표의 5번째 줄이 아니게 되고,
        # "자리 번호로 치환표와 대조한다"는 마스킹 계약이 성립하지 않는다.
        nonlocal seq
        seq += 1
        idx = seq
        if len(raw) < MIN_NEEDLE:
            skipped.append(f"#{idx} {source} {mask(raw)}: 너무 짧아 검증하지 않음")
            return
        if kind == "glob":
            # filter-repo 의 glob: 은 경로가 아니라 **내용** 글롭이다(glob_to_regex 를 거쳐
            # 바이트 정규식이 된다). 경로로 오해해 git log -- 에 넣으면 실제 치환 대상을
            # 통째로 놓친 채 0건이 나온다.
            skipped.append(f"#{idx} {source} {mask(raw)}: filter-repo 의 glob: 은 내용 글롭이라 "
                           f"여기서 검증할 수 없음. 리터럴 좌변으로 나눠 적으세요")
            return
        if kind == "regex":
            try:
                compiled = re.compile(raw)
            except re.error as exc:
                skipped.append(f"#{idx} {source} {mask(raw)}: 정규식 오류 ({exc})")
                return
            if compiled.search(""):
                # 빈 문자열에 맞는 패턴은 커밋 메시지 길이만큼 히트를 만들어 숫자가 무의미해진다
                skipped.append(f"#{idx} {source} {mask(raw)}: 빈 문자열에도 맞는 패턴이라 "
                               f"셀 수 없음")
                return
            unsafe = st.byte_regex_unsafe(raw)
            if unsafe:
                skipped.append(f"#{idx} {source} {mask(raw)}: {unsafe}. git·filter-repo 의 바이트 "
                               f"처리와 Python 의 문자 처리가 갈려 검증할 수 없음. "
                               f"{PORTABLE_HINT}")
                return
            if ERE_UNSAFE.search(raw) or PY_UNSAFE.search(raw):
                skipped.append(f"#{idx} {source} {mask(raw)}: git 과 Python 의 정규식 방언이 갈려 "
                               f"검증할 수 없음. {PORTABLE_HINT}")
                return
        items.append(Item(idx, raw, kind == "regex", source))

    if args.replace_text:
        for kind, raw in parse_replace_text(args.replace_text):
            add_needle(kind, raw, "replace-text")

    if args.use_local:
        cfg = st.load_local_config(root)
        if not cfg.found:
            print(f"오류: {st.LOCAL_FILE} 이 없습니다.", file=sys.stderr)
            raise SystemExit(2)
        for _pat, _repl, raw in cfg.replacements:
            add_needle("regex" if raw.startswith("re:") else "literal",
                       raw[3:].strip() if raw.startswith("re:") else raw,
                       f"{st.LOCAL_FILE} 치환")
        # `## 탐지` 절은 기본에서 뺀다. 후보를 넓게 찾는 용도라 정당한 공개 문맥에서도
        # 맞고, 그것이 공개 전환 게이트에 걸리면 게이트가 상시 1이 되어 결국 꺼진다.
        if args.with_detect:
            for _pat, raw in cfg.detects:
                add_needle("regex" if raw.startswith("re:") else "literal",
                           raw[3:].strip() if raw.startswith("re:") else raw,
                           f"{st.LOCAL_FILE} 탐지")
        elif cfg.detects:
            # 검사하지 않았다는 사실을 반드시 보이게 남긴다. 치환 절이 전부 0이면
            # 화면에는 "전부 0건"만 남아, 탐지 절 대상이 이력에 그대로 있는데도
            # 공개 전환 게이트가 통과한다. 범위를 좁히는 선택은 눈에 보여야 한다.
            notes.append(f"'## 탐지' 절 {len(cfg.detects)}개는 검사하지 않음 "
                         f"(넣으려면 --with-detect)")
        for spec in cfg.removed_paths:
            paths.append(PathItem(len(paths) + 1, spec, f"{st.LOCAL_FILE} 삭제 경로",
                                  sensitive=True))

    for spec in args.path_specs or []:
        paths.append(PathItem(len(paths) + 1, spec, "--path"))

    return items, paths, skipped, notes


def _lines(out: str) -> int:
    return len([ln for ln in out.split("\n") if ln.strip()])


def count_content(root: Path, item: Item) -> int | None:
    """None 은 0건이 아니라 '세지 못했다'는 뜻이다.

    git 이 오류로 끝난 것을 0으로 접으면 잘못된 패턴·깨진 저장소가 그대로 깨끗 판정이
    된다. 이 도구가 막아야 하는 실패가 바로 그것이라 오류와 0건을 구분한다.
    """
    args = ["log", "--all", "--oneline", f"-S{item.raw}"]
    if item.is_regex:
        args.append("--pickaxe-regex")
    code, out = git(args, root)
    return None if code != 0 else _lines(out)


def count_head(root: Path, item: Item) -> int | None:
    """HEAD 트리에 남아 있는 파일 수.

    리터럴에 -F 를 붙이는 이유는 주소·경로에 흔한 `.`·`(`·`\\` 가 정규식으로 해석되면
    엉뚱한 것을 세거나 문법 오류로 조용히 0 이 되기 때문이다.
    """
    flags = ["-E"] if item.is_regex else ["-F"]      # 방언은 pickaxe(ERE)에 맞춘다
    code, out = git(["grep", "-I", "-l", *flags, "-e", item.raw, "HEAD"], root)
    if code == 1:                                    # 매치 없음
        return 0
    return None if code != 0 else _lines(out)


def count_messages(messages: str, item: Item) -> int:
    if item.is_regex:
        return len(re.findall(item.raw, messages))
    return messages.count(item.raw)


def run(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"오류: 디렉터리가 아닙니다: {root}", file=sys.stderr)
        return 2
    code, _ = git(["rev-parse", "--git-dir"], root)
    if code != 0:
        print(f"오류: git 저장소가 아닙니다: {root}", file=sys.stderr)
        return 2

    items, paths, skipped, notes = collect_inputs(root, args)
    # 항목이 있었는데 전부 검증 불가로 걸러진 것과, 애초에 입력이 없는 것은 다르다.
    # 앞쪽을 "입력 없음"으로 처리하면 검증하지 못한 사실이 실행 오류에 묻힌다.
    if not items and not paths and not skipped:
        print("오류: 검사할 항목이 없습니다. --replace-text, --local, --path 중 하나를 주세요.",
              file=sys.stderr)
        return 2

    # 커밋이 하나도 없는 저장소에서는 git log 가 오류로 끝난다. 그것은 "세지 못함"이
    # 아니라 "이력에 아무것도 없음"이므로 여기서 갈라 둔다.
    has_history = (bool(git(["for-each-ref", "--count=1"], root)[1].strip())
                   or git(["rev-parse", "--verify", "--quiet", "HEAD"], root)[0] == 0)
    messages = ""
    if has_history:
        _, messages = git(["log", "--all", "--format=%B"], root)
    for item in items:
        if not has_history:
            continue
        content, head = count_content(root, item), count_head(root, item)
        if content is None or head is None:
            item.error = True
            skipped.append(f"{item.source} {mask(item.raw)}: git 이 오류로 끝나 세지 못함")
            continue
        item.content, item.head = content, head
        item.message = count_messages(messages, item)
    for p in paths:
        if not has_history:
            continue
        code, out = git(["log", "--all", "--oneline", "--", p.spec], root)
        if code != 0:
            p.error = True
            skipped.append(f"{p.source} {p.shown}: git 이 오류로 끝나 세지 못함 "
                           f"(글롭은 ':(glob)' 를 붙인다)")
            continue
        p.commits = _lines(out)

    # 검증하지 못한 항목이 있으면 깨끗하다고 말할 수 없다. 게이트를 참으로 만드는 것은
    # "발견 0건"이 아니라 "전부 실제로 확인했고 0건"이다.
    hits = [i for i in items if i.total] + [p for p in paths if p.commits]
    clean = not hits and not skipped

    if args.format == "json":
        json.dump({
            "root": str(root),
            "clean": clean,
            "items": [{"index": i.index, "source": i.source, "masked": mask(i.raw),
                       "regex": i.is_regex, "counted": not i.error,
                       "content_commits": i.content, "head_files": i.head,
                       "message_hits": i.message} for i in items],
            "paths": [{"index": p.index, "source": p.source, "spec": p.shown,
                       "counted": not p.error, "commits": p.commits} for p in paths],
            "skipped": skipped, "notes": notes,
        }, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0 if clean else 1

    print(f"\n대상: {root}    항목 {len(items)}개 · 경로 {len(paths)}개")
    for note in notes:
        print(f"    {note}")
    if skipped:
        print(f"\n── 검증하지 못한 항목 {len(skipped)}개 (0건이 아니라 '모름'이다)")
        for s in skipped:
            print(f"    {s}")
    if items:
        print("\n  #   파일 내용  HEAD  메시지  출처")
        for i in items:
            flag = "?" if i.error else (" " if i.total == 0 else "!")
            cells = ("        ?", "    ?", "      ?") if i.error else (
                f"{i.content:>9}", f"{i.head:>5}", f"{i.message:>7}")
            print(f"  {flag}{i.index:<3} {cells[0]} {cells[1]} {cells[2]}  "
                  f"{i.source} {mask(i.raw)}")
    if paths:
        print("\n  #   커밋  경로")
        for p in paths:
            flag = "?" if p.error else (" " if p.commits == 0 else "!")
            cell = "?" if p.error else str(p.commits)
            print(f"  {flag}{p.index:<3} {cell:>5}  {p.shown} ({p.source})")

    if hits:
        print(f"\n잔존 {len(hits)}항목. 재작성 전이라면 이력 재작성이 필요하다는 뜻이고"
              f"(공개 포기도 정당한 선택지다), 재작성 후라면 재작성이 덜 끝난 것이다.")
        print("메시지 열이 0이 아니면 --replace-message 가 필요하다.")
    if skipped:
        print(f"\n검증하지 못한 항목이 {len(skipped)}개 있어 깨끗하다고 판정하지 않는다.")
    if clean:
        print("\n전부 0건. 이력에 남은 것이 없다.\n")
        return 0
    print()
    return 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="치환표 좌변과 삭제 경로가 git 이력에 남아 있는지 센다",
        epilog="종료 코드: 0 전부 0건 / 1 잔존 있음 / 2 실행 오류")
    ap.add_argument("path", nargs="?", default=".", help="저장소 경로 (기본: 현재 디렉터리)")
    ap.add_argument("--replace-text", type=Path, default=None,
                    help="git-filter-repo 의 --replace-text 파일 (저장소 밖 격리 폴더)")
    ap.add_argument("--local", action="store_true", dest="use_local",
                    help=f"대상 저장소의 {st.LOCAL_FILE} 의 '## 치환' 좌변과 "
                         f"'## 삭제 경로' 를 읽는다")
    ap.add_argument("--with-detect", action="store_true",
                    help="패턴 파일의 '## 탐지' 절도 이력 검사에 넣는다. 후보를 넓게 잡는 "
                         "패턴이라 기본에서는 제외한다")
    ap.add_argument("--path", action="append", dest="path_specs", metavar="PATHSPEC",
                    help="이력에서 지운 경로. 여러 번 줄 수 있다. 글롭은 ':(glob)docs/**/*.log'")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    try:
        return run(args)
    except SystemExit as exc:
        return int(exc.code or 0)
    except KeyboardInterrupt:
        return 2
    except Exception as exc:                        # 종료 코드 계약을 지킨다
        print(f"오류: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
