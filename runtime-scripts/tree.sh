#!/usr/bin/env bash
# tree.sh: print the project tree and mark everything git will NOT upload with IGNORED.
#
#   bash runtime-scripts/tree.sh            # the tree
#   bash runtime-scripts/tree.sh --sizes    # plus file count and size of each folder git skips
#                                           # (slower: it has to look inside them)
#
# Every real secret should say IGNORED, and no .example file should. Git itself decides, so the
# tree always agrees with what a push would do. Folders git skips are shown two levels deep
# (at most 15 entries per folder) instead of in full. Prints names only, never file contents.
# Works from anywhere inside the project.
exec python3 -I - "$(cd "$(dirname "$0")" && pwd)" "$@" <<'PY'
import os
import subprocess
import sys
import tempfile

start, args = sys.argv[1], sys.argv[2:]
SIZES = "--sizes" in args
COL = 36          # where IGNORED starts
SHOW = 15         # entries listed per folder inside a skipped folder
DEPTH = 2         # levels listed inside a skipped folder

root = start
while not os.path.isfile(os.path.join(root, "docker-compose.yml")):
    parent = os.path.dirname(root)
    if parent == root:
        sys.exit("can't find the project folder (docker-compose.yml)")
    root = parent
os.chdir(root)

# Use the real repo if this folder is one; otherwise a throwaway index (changes nothing here).
tmp = None
top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
if top.returncode == 0 and os.path.realpath(top.stdout.strip()) == os.path.realpath(root):
    GIT = ["git"]
else:
    tmp = tempfile.TemporaryDirectory()
    subprocess.run(["git", "init", "-q", tmp.name], check=True)
    GIT = ["git", "--git-dir=" + os.path.join(tmp.name, ".git"), "--work-tree=."]


def ignored(paths):
    """The subset of paths (relative, no trailing slash) that git would skip. Git checks on disk
    whether each one is a folder; a trailing slash would make `**/secrets/*` match the folder."""
    if not paths:
        return set()
    p = subprocess.run(GIT + ["check-ignore", "--stdin", "-z"], input="\0".join(paths) + "\0",
                       capture_output=True, text=True)
    return set(x for x in p.stdout.split("\0") if x)


def entries(rel):
    """Files first, then folders, each in plain byte order (dotfiles first), like `ls`."""
    try:
        with os.scandir(rel or ".") as it:
            items = [(e.name, e.is_dir(follow_symlinks=False)) for e in it if e.name != ".git"]
    except OSError:
        return None
    return sorted([i for i in items if not i[1]]) + sorted([i for i in items if i[1]])


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def count(c, s):
    return "(empty)" if c == 0 else f"({c} file{'' if c == 1 else 's'}, {human(s)})"


def tally(rel):
    """file count and bytes for rel and every folder inside it down to DEPTH levels."""
    out = {}
    base = rel
    for dirpath, dirs, files in os.walk(base, onerror=lambda e: None):
        dirs[:] = [d for d in dirs if d != ".git"]
        size = 0
        for f in files:
            try:
                size += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
        parts = os.path.relpath(dirpath, base).split(os.sep)
        parts = [] if parts == ["."] else parts
        for k in range(0, min(len(parts), DEPTH) + 1):
            key = "/".join([base] + parts[:k])
            c, s = out.get(key, (0, 0))
            out[key] = (c + len(files), s + size)
    return out


def line(prefix, name, tag=""):
    text = prefix + name
    pad = max(COL - len(text), 2)
    print(text + (" " * pad + tag if tag else ""))


uploaded = 0


def show_skipped(rel, prefix, level, sizes):
    """List what's inside a folder git skips, without tagging each entry."""
    if level > DEPTH:
        return
    items = entries(rel)
    if items is None:
        line(prefix, "└── (can't read this folder)")
        return
    hidden = max(len(items) - SHOW, 0)
    items = items[:SHOW]
    for i, (name, is_dir) in enumerate(items):
        last = i == len(items) - 1 and not hidden
        path = rel + name
        tag = ""
        if is_dir and sizes is not None and path in sizes:
            c, s = sizes[path]
            tag = count(c, s)
        line(prefix + ("└── " if last else "├── "), name + ("/" if is_dir else ""), tag)
        if is_dir:
            show_skipped(path + "/", prefix + ("    " if last else "│   "), level + 1, sizes)
    if hidden:
        line(prefix + "└── ", f"… and {hidden} more")


def walk(rel, prefix):
    global uploaded
    items = entries(rel)
    if items is None:
        line(prefix, "└── (can't read this folder)")
        return
    paths = [rel + n for n, d in items]
    skip = ignored(paths)
    for i, ((name, is_dir), path) in enumerate(zip(items, paths)):
        last = i == len(items) - 1
        branch, deeper = ("└── ", "    ") if last else ("├── ", "│   ")
        if path in skip:
            tag = "IGNORED"
            sizes = None
            if is_dir and SIZES:
                sizes = tally(path)
                c, s = sizes.get(path, (0, 0))
                tag += "  " + count(c, s)
            line(prefix + branch, name + ("/" if is_dir else ""), tag)
            if is_dir:
                show_skipped(path + "/", prefix + deeper, 1, sizes)
        else:
            line(prefix + branch, name + ("/" if is_dir else ""))
            if is_dir:
                walk(path + "/", prefix + deeper)
            else:
                uploaded += 1


print(os.path.basename(root) + "/")
walk("", "")
print(f"\n{uploaded} files would be uploaded (everything above without IGNORED)")
PY
