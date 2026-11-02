#!/bin/bash
# Mutation harness: prove an offline suite's assertions actually bite. Each case replaces one anchor in a
# source file with a wrong value, rebuilds, and reports what the suite turned red. A mutation that fails to
# compile, or that the built binary does not contain, covers nothing - so those two outcomes are named rather
# than counted as passing.
#
# usage: tools/sabotage.sh --source <file> --test <csproj> --artifact <dll> --run <exe> --cases <file>
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
SRC="" TEST="" ARTIFACT="" EXE="" CASES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --source)   SRC="$2"; shift 2 ;;
        --test)     TEST="$2"; shift 2 ;;
        --artifact) ARTIFACT="$2"; shift 2 ;;
        --run)      EXE="$2"; shift 2 ;;
        --cases)    CASES="$2"; shift 2 ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done
for pair in "--source $SRC" "--test $TEST" "--artifact $ARTIFACT" "--run $EXE" "--cases $CASES"; do
    [ -n "${pair#* }" ] || { echo "missing ${pair%% *}"; exit 2; }
done
[ -f "$SRC" ] && [ -f "$TEST" ] && [ -f "$CASES" ] || { echo "no such file among source/test/cases"; exit 2; }

# A mutation edits a tracked file in place, so it must not be run over somebody's uncommitted work.
DIRTY=$(git status --porcelain -- "$SRC")
[ -z "$DIRTY" ] || { echo "$SRC is not clean; commit or stash it before sabotaging it"; exit 1; }

OUT="${TEMP:-/tmp}/sabotage-$(basename "$SRC" .cs)/"
OUTW="$(cygpath -w "${OUT%/}")\\"
BIN="${OUT}Debug/net10.0"
PRISTINE="${OUT}pristine.cs"
LOG="${OUT}log"
mkdir -p "$OUT" || exit 1
: > "$LOG"

restore() { [ -f "$PRISTINE" ] && cp "$PRISTINE" "$SRC" && touch "$SRC"; }
trap 'restore; echo "--- restored $SRC ---" >> "$LOG"' EXIT INT TERM

build() {
    dotnet build "$TEST" --nologo -v q --no-incremental -p:BaseOutputPath="$OUTW" > "${OUT}build.txt" 2>&1
}

run_suite() { "$BIN/$EXE" > "${OUT}run.txt" 2>&1; }

# The control comes first: red is only attributable to the mutation if the same suite was green a moment ago.
cp "$SRC" "$PRISTINE"; touch "$SRC"
if ! build || ! grep -qE ' 0 Error\(s\)' "${OUT}build.txt"; then
    echo "the suite does not build clean before any mutation - see ${OUT}build.txt"; exit 1; fi
if ! run_suite || grep -qE 'FAIL \(' "${OUT}run.txt"; then
    echo "the suite is not green before any mutation - every case below would be ambiguous"; exit 1; fi
echo "=== baseline: green, before any mutation ===" >> "$LOG"

run_case() {
    local name="$1" old="$2" new="$3" expect="$4" count
    cp "$PRISTINE" "$SRC"; touch "$SRC"
    # The anchor has to be unique: two matches would mean the case mutated something other than what it names.
    if ! perl -e 'use strict; use warnings;
        my ($path,$old,$new)=@ARGV;
        open my $fh,"<",$path or die "open: $!"; binmode $fh; local $/; my $data=<$fh>; close $fh;
        my $n = () = $data =~ /\Q$old\E/g;
        die "anchor seen $n times (need 1)\n" unless $n==1;
        $data =~ s/\Q$old\E/$new/;
        open my $out,">",$path or die; binmode $out; print $out $data; close $out;
    ' "$SRC" "$old" "$new"; then
        echo "=== $name ANCHOR-FAILED (mutation never applied; covers nothing)" >> "$LOG"; return
    fi
    if cmp -s "$PRISTINE" "$SRC"; then
        echo "=== $name SOURCE-UNCHANGED (covers nothing)" >> "$LOG"; return
    fi
    if ! build || ! grep -qE ' 0 Error\(s\)' "${OUT}build.txt"; then
        echo "=== $name BUILD-FAILED (covers nothing; see ${OUT}build.txt)" >> "$LOG"; return
    fi
    # Without a trailing backslash on BaseOutputPath, MSBuild puts a referenced project's output in a
    # sibling directory and the exe here runs a dll that was never rebuilt.
    if [ ! "$BIN/$ARTIFACT" -nt "$SRC" ]; then
        echo "=== $name STALE-BINARY: $ARTIFACT is not newer than $SRC" >> "$LOG"; return
    fi
    run_suite
    count=$(grep -oE 'FAIL \([0-9]+\)' "${OUT}run.txt" | grep -oE '[0-9]+' | head -1)
    echo "=== $name  red=${count:-0}  predicted: $expect" >> "$LOG"
    grep -E '\]   ' "${OUT}run.txt" | head -6 >> "$LOG"
}

. "$CASES"

restore
touch "$SRC"
if build && run_suite && ! grep -qE 'FAIL \(' "${OUT}run.txt"; then
    echo "--- restored, forced rebuild, still green ---" >> "$LOG"
    tail -1 "${OUT}run.txt" >> "$LOG"
else
    echo "--- restored but the suite is NOT green after the restore: the run damaged $SRC ---" >> "$LOG"
fi
cat "$LOG"
