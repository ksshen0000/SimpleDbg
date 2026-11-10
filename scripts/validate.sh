#!/usr/bin/env bash
set -euo pipefail
sdb_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
sdb_build="build"
sdb_sanitizers=OFF
sdb_coverage=OFF
while (($#)); do
    case "$1" in
        --sanitize) sdb_sanitizers=ON; shift ;;
        --coverage) sdb_coverage=ON; shift ;;
        --build-dir)
            if (($# < 2)); then echo 'Missing directory after --build-dir' >&2; exit 2; fi
            sdb_build="$2"; shift 2 ;;
        --help)
            echo 'Usage: scripts/validate.sh [--sanitize] [--coverage] [--build-dir DIR]'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
if [[ "$sdb_build" != /* ]]; then sdb_build="$sdb_root/$sdb_build"; fi
cmake -S "$sdb_root" -B "$sdb_build" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
    -DSDB_ENABLE_SANITIZERS="$sdb_sanitizers" -DSDB_ENABLE_COVERAGE="$sdb_coverage"
cmake --build "$sdb_build" -j2
ctest --test-dir "$sdb_build" --output-on-failure
python3 "$sdb_root/tests/replay_demo.py" --sdb "$sdb_build/sdb" --delay 0 --record "$sdb_build/demo-session.txt"
python3 "$sdb_root/tests/replay_demo.py" --sdb "$sdb_build/sdb" --extended --delay 0 --record "$sdb_build/demo-extended-session.txt"
