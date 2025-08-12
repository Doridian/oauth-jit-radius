#!/bin/bash
set -euo pipefail

generate() {
    infile="$1"
    outfile="${infile%.txt}.go"
    go run layeh.com/radius/cmd/radius-dict-gen -package radius -output "$outfile" "$infile"
}

for f in *.txt; do
    generate "$f"
done
