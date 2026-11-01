#!/usr/bin/env bash
set -euo pipefail

mkdir -p baseline
go test -run '^TestBundledDatasetStartupMemoryAndPublicQueryConsistency$' -v ./pkg/geoip | tee baseline/geoip-startup.txt
go test ./pkg/kone -run '^$' -bench . -benchmem -benchtime=500ms -count=3 -cpu=1,2 | tee baseline/core.txt
go test ./pkg/geoip -run '^$' -bench . -benchmem -benchtime=500ms -count=3 -cpu=1,2 | tee baseline/geoip.txt
grep -q '^Benchmark' baseline/core.txt
grep -q '^Benchmark' baseline/geoip.txt
go test ./pkg/kone -run '^$' -bench '^BenchmarkObservationQueries$' -benchmem -benchtime=1s -count=1 -cpu=2 -cpuprofile=baseline/cpu.out -memprofile=baseline/memory.out -o baseline/kone.test > baseline/profile.txt
