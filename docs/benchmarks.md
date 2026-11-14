# Benchmarks

Run them yourself:

```
make bench
```

or `PYTHONPATH=src python bench/run.py`. The script uses `timeit` from the
standard library and reports the best of five repeats, so the numbers are a
floor for one CPU core, not a throughput promise. Compare runs on the same
machine only.

Last recorded run, Nov 14, 2026, on a shared cloud VM (Intel Xeon, 1 core in use):

Python 3.13.5 on x86_64 (linux)

| case | µs/op | ops/s |
|---|---:|---:|
| scan_text over own source (2,300 lines) | 8,563.64 | 117 |
| entropy, 40-char token | 3.77 | 265,349 |
| scan_secrets, tree of 600 files | 107,527.92 | 9 |
| scan_workflows, 200 workflow files | 84,066.75 | 12 |
| scan_dockerfiles, 200 Dockerfiles | 16,713.43 | 60 |
