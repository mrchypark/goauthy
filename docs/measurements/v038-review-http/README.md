# v0.3.8 review HTTP runtime measurements

The three serial baseline/fixed pairs ran with Go 1.27.2 on a Macmini9,1 M1
(`darwin/arm64`, 8 CPU, 16 GiB), with `GOMAXPROCS=2`.
Each test used loopback TCP through `httptest.Server` and `http.Client`, the
production token and UserInfo handlers, and private synthetic data only. The
matrix covers authorization-code token exchange, UserInfo, and refresh grant;
0 or 1,000 unrelated identity rows; and concurrency 1 or 8. Each cell has 200
observations per run and three runs per tree. Raw sanitized measurements are in
[`raw/`](raw/), with per-run numeric counters, status codes, and byte counts.
The complete machine-readable aggregation is [`summary.json`](summary.json);
[`summarize.jq`](summarize.jq) regenerates it from [`runs.json`](runs.json).
[`manifest.json`](manifest.json) records test provenance and workload scope.
[`REVIEW-DISPOSITION.md`](REVIEW-DISPOSITION.md) records source-backed retained
contracts and the performance areas this campaign did not measure.
`SHA256SUMS` records hashes for all included result artifacts and the harness.

Immediately after the six-run campaign, the host reported load averages 18.09,
19.88, and 20.61. Background load was not controlled or recorded per run, and
workload identities and process details are omitted. Treat all timing and
throughput figures below as descriptive observations under uncontrolled host
conditions, not evidence of a causal change, speed regression or improvement,
capacity, or a production SLO. Three runs and 200 samples per cell also make
tail-percentile ranges noisy; no significance claim is made.

The deterministic implementation counters do show the intended lookup change:
authorization-code and refresh requests issue 2 profile-resolver calls per
request in baseline and 1 in fixed; UserInfo remains at 1 in both. Across the
three runs, that is 1,200 versus 600 resolver calls in each authorization-code
or refresh cell, with 600 versus 600 for UserInfo. The requests use the current
linearizable resolver and production-equivalent profile projection. The invalid
code (400) and invalid UserInfo (401) controls run outside the latency samples.
All timed HTTP observations returned 200: 14,400 total with zero HTTP errors.

## HTTP observations

Values are `median [minimum–maximum]` across the three runs. Latency is in
milliseconds. `B/F` means baseline/fixed. Resolver calls are summed over the
600 requests in each cell. HTTP errors count non-2xx responses in the timed
samples; all 12 cells had 600 status-200 responses per tree.

| Stage | Rows | C | P50 baseline | P50 fixed | P95 baseline | P95 fixed | P99 baseline | P99 fixed | Errors B/F | Resolver calls B/F |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| authorization_code_token | 0 | 1 | 18.21 [15.74–27.96] | 18.43 [16.31–25.99] | 34.25 [33.65–68.68] | 41.72 [31.7–71.25] | 65.28 [41.98–135.41] | 67.51 [41.77–101.16] | 0/0 | 1200/600 |
| authorization_code_token | 0 | 8 | 53.37 [46.62–67.2] | 45.45 [43.23–50.41] | 111.95 [93.13–244.22] | 90.23 [82.49–135.96] | 123.06 [112.58–467.53] | 165.52 [112.53–187.08] | 0/0 | 1200/600 |
| authorization_code_token | 1000 | 1 | 20.08 [16.59–28.51] | 22.38 [17.83–23.74] | 43.15 [35.16–62.78] | 60.53 [32.57–62.45] | 66.16 [42.88–93.36] | 145.32 [37.98–179.88] | 0/0 | 1200/600 |
| authorization_code_token | 1000 | 8 | 53.31 [47.49–92.11] | 63.72 [40.74–87.89] | 217.33 [155.53–228.32] | 150.89 [116.75–179.73] | 259.58 [181.43–500.79] | 176.01 [148.84–216.22] | 0/0 | 1200/600 |
| refresh_grant | 0 | 1 | 21.57 [16.45–24.36] | 19.35 [14.95–27.37] | 50.43 [40.68–64.66] | 39.04 [26.92–66.97] | 88.49 [67.84–97.3] | 53.31 [29–123.72] | 0/0 | 1200/600 |
| refresh_grant | 0 | 8 | 53.26 [49.02–56.08] | 71.95 [50.39–74.97] | 121.04 [118.67–134.5] | 140.93 [101.27–205.19] | 165.91 [161.86–204.78] | 198.09 [125.12–235.9] | 0/0 | 1200/600 |
| refresh_grant | 1000 | 1 | 23.78 [22.05–25.33] | 19.27 [16.33–21.53] | 70.26 [54.34–73.59] | 39.46 [39–43.41] | 134.67 [94.57–156.34] | 62.24 [55.05–84.4] | 0/0 | 1200/600 |
| refresh_grant | 1000 | 8 | 95.24 [61.24–168.16] | 112.99 [41.33–120.43] | 356.01 [172.78–479.14] | 342.97 [81.44–447.27] | 557.68 [209.73–1574.98] | 570.37 [102.67–2238.84] | 0/0 | 1200/600 |
| userinfo | 0 | 1 | 1.02 [0.38–2.35] | 0.69 [0.37–1.25] | 2.72 [0.48–9.63] | 1.76 [0.6–2.78] | 4.5 [0.58–48.74] | 2.29 [1.24–4.54] | 0/0 | 600/600 |
| userinfo | 0 | 8 | 1.63 [1.34–2.06] | 1.36 [1.22–1.38] | 2.94 [2.88–6.71] | 4.21 [3.32–5.2] | 3.8 [3.1–8.83] | 5.48 [4.38–6.67] | 0/0 | 600/600 |
| userinfo | 1000 | 1 | 0.92 [0.41–1.58] | 0.44 [0.41–0.54] | 3.62 [0.98–7.04] | 1.38 [0.79–1.67] | 4.92 [1.65–14.7] | 2.08 [1.74–2.62] | 0/0 | 600/600 |
| userinfo | 1000 | 8 | 2.53 [2.28–5.53] | 3.55 [1.3–4.33] | 7.92 [6.55–19.09] | 8.35 [3.29–14] | 9.32 [8.2–31.86] | 11.55 [4.43–30.97] | 0/0 | 600/600 |

Throughput, also `median [minimum–maximum]` requests/s across runs:

| Stage | Rows | C | Throughput baseline req/s | Throughput fixed req/s | HTTP status baseline/fixed |
|---|---:|---:|---:|---:|---:|
| authorization_code_token | 0 | 1 | 45.6 [28.8–55.3] | 45.4 [31–53.6] | {"200":600}/{"200":600} |
| authorization_code_token | 0 | 8 | 130.1 [78–149.6] | 153.6 [127–158.3] | {"200":600}/{"200":600} |
| authorization_code_token | 1000 | 1 | 42.2 [30.8–50.3] | 32.6 [31.6–49.5] | {"200":600}/{"200":600} |
| authorization_code_token | 1000 | 8 | 86.5 [73–127.3] | 106.6 [76.8–149.5] | {"200":600}/{"200":600} |
| refresh_grant | 0 | 1 | 37.5 [32.6–49] | 45.2 [28.8–60.9] | {"200":600}/{"200":600} |
| refresh_grant | 0 | 8 | 120.5 [117.8–127] | 101.9 [94–142.4] | {"200":600}/{"200":600} |
| refresh_grant | 1000 | 1 | 30.8 [30.8–36.1] | 42.6 [40.7–49.1] | {"200":600}/{"200":600} |
| refresh_grant | 1000 | 8 | 44.7 [39.7–101.9] | 50.3 [37.4–172.6] | {"200":600}/{"200":600} |
| userinfo | 0 | 1 | 826 [187.5–2526.1] | 1172.4 [724.9–2423.5] | {"200":600}/{"200":600} |
| userinfo | 0 | 8 | 5004.4 [2749.9–5017.5] | 4494.5 [3853.1–4751] | {"200":600}/{"200":600} |
| userinfo | 1000 | 1 | 757.9 [397.4–2069.7] | 1728.3 [1303.2–2064.8] | {"200":600}/{"200":600} |
| userinfo | 1000 | 8 | 2296.3 [978.5–2668.8] | 1666 [1273.5–4575.8] | {"200":600}/{"200":600} |

The raw HTTP records include request body, authorization header, and response
body byte counts per cell. `summary.json` aggregates those byte totals for each
set of three repetitions and contains full P50/P95/P99 and throughput medians
and ranges, status totals, errors, sample counts, and resolver counts. Its jq
summary can be regenerated with:

```sh
cd docs/measurements/v038-review-http
jq -f summarize.jq runs.json > summary.json
```

## Separate Argon2 verify observations

This direct KDF check is not an HTTP endpoint measurement. The application work
admission errors are included in the counts rather than dropped. As with the
HTTP timings, these latency and throughput figures are only descriptive under
the shared-host load described above.

| Concurrency | Baseline P95 ms (median [range]) | Fixed P95 ms (median [range]) | Baseline P99 ms (median [range]) | Fixed P99 ms (median [range]) | Baseline/fixed median req/s | Work-limit errors B/F |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 122.86 [116.07–158.72] | 90.98 [67.81–119.21] | 222.56 [180.44–421.92] | 166.85 [117.99–198.40] | 17.75 / 21.73 | 0 / 0 of 600 each |
| 8 | 384.15 [309.10–415.30] | 430.17 [215.00–649.33] | 505.44 [393.84–582.91] | 504.64 [242.11–976.58] | 36.69 / 38.07 | 18 / 61 of 600 each |

The different admission-error counts at concurrency 8 and wide KDF timing
ranges are reported as observed, not interpreted as a causal change. This
campaign did not include expired-token backlog, browser session validation,
remote network, multi-node replication, a 10,000-row case, or live-user data.
