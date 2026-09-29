def require($ok; $message): if $ok then . else error($message) end;
def expected_outcomes($phase; $route; $n):
  if $phase == "baseline" or $phase == "recovery"
    or $route == "iam" or $route == "api-healthy" or $route == "oauth-healthy" then
    [{outcome: "success", n: $n}]
  elif $phase == "mixed" and ($route == "oauth-cancel" or $route == "oauth-header" or $route == "api-body") then
    [{outcome: "client-error", n: $n}]
  elif $phase == "mixed" and $route == "api-dial" then
    [{outcome: "http-502", n: $n}]
  else [] end;
def limit($value; $factor; $offset): [($value * $factor), ($value + $offset)] | max;

. as $runs
| require(($runs | type) == "array"; "expected result array")
| require(($runs | length) == 3; "expected exactly three retained primary runs")
| require([$runs[].run] == [1, 2, 3]; "run IDs must be 1, 2, 3 in order")
| require(all($runs[];
    .mode == "primary"
    and .attempts == 260
    and .violations == []
    and (.groups | length) == 17
    and ([.groups[] | "\(.phase)/\(.route)"] | sort) == [
      "baseline/api-body", "baseline/api-dial", "baseline/api-healthy", "baseline/iam",
      "baseline/oauth-cancel", "baseline/oauth-header", "baseline/oauth-healthy",
      "mixed/api-body", "mixed/api-dial", "mixed/api-healthy", "mixed/iam",
      "mixed/oauth-cancel", "mixed/oauth-header", "mixed/oauth-healthy",
      "recovery/api-healthy", "recovery/iam", "recovery/oauth-healthy"
    ]
    and (.protected_comparisons | length) == 6
    and ([.protected_comparisons[] | "\(.phase)/\(.route)"] | sort) == [
      "mixed/api-healthy", "mixed/iam", "mixed/oauth-healthy",
      "recovery/api-healthy", "recovery/iam", "recovery/oauth-healthy"
    ]
    and all(.groups[];
      (if .phase == "recovery" then 12 else 16 end) as $n
      | .offered == $n
        and ([.outcomes[].n] | add) == $n
        and .outcomes == expected_outcomes(.phase; .route; $n)
        and (if expected_outcomes(.phase; .route; $n)[0].outcome == "success" then
          .success.n == $n
            and (.success.p95_ms | type) == "number"
            and (.success.p99_ms | type) == "number"
        else true end))
    and all($runs[]; . as $run
      | all($run.protected_comparisons[];
        . as $comparison
        | ($run.groups[] | select(.phase == "baseline" and .route == $comparison.route)) as $baseline
        | ($run.groups[] | select(.phase == $comparison.phase and .route == $comparison.route)) as $observed
        | $comparison.n == $observed.success.n
          and $comparison.p95_ms == $observed.success.p95_ms
          and $comparison.p99_ms == $observed.success.p99_ms
          and $comparison.p95_limit_ms == limit($baseline.success.p95_ms; 1.25; 25)
          and $comparison.p99_limit_ms == limit($baseline.success.p99_ms; 1.5; 50)
          and ($comparison.pass | type) == "boolean"
          and $comparison.pass == ($comparison.p95_ms <= $comparison.p95_limit_ms and $comparison.p99_ms <= $comparison.p99_limit_ms)))
    and .mutations.bindings == 108
    and .mutations.total == 108
    and .mutations.max_per_old_version == 1
    and .resources.sample_count > 0
    and .resources.max_rss_bytes <= 314474496
    and .resources.sampled_heap_peak_bytes <= 124526000
    and .resources.sampled_goroutine_peak <= 390
    and (.final_pools | length) == 2
    and all(.final_pools[]; .Leases == 0 and .Dials == 0 and .Connections == 0)
  ); "retained run failed completeness, correctness, or resource checks")
| {
    run_count: 3,
    runs: [$runs[].run],
    standalone_correctness: "pass",
    standalone_performance: (if all($runs[]; all(.protected_comparisons[]; .pass)) then "pass" else "inconclusive" end),
    performance_breaches: [$runs[] | . as $run | .protected_comparisons[] | select(.pass | not) | {run: $run.run, phase, route, p95_ms, p95_limit_ms, p99_ms, p99_limit_ms}],
    exact_three_topology: "not-qualified-by-standalone-runs"
  }
