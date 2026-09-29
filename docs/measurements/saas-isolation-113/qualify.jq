def require($ok; $message): if $ok then . else error($message) end;

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
    and all(.protected_comparisons[]; (.pass | type) == "boolean")
    and all(.groups[];
      (if .phase == "recovery" then 12 else 16 end) as $n
      | .offered == $n
        and ([.outcomes[].n] | add) == $n
        and (if (.phase == "baseline" or .route == "iam" or (.route | endswith("healthy"))) then
          .success.n == $n and .outcomes == [{outcome: "success", n: $n}]
        else true end))
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
