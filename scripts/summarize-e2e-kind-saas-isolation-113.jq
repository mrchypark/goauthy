def nonneg: type == "number" and isfinite and . >= 0;
def nearest_rank($arr; $p): ($arr | sort) as $s | $s[((($s | length) * $p) | ceil) - 1];
def p95($arr): if ($arr | length) == 0 then null else nearest_rank($arr; 0.95) end;
def p99($arr): if ($arr | length) == 0 then null else nearest_rank($arr; 0.99) end;
def limit($v; $f; $o): if $v == null then null else [$v * $f, $v + $o] | max end;
def cfs_delta($field):
  . as $all |
  (map(select(.[$field] != null and .containerID != null))) as $v |
  (if ($v | length) >= 2 and ($v | length) == ($all | length) then
    ($v | map(.containerID) | unique) as $inst |
    ($v | map(.[$field])) as $vals |
    (if ($inst | length) == 1 and ([range(1; ($vals | length)) as $i | $vals[$i] >= $vals[$i-1]] | all) then
      {first: $vals[0], last: $vals[-1], delta: ($vals[-1] - $vals[0]), complete: true}
    else
      {first: null, last: null, delta: null, complete: false}
    end)
  else
    {first: null, last: null, delta: null, complete: false}
  end);

def base_expected($phase; $route; $operation):
  if $route == "iam" then
    (if $phase == "baseline" then 6 elif $phase == "mixed" then 6 elif $phase == "recovery" then 4 else 0 end)
  elif $route == "api-key" then
    (if $operation == "account" then (if $phase == "mixed" then 1 elif $phase == "recovery" then 4 else 0 end)
     elif $operation == "slow-headers" then (if $phase == "mixed" then 2 else 0 end)
     elif $operation == "slow-body" then (if $phase == "mixed" then 2 else 0 end)
     elif $operation == "failure" then (if $phase == "mixed" then 1 else 0 end)
     else 0 end)
  else 0 end;

def expected_n($phase; $route; $operation; $mult): base_expected($phase; $route; $operation) * $mult;

def is_protected($route; $operation): $route == "iam" or ($route == "api-key" and $operation == "account");
def is_fault($route; $operation): $route == "api-key" and ($operation == "slow-headers" or $operation == "slow-body" or $operation == "failure");
def fixture_expected: {healthy: 5, "slow-headers": 2, "slow-body": 2, fail: 1};

def expected_groups: [
  {phase: "baseline", route: "iam", operation: null},
  {phase: "mixed", route: "iam", operation: null},
  {phase: "recovery", route: "iam", operation: null},
  {phase: "mixed", route: "api-key", operation: "account"},
  {phase: "recovery", route: "api-key", operation: "account"},
  {phase: "mixed", route: "api-key", operation: "slow-headers"},
  {phase: "mixed", route: "api-key", operation: "slow-body"},
  {phase: "mixed", route: "api-key", operation: "failure"}
];

. as $input |
($input.observations // []) as $obs |
($input.samples // []) as $samp |
($input.fixture // []) as $fix |

($obs | length) as $obs_n |
if $obs_n == 0 then error("no observation records") else . end |

($obs | group_by([.driver_index, .phase, .route, .operation])) as $rawgrp |

[$rawgrp[] | {
  driver_index: .[0].driver_index,
  phase: .[0].phase,
  route: .[0].route,
  operation: .[0].operation,
  n: length,
  outcomes: (group_by(.outcome) | map({outcome: .[0].outcome, n: length})),
  success_n: ([.[] | select(.outcome == "success")] | length),
  success_latencies_ms: [.[] | select(.outcome == "success") | .completion_latency_ms],
  error_n: ([.[] | select(.outcome != "success")] | length),
  statuses: (group_by(.status // "none") | map({status: (.[0].status // "none"), n: length}))
}] as $groups |

[$groups[] | {
  driver_index, phase, route, operation, n, outcomes, success_n, error_n, statuses,
  p95_ms: p95(.success_latencies_ms),
  p99_ms: p99(.success_latencies_ms)
}] as $groups_output |

($input.stages // []) as $stages |
($stages | group_by([.driver_index, .phase, .stage, .outcome])) as $stage_groups |
[$stage_groups[] | {
  driver_index: .[0].driver_index,
  phase: .[0].phase,
  stage: .[0].stage,
  outcome: .[0].outcome,
  n: length,
  elapsed_ms_max: (map(.elapsed_ms) | max),
  elapsed_ms_p95: p95(map(.elapsed_ms))
}] as $stage_outcome_groups |
($stages | map(select(.outcome == "timeout")) | length) as $stage_timeout_n |

($obs | map(.driver_index) | unique) as $drivers |
($drivers | any(. != null)) as $attributed |
($fix | map(.index) | sort) as $fixture_indices |
if $fixture_indices != [0, 1, 2] then error("fixture metrics must cover indices 0,1,2") else . end |
(if $attributed then 1 else 3 end) as $mult |
(if $attributed then [0, 1, 2] else [null] end) as $slots |

([$slots[] as $d | ["baseline", "mixed", "recovery"][] as $p |
  {
    driver_index: $d,
    phase: $p,
    iam_attempts: ([$groups[] | select(.driver_index == $d and .route == "iam" and .phase == $p) | .n] | add // 0),
    stage_observations: ([$stage_outcome_groups[] | select(.driver_index == $d and .phase == $p) | .n] | add // 0)
  }]) as $stage_coverage |

([$obs[] | select(.route == "iam") | . as $o |
  {
    driver_index: $o.driver_index,
    phase: $o.phase,
    scheduled_unix_ms: $o.scheduled_unix_ms,
    stage_n: ([$stages[] | select(.driver_index == $o.driver_index and .phase == $o.phase and .scheduled_unix_ms == $o.scheduled_unix_ms)] | length)
  }]) as $attempt_stage_coverage |

([$stages[] | select((. as $s | [$attempt_stage_coverage[] | select(.driver_index == $s.driver_index and .phase == $s.phase and .scheduled_unix_ms == $s.scheduled_unix_ms)] | length) == 0)] | length) as $unmatched_stages |

[$slots[] as $d | expected_groups[] as $eg |
  ([$groups[] | select(.driver_index == $d and .phase == $eg.phase and .route == $eg.route and .operation == $eg.operation)][0]) as $g |
  {
    driver_index: $d,
    phase: $eg.phase,
    route: $eg.route,
    operation: $eg.operation,
    expected: expected_n($eg.phase; $eg.route; $eg.operation; $mult),
    observed: ($g.n // 0),
    complete: ($g != null and $g.n == expected_n($eg.phase; $eg.route; $eg.operation; $mult))
  }
] as $denom |

[$denom[] | select(.complete | not)] as $denom_incomplete |
[$denom[] | select(.observed > .expected)] as $denom_excess |

[$groups[] | select(
  . as $g | [expected_groups[] | select(.phase == $g.phase and .route == $g.route and .operation == $g.operation)] | length == 0
)] as $unexpected_groups |

[$groups[] | select(is_protected(.route; .operation)) | {driver_index, phase, route, operation, n, error_n}] as $protected_groups |
([$protected_groups[] | .error_n] | add // 0) as $protected_errors |

[$groups[] | select(is_fault(.route; .operation)) |
  {
    driver_index, phase, route, operation, n, statuses,
    wrong_outcome: ([.outcomes[] | select(.outcome != "http-error") | .n] | add // 0),
    wrong_status: ([.statuses[] | select(.status != 502) | .n] | add // 0)
  }
] as $fault_groups |
[$fault_groups[] | select(.wrong_outcome > 0 or .wrong_status > 0) | {driver_index, phase, route, operation, wrong_outcome, wrong_status}] as $fault_mismatches |

[$slots[] as $d |
  ([$groups[] | select(.driver_index == $d and .route == "iam" and .phase == "baseline")][0]) as $base |
  $groups[] | select(.driver_index == $d and .route == "iam" and .phase != "baseline") | . as $o |
  {
    driver_index: $d,
    phase: $o.phase,
    route: "iam",
    n: $o.n,
    p95_ms: p95($o.success_latencies_ms),
    p99_ms: p99($o.success_latencies_ms),
    p95_limit_ms: limit(p95($base.success_latencies_ms); 1.25; 25),
    p99_limit_ms: limit(p99($base.success_latencies_ms); 1.5; 50),
    pass: (if $base == null or ($base.success_latencies_ms | length) == 0 or ($o.success_latencies_ms | length) == 0 then null
           else (p95($o.success_latencies_ms) <= limit(p95($base.success_latencies_ms); 1.25; 25)
                 and p99($o.success_latencies_ms) <= limit(p99($base.success_latencies_ms); 1.5; 50)) end)
  }
] as $comparisons |

[$groups[] | select(.route == "api-key" and .operation == "account") |
  {driver_index, phase, route, operation, n, p95_ms: p95(.success_latencies_ms), p99_ms: p99(.success_latencies_ms), comparison: "no-baseline"}
] as $account_groups |

(if ($comparisons | length) == 0 then "inconclusive"
 elif [$comparisons[] | select(.pass == false)] | length > 0 then "fail"
 elif [$comparisons[] | select(.pass == null)] | length > 0 then "inconclusive"
 else "pass" end) as $performance_status |

($samp | group_by([.pod_index, .container])) as $series |
[$series[] | {
  pod_index: .[0].pod_index,
  container: .[0].container,
  samples: length,
  first_timestamp: (map(.hostTimestampUTC) | sort | .[0]),
  last_timestamp: (map(.hostTimestampUTC) | sort | .[-1]),
  peak_working_set_bytes: (map(.memoryWorkingSetBytes) | max),
  peak_rss_bytes: (map(.memoryRSSBytes) | map(select(. != null)) | if length == 0 then null else max end),
  peak_cpu_nano: (map(.cpuUsageCoreNanoSeconds) | max),
  working_set_range_bytes: ((map(.memoryWorkingSetBytes) | sort | .[-1]) - (map(.memoryWorkingSetBytes) | sort | .[0])),
  unavailable: (group_by(.unavailable) | map({reasons: .[0].unavailable, n: length})),
  cfs_periods: cfs_delta("cpuCfsPeriodsTotal"),
  cfs_throttled_periods: cfs_delta("cpuCfsThrottledPeriodsTotal"),
  cfs_throttled_seconds: cfs_delta("cpuCfsThrottledSecondsTotal"),
  cfs_unavailable: (group_by(.cpuCfsUnavailable // []) | map({reasons: .[0].cpuCfsUnavailable, n: length}))
}] as $resource_series |

([$samp[] | .unavailable[]? | select(. != "rss-not-exposed")] | length) as $unavailable_non_rss |

[$fix[] | . as $f |
  [fixture_expected | to_entries[] | . as $e |
    ($f.metrics[$e.key] // null) as $m |
    {
      route: $e.key,
      expected_started: $e.value,
      observed_started: ($m.started // null),
      count_ok: ($m != null and $m.started == $e.value),
      drained: ($m != null and $m.completed == $m.started and $m.active == 0),
      complete: ($m != null and $m.started == $e.value and $m.completed == $m.started and $m.active == 0)
    }
  ] as $routes |
  {index: $f.index, routes: $routes, complete: ($routes | all(.complete))}
] as $fixture_check |
[$fixture_check[] | select(.complete | not) | {index, routes: [.routes[] | select(.complete | not)]}] as $fixture_mismatches |
($fixture_check | all(.complete)) as $fixture_complete |
($protected_errors != 0 or ($denom_incomplete | length) > 0 or ($denom_excess | length) > 0 or ($unexpected_groups | length) > 0 or ($fixture_complete | not) or ($fault_mismatches | length) > 0) as $correctness_fail |

{
  started: ([$fix[].metrics | to_entries[].value.started] | add),
  completed: ([$fix[].metrics | to_entries[].value.completed] | add),
  active: ([$fix[].metrics | to_entries[].value.active] | add),
  drain: ([$fix[] | .metrics | to_entries | all(.value.active == 0 and .value.completed == .value.started)] | all)
} as $fixture_aggregate |

{
  schema_version: 1,
  analyzer: "scripts/summarize-e2e-kind-saas-isolation-113.sh",
  diagnostic_directory_basename: ($dir | split("/") | last),
  inputs: {
    observation_records: $obs_n,
    drivers: [$drivers[]],
    driver_attribution: (if $attributed then "per-driver-log" else "unattributed" end),
    expected_drivers: [0, 1, 2],
    sample_rows: ($samp | length),
    sample_timestamps: ($samp | map(.hostTimestampUTC) | unique | length),
    series_count: ($resource_series | length),
    fixture_metrics_files: ($fix | length)
  },
  denominators: {
    per_driver: $denom,
    complete: (($denom_incomplete | length) == 0 and ($denom_excess | length) == 0),
    incomplete: [$denom_incomplete[] | {driver_index, phase, route, operation, expected, observed}],
    excess: [$denom_excess[] | {driver_index, phase, route, operation, expected, observed}],
    unexpected_groups: $unexpected_groups
  },
  duplicate_detection: {
    iam_schedule_unique: true,
    resource_sample_keys: true,
    api_records: "api-key observations carry no scheduled_unix_ms; identical legitimate API observations are not distinguishable and are never deduplicated; excess API counts are rejected by the denominator check"
  },
  groups: $groups_output,
  protected: {
    criterion: "zero protected errors (iam and api-key account)",
    errors: $protected_errors,
    groups: $protected_groups,
    status: (if $protected_errors == 0 then "pass" else "fail" end)
  },
  fault_routes: {
    expected_status: 502,
    groups: $fault_groups,
    mismatches: $fault_mismatches,
    status: (if ($fault_mismatches | length) == 0 then "pass" else "fail" end)
  },
  performance: {
    criterion: {
      name: "local_relative_p95_p99",
      status: "local_approved",
      calibration: "deferred_to_ci",
      p95_factor: 1.25,
      p95_offset_ms: 25,
      p99_factor: 1.5,
      p99_offset_ms: 50
    },
    comparisons: $comparisons,
    account_descriptive: $account_groups,
    status: $performance_status
  },
  resources: {
    ceiling: {status: "missing", result: "inconclusive", reason: "no approved local resource ceiling; capacity/resource qualification not established"},
    series: $resource_series,
    evidence: {unavailable_non_rss_count: $unavailable_non_rss, complete: ($unavailable_non_rss == 0)}
  },
  fixture: {per_index: $fixture_check, aggregate: $fixture_aggregate, complete: $fixture_complete, mismatches: $fixture_mismatches},
  iam_stages: {
    stage_outcomes: $stage_outcome_groups,
    timeout_n: $stage_timeout_n,
    coverage: $stage_coverage,
    attempt_coverage: $attempt_stage_coverage,
    complete: (($stage_coverage | all(.stage_observations > 0 or .iam_attempts == 0))
              and ($attempt_stage_coverage | all(.stage_n > 0))
              and ($unmatched_stages == 0)),
    attempt_complete: ($attempt_stage_coverage | all(.stage_n > 0)),
    note: "per-HTTP-leg stage observations; missing stage evidence is reported as missing, never as zero"
  },
  small_sample: {
    min_group_n: ([$groups[].n] | min),
    threshold: 16,
    small: (([$groups[].n] | min) < 16),
    note: "nearest-rank p95/p99 at small n are extreme samples, not stable tail estimates"
  },
  overall: {
    correctness: (if $correctness_fail then "fail" else "pass" end),
    performance: $performance_status,
    resource_ceiling: "inconclusive",
    status: (if $correctness_fail then "fail"
             elif $performance_status == "fail" then "fail"
             else "inconclusive" end),
    issue_closure: false,
    admission: "none",
    reason: "resource ceiling missing; latency calibration deferred to CI; no issue closure or admission granted"
  }
}
