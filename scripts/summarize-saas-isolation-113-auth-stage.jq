# Bounded per-pod capture-interval delta summary for the native
# authentication-stage histogram.
#
# Input (built by the companion shell wrapper) is
#   {"pre": [<collector.json>...], "post": [<collector.json>...]}
# where each collector record was already strictly validated against the exact
# goauthy_auth_stage_duration_seconds family and the fixed issue #113 stage
# label set. This analyzer only subtracts cumulative counters between the two
# capture endpoints. It never derives a percentile, an average, or a causal
# claim, and it never attributes latency to a workload phase: the two endpoints
# bound the whole diagnostic interval, so the output is a capture-interval
# delta keyed by timestamp and pod index, not phase alignment evidence.
def allowed_stages: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session"];
def le_key: if . == "+Inf" then 1e300 else (. | tonumber) end;
def bucket_value($buckets; $le): ([$buckets[] | select(.le == $le)][0].value // 0);

$post[0] as $post_all |
$pre[0] as $pre_all |
[ $post_all[] | . as $p |
  ($pre_all[] | select(.pod_index == $p.pod_index)) as $q |
  {
    pod_index: $p.pod_index,
    pre_captured_at_unix_ms: $q.captured_at_unix_ms,
    post_captured_at_unix_ms: $p.captured_at_unix_ms,
    span_ms: ($p.captured_at_unix_ms - $q.captured_at_unix_ms),
    stages: ([ ($p.stages | keys_unsorted[]) as $s |
      ($q.stages[$s] // {count: 0, sum: 0, buckets: {}}) as $ps |
      ($p.stages[$s]) as $qs |
      (($qs.count < $ps.count) or ($qs.sum < $ps.sum)
        or ([ $qs.buckets[] | .le as $le | (.value < (bucket_value($ps.buckets; $le))) ] | any)) as $rst |
      {
        stage: $s,
        count_pre: $ps.count,
        count_post: $qs.count,
        count_delta: (if $rst then null else ($qs.count - $ps.count) end),
        sum_pre: $ps.sum,
        sum_post: $qs.sum,
        sum_delta: (if $rst then null else ($qs.sum - $ps.sum) end),
        reset: $rst,
        buckets: ([ $qs.buckets[] | .le as $le | .value as $post |
          {
            le: $le,
            pre: (bucket_value($ps.buckets; $le)),
            post: $post,
            delta: (if $rst then null else ($post - (bucket_value($ps.buckets; $le))) end)
          } ] | sort_by(.le | le_key))
      }
    ] | sort_by(.stage))
  }
] | sort_by(.pod_index) as $pods |
if ([$pods[].span_ms <= 0] | any) then error("pre and post capture timestamps must differ")
else {
  schema_version: 1,
  available: true,
  family: "goauthy_auth_stage_duration_seconds",
  captured: (any($pods[].stages[]; .count_post > 0)),
  known_stages: allowed_stages,
  observed_stages: ([$pods[].stages[].stage] | unique),
  pods: $pods,
  totals: ([ $pods[].stages[] ] | group_by(.stage) | map(
    {
      stage: .[0].stage,
      reset_any: any(.[]; .reset),
      count_delta: (if any(.[]; .reset) then null else ([.[].count_delta] | add) end),
      sum_delta: (if any(.[]; .reset) then null else ([.[].sum_delta] | add) end)
    }
  )),
  notes: "Per-pod cumulative histogram deltas between the pre-run and post-run native metrics listener captures, bound to the pod index observed through the per-pod port-forward. Only the exact goauthy_auth_stage_duration_seconds family and the fixed eight-stage label set are read. Counts, sums, and bucket deltas are reported with both capture timestamps and the interval span. The two endpoints bound the whole diagnostic interval, so this is capture-interval evidence, not workload-phase alignment, and no percentile, average, or causal claim is derived."
}
end
