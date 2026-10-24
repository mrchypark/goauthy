def median:
  sort as $v
  | if ($v|length) % 2 == 1 then $v[((($v|length)-1)/2|floor)]
    else (($v[(($v|length)/2|floor)-1] + $v[(($v|length)/2|floor)])/2) end;
def range_pair:
  sort as $v | [$v[0], $v[-1]];
def stats($key):
  map(.[$key]) as $v
  | {median: ($v|median), range: ($v|range_pair)};
def status_totals($cells):
  [$cells[].status_codes | to_entries[]]
  | group_by(.key)
  | map({key:.[0].key,value:(map(.value)|add)})
  | from_entries;
def aggregate($runs):
  [$runs[] as $run | $run.cells[] | . + {run: $run.run}]
  | group_by([.stage,.unrelated_records,.concurrency])
  | map(.[0] as $cell
    | {stage:$cell.stage, records:$cell.unrelated_records, concurrency:$cell.concurrency,
       baseline:(map(select(.run|startswith("baseline"))) as $b
         | {p50_ms:($b|stats("p50_ms")),p95_ms:($b|stats("p95_ms")),p99_ms:($b|stats("p99_ms")),rps:($b|stats("requests_per_second")),errors:([$b[].errors]|add),samples:([$b[].samples]|add),profile_resolver_calls:([$b[].profile_resolver_calls]|add),status_codes:status_totals($b),request_body_bytes:([$b[].request_body_bytes]|add),authorization_header_bytes:([$b[].authorization_header_bytes]|add),response_body_bytes:([$b[].response_body_bytes]|add)}),
       fixed:(map(select(.run|startswith("fixed"))) as $f
         | {p50_ms:($f|stats("p50_ms")),p95_ms:($f|stats("p95_ms")),p99_ms:($f|stats("p99_ms")),rps:($f|stats("requests_per_second")),errors:([$f[].errors]|add),samples:([$f[].samples]|add),profile_resolver_calls:([$f[].profile_resolver_calls]|add),status_codes:status_totals($f),request_body_bytes:([$f[].request_body_bytes]|add),authorization_header_bytes:([$f[].authorization_header_bytes]|add),response_body_bytes:([$f[].response_body_bytes]|add)})})
  | sort_by(.stage,.records,.concurrency);
aggregate(.runs)
