def times:
  map(. / 1000000) | sort | . as $s |
  if length == 0 then null else
  {n:length,p50_ms:$s[((length*0.50)|ceil)-1],p95_ms:$s[((length*0.95)|ceil)-1],p99_ms:$s[((length*0.99)|ceil)-1],max_ms:max} end;
. as $r |
[.attempts | group_by([.Phase,.Route])[] |
 {phase:.[0].Phase,route:.[0].Route,offered:length,
  outcomes:(group_by(.Outcome)|map({outcome:.[0].Outcome,n:length})),
  success:([.[]|select(.Outcome=="success")|.ClientNS]|times),
  scheduling:([.[]|select(.Outcome!="generator-drop" and .Outcome!="schedule-missed")|.DispatchNS-.ScheduledNS]|times),
  client_done_handler_active:([.[]|select(.ClientDoneWhileActive)]|length)}] as $groups |
{mode,go,gomaxprocs,violations:(.violations//[]),attempts:(.attempts|length),groups:$groups,
 protected_comparisons:[$groups[]|select(.phase!="baseline" and (.route=="iam" or (.route|endswith("healthy")))) as $x |
  ($groups[]|select(.phase=="baseline" and .route==$x.route)) as $b |
  {phase:$x.phase,route:$x.route,n:$x.success.n,
   p95_ms:$x.success.p95_ms,p95_limit_ms:([$b.success.p95_ms*1.25,$b.success.p95_ms+25]|max),
   p99_ms:$x.success.p99_ms,p99_limit_ms:([$b.success.p99_ms*1.5,$b.success.p99_ms+50]|max)} |
   .+{pass:(.p95_ms!=null and .p99_ms!=null and .p95_ms<=.p95_limit_ms and .p99_ms<=.p99_limit_ms)}],
 resources:([.samples[]]|{sample_count:length,max_rss_bytes:(map(.RSS)|max),sampled_heap_peak_bytes:(map(.Heap)|max),sampled_goroutine_peak:(map(.Goroutines)|max),sampled_active_handlers_peak:(map(.ActiveHandlers)|max)}),
 cpu_user_ms:(.cpu_user_us/1000),cpu_system_ms:(.cpu_system_us/1000),peak_workflows,final_pools,
 mutations:[.posts|to_entries[]|select(.key|startswith("control-")|not)]|{bindings:length,total:map(.value)|add,max_per_old_version:map(.value)|max},
 durable:(.durable|group_by([.[1],.[2]])|map({state:.[0][1],version:.[0][2],n:length})),
 mixed_refresh:([.durable[]|select(.[0]|startswith("mixed-oauth-"))]|group_by([.[1],.[2]])|map({state:.[0][1],version:.[0][2],n:length}))}
