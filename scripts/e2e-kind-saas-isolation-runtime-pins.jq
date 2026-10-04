def runtime_digest:
	sub("^(containerd|docker-pullable)://"; "")
	| if contains("@sha256:") then sub("^.*@"; "") else . end;
def strict_digest:
	if (type) == "string" and (test("^sha256:[0-9a-f]{64}$")) then . else "invalid" end;
[
	.items[] as $pod
	| $pod.status.containerStatuses[]?
	| select(.name == $container) as $status
	| {
		pod: $pod.metadata.name,
		image: ([$pod.spec.containers[] | select(.name == $container) | .image][0]),
		imageID: $status.imageID
	}
] as $pins
| if ($pins | length) == $count
	and ([$pins[].pod] | unique | length) == $count
	and all($pins[]; .image == $ref and ((.imageID | runtime_digest) == $manifest or (.imageID | runtime_digest) == $config))
  then $pins
  else error(
    "helper image runtime pin mismatch: "
    + "expected_count=\($count) observed_count=\($pins | length) "
    + "ref_matches=\([$pins[] | .image == $ref]) "
    + "observed_digests=\([$pins[] | ((.imageID // "") | runtime_digest | strict_digest)])"
  )
  end
