def runtime_digest:
	sub("^(containerd|docker-pullable)://"; "")
	| if contains("@sha256:") then sub("^.*@"; "") else . end;
def strict_digest:
	if (type) == "string" and (test("^sha256:[0-9a-f]{64}$")) then . else "invalid" end;
def valid_node_pins:
  ($node_pins | type) == "object"
  and ($node_pins.config_digest | strict_digest) != "invalid"
  and ($node_pins.runtime_digests | type) == "array"
  and (all($node_pins.runtime_digests[]; (. | strict_digest) != "invalid"));
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
| if valid_node_pins
  and $node_pins.config_digest == $config
  and ($pins | length) == $count
  and ([$pins[].pod] | unique | length) == $count
  and all($pins[]; .image == $ref and ((.imageID | runtime_digest) == $manifest or (.imageID | runtime_digest) == $config or (.imageID | runtime_digest | IN($node_pins.runtime_digests[]))))
  then $pins
  else error(
    "helper image runtime pin mismatch: "
    + "expected_count=\($count) observed_count=\($pins | length) "
    + "ref_matches=\([$pins[] | .image == $ref]) "
    + "observed_digests=\([$pins[] | ((.imageID // "") | runtime_digest | strict_digest)])"
  )
  end
