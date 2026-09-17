.spec.template.spec.volumes
| to_entries | map(select(.value.name == "secrets"))
| if length != 1 then error("expected one secrets volume") else .[0] end
| if .value.secret.secretName != "goauthy-secrets" or (.value.secret.items | type) != "array"
  then error("unexpected secrets projection") else . end
| . as $volume
| "/spec/template/spec/volumes/\(.key)" as $path
| [{op: "test", path: $path, value: $volume.value},
   {op: "add", path: ($path + "/secret/items"),
    value: ($volume.value.secret.items | map(select(.key != "passkey-key")) + [{key: "passkey-key", path: "passkey-key"}])}]
