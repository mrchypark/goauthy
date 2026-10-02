# Local OAuth consumer verification — 2026-10-02

These isolated local runs exercised the Beesuh OAuth adapter and the Conductor credential-delivery handler against GoAuthy. They record focused consumer evidence, not a release gate, issue acceptance, or production deployment claim. The underlying task-state receipts and command logs are the detailed evidence records.

## Pinned inputs

| Component | Source pin |
| --- | --- |
| GoAuthy | `b80c6a2e44ef630a27cefba54596a1a9d88d9ffd` (tree `b15d640f2ef4abbed04ff26e4d86ee5b4df360e5`) |
| Beesuh | `105d47f8a069f9060fa6aa3450e3f0164bde08f1` (tree `4b17a00de125965f5052747ee1d473967163e833`) |
| Conductor | `2be6e6d7bac94e42dfe4a4e907ee785c8f9dcee1` |
| Gowid SDK | `e939fc41d3d4e6a6bfabf5dfec57bceb2442a8b3` (the pinned Conductor dependency revision) |
| Rhiza | `github.com/mrchypark/rhiza@v0.18.0`, source commit `ff38548cd9561f27dd474a1151f0c6dd5da79b9b` |

The GoAuthy test base image was `sha256:c21be540223e3f32e8d488a75006a671c7ca4af3e3d501990a84caeb86a219d6`. The Beesuh candidate image was `sha256:9884b81ee05a6f48023228a57d9439ce9a070ae697fa8eb6ed9569f56830aac8`; the Conductor candidate image was `sha256:60ae000f6d665c395f56758e0f29c8b5579b87ac0cf0099bc7dac73b157f0fec`.

## Results

The existing `TestConnectionOAuth2RegisteredSuccess` ordinary-HTTP flow passed for Beesuh before and after a GoAuthy restart. Its consumer checkpoints reported two synthetic model calls for each allowed delivery and zero for denied/revoked delivery. Refresh was explicitly initiated by the owner flow.

The same existing GoAuthy HTTP flow passed with the Conductor overlay and active restart enabled. It spawned a separate Conductor test-binary process. Across four allowed checkpoints—including the refresh from credential version 1 to 2 and checks across restarts—the actual GoAuthy credential endpoint returned `[200 200]` and Conductor made two synthetic provider calls per checkpoint. The revoked checkpoint returned `[404 404]` and made zero provider calls. `TestConnectionOAuth2RegisteredSuccess` passed in 2.73s.

The Conductor binary exercised its production credential handler and `/v1/executions` route through `ServeHTTP` in-process. It was a separate process from the GoAuthy HTTP service, but it was not a listening Conductor daemon test.

The Conductor candidate was run with networking disabled and no host mounts or published ports:

```sh
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges --add-host oauth-provider.e2e.test:8.8.8.8 -e GOAUTHY_E2E_OAUTH2_GRANT_UI=0 -e GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART=1 goauthy-conductor-oauth-e2e:candidate
```

The Beesuh candidate used the same isolation settings with `-e GOAUTHY_E2E_OAUTH2_GRANT_UI=0` and image `goauthy-beesuh-oauth-e2e:candidate`.

## Limits

Both runs used synthetic local OAuth/provider fixtures and static human-token fixtures; they made no real SaaS calls and did not verify a graphical consumer UI. Refresh was explicitly initiated by the owner flow; no adapter-owned scheduler, automatic refresh, or background recall was tested. The Conductor HTTP handler test server used in-process `ServeHTTP`, not a listening Conductor daemon. These local runs do not establish production readiness, provider-side revocation, credential recall/replay behavior, or completion of any issue or release gate.
