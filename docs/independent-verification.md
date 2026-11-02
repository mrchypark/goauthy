# Independent local verification

Use this GoAuthy-only disposable run for local verification and CI. It targets
the login journey, open registration, and admin session flow against fresh
single-node fixtures.

## Commands

```sh
sh scripts/verify-isolated.sh --check
GOAUTHY_ISOLATED_E2E_SLOT=granted sh scripts/verify-isolated.sh --run
```

`--check` verifies that `go`, `curl`, `nc`, and Chrome are available, checks
required source files, and parses shell syntax. It does not build GoAuthy,
start listeners, launch a browser, or create the application fixture.

`--run` requires `GOAUTHY_ISOLATED_E2E_SLOT=granted`. Each child harness gets a
clean environment. CI invokes the same `--run` command with the slot grant.

## Fixture isolation

All services bind to loopback and use reserved ports:

| Scenario | Ports | Services |
| --- | --- | --- |
| Login journey | 19380–19381 | GoAuthy and demo app |
| Open registration | 19400–19402 | GoAuthy and disposable SMTP sink |
| Admin journey | 19410 | GoAuthy |

The runner uses private temporary directories for fresh DataDirs, synthetic
identities and credentials, keys, SMTP state, and logs. It must fail if a
reserved port is occupied. It tracks and stops only children it starts, releases
its own port locks, and removes fixture data during cleanup. Failure diagnostics
must stay restricted and sanitized; never retain credentials, cookies, message
contents, or user records.

The three component harnesses have different setup interfaces. Invoke the root
runner for this verification scope; do not enable their optional consumer
profiles. The runner clears the inherited environment per child and passes only
the inputs required by that scenario.

## Scope

A pass covers only these named GoAuthy scenarios on disposable local fixtures.
It does not qualify consumer applications, Kubernetes, operators, HA or
distributed fencing, live cloud storage, production records, or cross-version
archive restore. A local filesystem owner lock does not fence a writer on
another host. Treat the CI result as applying to the exact commit tested by that
run.
