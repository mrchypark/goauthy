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

The stage supervisor is a standard-library Go helper. Its launcher keys the
cache by SHA-256 of the helper source, module file, selected Go version, and
effective host target at
`~/.cache/goauthy-stage-supervisor/<OS>-<architecture>-<digest>/supervisor`.
`--check` does not build or populate this cache; `--run` prepares the helper
before starting any application fixture. Preparation removes its temporary
build directory on success. The digest-keyed binary remains cached until that
entry is removed; this is a local build artifact, not an always-on service or
deployment resource.

Each stage runs in a newly created process group whose positive PGID is verified
before use. Root `TERM` targets only the active controller and waits up to 90
seconds; it does not kill the controller. The controller sends `TERM` only to
its owned stage group and waits up to 75 seconds for group absence. If the group
remains, it sends `KILL` to that group and checks for absence for up to five
seconds. The controller waits for its direct child; group absence is the
descendant-cleanup check. It never signals a pre-existing or foreign group. If
the root cannot confirm the controller stopped, or the controller cannot
confirm group absence, the runner reports this and preserves private fixture
data.

The runner uses a private temporary directory for fresh DataDirs, synthetic
identities and credentials, keys, SMTP state, and stage logs. On normal
completion, child harnesses remove their temporary application data and keys;
the runner releases its port locks and removes the run directory, including
stage logs. On failure, raw synthetic-fixture logs are retained in a private
directory (mode 0700; log files mode 0600) and are not uploaded as CI artifacts.
They are not sanitized. If a child reports incomplete fixture cleanup, its
private fixture directory may also remain for investigation. Use only synthetic
identities and data; never use real credentials, messages, or user records in
this run. The runner provisions no always-on resources.

The three component harnesses have different setup interfaces. Invoke the root
runner for this verification scope; do not enable their optional consumer
profiles. The runner clears the inherited environment per child and passes only
the inputs required by that scenario.

## Scope

A pass covers only these named GoAuthy scenarios on disposable local fixtures.
It does not qualify consumer applications, Kubernetes, operators, HA or
distributed fencing, live cloud storage, production records, or cross-version
archive restore. A local filesystem owner lock does not fence a writer on
another host. A child that deliberately creates a new process group or session
can escape containment; `SIGKILL` of the controller or root bypasses cooperative
cleanup. Treat the CI result as applying to the exact commit tested by that run.
