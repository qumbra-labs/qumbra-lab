# Offline validation for the explorer image's provenance readback

Covers the `Read the provenance back from the registry` step of
[`../../explorer-image.yml`](../../explorer-image.yml). Run it:

```sh
.github/workflows/tests/explorer-provenance/run.sh
```

Needs `jq`. No docker, no network, no registry credential, no CI minutes — it is
**not wired into any workflow** and costs nothing until someone runs it.

## Why an offline test and not just a CI run

The step it covers lives in the `image` job, which runs only on the paid
`qumbra-arm64-8` runner (~$0.7/run against a $20/month cap,
`docs/ci-runner-cost-decision.md` §4) and only after a full build+push. So the
step can be exercised *only* by spending the thing the workflow header exists to
ration. Lab #428 — the bug these fixtures pin — was a readback that reported red
after a genuinely-good, correctly-labelled publish; testing its fix by spending
another paid build would have been the wrong trade.

## The bug, so nobody reintroduces it

The step used to read the label with

```sh
grep -o '"org.opencontainers.image.revision":"[0-9a-f]*"'
```

`docker buildx imagetools inspect --format '{{json .Image}}'` renders through
`json.MarshalIndent`, so the real bytes are `"...revision": "<sha>"` — **with a
space after the colon**, two-space indented and newline-wrapped. The pattern
matched nothing, exited 1, and `set -o pipefail` carried that through
`| head | sed` and failed the step.

Two details worth keeping, because the obvious reading of that failure is wrong:

- **`-e` was not what failed it.** `grep` was not the last command in the
  pipeline, so `-e` only ever saw `sed`'s `0`. `pipefail` is the mechanism.
- **The roll-note never printed**, because the pipeline died before it. The one
  output an operator actually needed was the one the bug ate.

`run.sh` reproduces both directions: the old pattern finding nothing on a good
image, and the new reader returning the right sha on the same bytes.

## The two shapes of `.Image`

Which shape arrives is a property of the runner's image store, not of this repo,
so the reader handles both. Both fixtures are **real captured output**:

| fixture | shape | label path |
|---|---|---|
| `real-single-platform.json` | one config object | `.config.Labels[...]` |
| `real-multi-platform.json` | map keyed by platform | `.["linux/arm64"].config.Labels[...]` |

Captured with `docker buildx imagetools inspect <ref> --format '{{json .Image}}'`
against `ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector`
— a public, GitHub-Actions-built image carrying real OCI provenance labels — on
2026-08-16. The single-platform file is that image's `linux/arm64` manifest
digest; the multi-platform file is its index.

A reader pinned to `.config.Labels` alone returns empty against the map and would
red a good push all over again, one layer further in. The step uses recursive
descent, which reads either and also absorbs the `.Config` casing some buildx
versions emit (`synthetic-capital-config.json`).

The `synthetic-*.json` fixtures cover what a public registry cannot supply on
demand: a missing label, a wrong revision, an abbreviated one, and two platforms
disagreeing with each other.

## Keeping this honest

`run.sh` carries a **copy** of the workflow's jq program, and a copy that
silently diverges is worse than no test — so `test_workflow_pin` fails if
`explorer-image.yml` no longer contains that exact program. There is also a
mutation check (`good-image-wrong-expect`): the same good fixture against a wrong
expectation must fail, or the assertion is decorative.
