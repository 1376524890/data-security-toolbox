# nuclei (third-party binary, baked into the analysis-worker image)

The worker drives `nuclei` for the active network-scan pipeline. It used to be
downloaded from GitHub on **every** image build, which made builds depend on that
network path (and hang when GitHub was slow or blocked). The archive now ships in
the build context and the image installs it with no network access at all.

## One-time fetch per build machine

```bash
python scripts/fetch_third_party.py          # amd64 + arm64
```

It writes `nuclei_<version>_linux_<arch>.zip` here and records each SHA256 in
`SHA256SUMS`; later runs verify the digest instead of trusting the file. The
`.zip` files are not committed (they are large binaries) — fetch them once on the
build machine, and carry them in the offline release bundle so an air-gapped
packaging host can rebuild the images too.

## What the image does

`backend/Dockerfile` copies this directory and installs the archive matching the
image's architecture, then deletes the copy. If the file is missing the build
fails with a pointer back to the fetch script, instead of silently reaching out
to GitHub.

Either form is accepted, matched to the image architecture:

| File | How it is obtained |
| --- | --- |
| `nuclei_<version>_linux_<arch>.zip` | `scripts/fetch_third_party.py` |
| `nuclei_<arch>` (raw executable) | copied out of a worker image that already has it: `docker cp <container>:/usr/local/bin/nuclei .` |

A zip is only used when it passes `unzip -t`, so a half-written download can never
be baked in.

## Version

`NUCLEI_VERSION` is pinned in both `scripts/fetch_third_party.py` and the
Dockerfile; keep them in step and re-run the fetch when the version moves.
