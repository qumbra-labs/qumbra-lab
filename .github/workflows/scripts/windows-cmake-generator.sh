#!/usr/bin/env bash
# Export CMAKE_GENERATOR for the randomx-rs C++ build on a Windows runner
# (lab #478). Shared by `windows-x86_64.yml` and `release-binaries.yml`'s windows
# leg, because two copies of this would drift — the same reason
# `assert-release-artifacts.sh` is a file (see its header, and lab #428).
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY IT EXISTS
#
# `randomx-rs`'s build script drives cmake through the `cmake` crate, which
# refuses to guess a generator it does not recognise and panics with "couldn't
# determine visual studio generator". That panic surfaces from inside a
# dependency's build script, which is the worst place for it: it reads as a Rust
# problem and it names nothing actionable. This step's job is to make that case
# say what is wrong, out here, before a single crate compiles.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY IT IS DERIVED AND NOT A HARDCODED MAP — a dated finding, run 32096791616
#
# The first version of this step carried `17 -> "Visual Studio 17 2022"` and a
# `16` arm, and failed the leg on anything else. It fired immediately:
# **`windows-latest` ships Visual Studio 18 (`18.8.12023.21`) as of 2026-08-18.**
# The map was already stale on the first run it ever made.
#
# It was also wrong to fail: the pinned `cmake` crate (0.1.58) knows
# `VsVers::Vs18 => "Visual Studio 18 2026"`, so that build would have worked on
# its own. A hardcoded map here turned a working configuration red.
#
# So the name now comes from **CMake's own generator list**, intersected with the
# **installed** VS major from `vswhere`. That is strictly better than any map,
# including the `cmake` crate's compiled-in one, because CMake itself has to
# support the generator regardless — and it needs no maintenance when the runner
# image moves again, which it will.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY IT WARNS INSTEAD OF FAILING
#
# If discovery comes up empty, `CMAKE_GENERATOR` is left unset and the `cmake`
# crate falls back to its own map — which, as above, is current. An aid that
# blocks the build when it cannot help is worse than no aid. The warning is
# loud, names the two versions it saw, and tells the next reader that a
# "couldn't determine visual studio generator" panic below this line is the case
# this step failed to prevent rather than a new mystery.
set -euo pipefail

VSWHERE="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
CMAKE_V="$(cmake --version 2>/dev/null | sed -n 1p || true)"
echo "cmake: ${CMAKE_V:-(not found)}"

if [ ! -x "$VSWHERE" ]; then
  echo "::warning::vswhere.exe is not at the documented path on this image, so the Visual Studio version could not be read. Leaving CMAKE_GENERATOR unset and letting the \`cmake\` crate decide. If randomx-rs's build script now panics with 'couldn't determine visual studio generator', THIS is the step that failed to prevent it."
  exit 0
fi

VER="$("$VSWHERE" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion 2>/dev/null || true)"
MAJOR="${VER%%.*}"
echo "visual studio: ${VER:-(none found)} (major ${MAJOR:-?})"

GEN=""
if [ -n "$MAJOR" ]; then
  # CMake's own list is the authority on the exact generator string. The
  # descriptions in `cmake --help` say things like "Generates Visual Studio 2026
  # project files", which this pattern cannot match — it requires the major
  # number AND a year, which only the generator names carry.
  GEN="$(cmake --help 2>/dev/null | grep -oE "Visual Studio ${MAJOR} [0-9]{4}" | head -n 1 || true)"
fi

if [ -z "$GEN" ]; then
  echo "::warning::could not derive a generator: Visual Studio major '${MAJOR:-?}' has no matching \"Visual Studio N <year>\" entry in this image's cmake (${CMAKE_V:-unknown}). Leaving CMAKE_GENERATOR unset so the \`cmake\` crate's own map still gets a turn. A 'couldn't determine visual studio generator' panic below this line means both have run out of ideas — the fix is a newer cmake on the runner, or pinning an older windows image."
  echo "--- Visual Studio generators this cmake knows ---"
  cmake --help 2>/dev/null | grep -E "Visual Studio [0-9]+ [0-9]{4}" || echo "(none)"
  exit 0
fi

echo "CMAKE_GENERATOR=$GEN" >> "$GITHUB_ENV"
echo "cmake generator: $GEN"
