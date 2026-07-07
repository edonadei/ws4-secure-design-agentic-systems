---
name: fetch-meeting-minutes
description: >-
  Mirror CoSAI meeting minutes into `meeting_minutes/`. Use when the user wants
  to fetch, sync, or refresh meeting notes for WS4, ADLC, WS3, Code-SIG, RM-SIG,
  Agent Credentials, or the TSC — typically before drafting an agenda. Pulls
  Gemini notes from Google Drive via a Drive MCP server and TSC minutes from
  GitHub, written verbatim as markdown.
---

# Fetch CoSAI meeting minutes

You **mirror** remote minutes into the repo: every doc lands **verbatim** — never
summarised, rewritten, reordered, or posted anywhere.

## Connect a Drive MCP first

The Drive sources need a connected **Google Drive MCP server** that can list a
folder's children, search `sharedWithMe`, and export a Google Doc as text. If no
such server is connected, halt and have the user add one before continuing:

```bash
claude mcp add gdrive -- npx -y @modelcontextprotocol/server-gdrive
```

then complete OAuth with the `drive.readonly` scope. Any Drive MCP offering those
three capabilities works; map its tool names onto the actions below. Do not fall
back to any other Drive path — halt and ask.

The TSC source needs only an authenticated `gh` CLI, no Drive access.

## Sources

`(Y)/(M)/(D)` is `YYYY/MM/DD`; the synthetic filename uses the captured
`y`/`m`/`d` (so `WS4 {y}{m}{d}` → `WS4 20260709`).

| Name | Type | Subdir | Folder ID / GitHub path | Shared-with-me title pattern | Synthetic name |
|------|------|--------|--------------------------|------------------------------|----------------|
| WS4 | drive | `ws4` | `1TJl4yqWIdfPc8fKWiTO0CsmsmuecGxWa` | `^CoSAI WS4 recurring meeting - (Y)/(M)/(D) .* Notes by Gemini$` | `WS4 {y}{m}{d}` |
| ADLC | drive | `adlc` | `1EkoOpMCtYahLu-sEhYrgNDmvPyTtgpit` | `^WS4 SIG Security of Agent Development Lifecycle - (Y)/(M)/(D) .* Notes by Gemini$` | `{y}-{m}-{d}` |
| WS3 | drive | `ws3` | `1NFk_-2Plyi3qYr2qtrvt42AQhzJZB0Wf` | _(none — folder walk only)_ | — |
| Code-SIG | drive | `code-sig` | `1yKk-Mbbpowsk3gfRwGIT7UpMOJ-fDzdo` | `^CoSAI WS3 SIG: Security of AI-Assisted Code Development - (Y)/(M)/(D) .* Notes by Gemini$` | `{y}-{m}-{d}` |
| RM-SIG | drive | `rm-sig` | `1tboOFAyYHnJRlXqMO3Kdh6KrcAVVIpiB` | `^CoSAI WS3 CoSAI-RM SIG weekly meeting - (Y)/(M)/(D) .* Notes by Gemini$` | `WS3 CoSAI-RM SIG {y}{m}{d}` |
| Agent-Credentials | drive | `agent-credentials` | `1Telz7CDwCgPNUyHlMwu9cBGl-keqP9z3` | `^CoSAI WS4: Agent Credentials - (Y)/(M)/(D) .* Notes by Gemini$` | `{y}-{m}-{d}` |
| TSC | github | `tsc` | `cosai-oasis/cosai-tsc` → `tsc-meeting-minutes` | — | (repo filename) |

## Run

Write under `meeting_minutes/<subdir>/` relative to the repo root — never a
hard-coded home path — one file per meeting. `--skip-existing` skips any meeting
whose output file already exists; use it for routine refreshes, omit it for a
full re-sync.

Process every source. The run is done only when **every** drive folder and github
file is accounted for — fetched, skipped, or logged as no-notes/error. A single
failed doc never aborts the run.

### Drive — folder walk

1. List meeting subfolders under the source's folder ID (folders, not trashed),
   sorted by name.
2. Filename = folder name with whitespace collapsed to hyphens, plus `.md`
   (`WS4 20260402` → `WS4-20260402.md`). Skip if `--skip-existing` and it exists.
3. Find the notes doc: prefer a Google Doc whose name contains `Notes by Gemini`,
   else any resolvable Doc; resolve a shortcut to its target Doc. None found →
   log as no-notes and move on.
4. Export as markdown and write header + body verbatim:

   ```markdown
   # <folder name>

   **Source:** <doc name>

   ---

   <exported content>
   ```

### Drive — shared-with-me fallback

For each source with a title pattern, catch Gemini notes shared with the user but
not yet filed into a subfolder:

1. Search `sharedWithMe = true`, not trashed, Google Docs whose name contains the
   source's fixed prefix.
2. For each name matching the full pattern, build the synthetic folder name from
   the captured `y`/`m`/`d`, then the same canonical filename step 2 above would
   produce. Skip/export as above, tagging the header source `(via shared-with-me
   fallback)`.

WS3 has no pattern — folder walk only.

### GitHub — TSC

List the repo directory and write each `.md` verbatim to
`meeting_minutes/tsc/<name>` with no header rewrite (honour `--skip-existing`):

```bash
gh api repos/cosai-oasis/cosai-tsc/contents/tsc-meeting-minutes \
  --jq '.[] | select(.type=="file" and (.name|endswith(".md"))) | .name'
```

## Report

Close with a one-line summary, then list every no-notes folder and export error so
the user can chase missing or restricted minutes:

```
Done: <fetched> fetched, <skipped> skipped, <no-notes> without notes, <errors> errors
```

## Failure modes

- **No Drive MCP connected, or unauthorised** — halt with the connect / re-auth
  instruction above; take no other Drive path.
- **`gh` missing or unauthenticated** — skip only the TSC source, note it in the
  report, continue with the Drive sources.
- **A single doc export fails** (e.g. a shortcut into a restricted Drive) — log
  and continue.

## Governance

License CC-BY-4.0. AI-assisted commits use `Co-authored-by: AI Assistant
<ai-assistant@coalitionforsecureai.org>` per the CoSAI vendor-neutral attribution
convention (cosai-oasis/secure-ai-tooling#149).
