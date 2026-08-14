# CLAUDE.md — THE RAW BUILD (weekly team competition)

This project runs a recurring weekly competition for a Workday Extend PMD development team:
**THE RAW BUILD** — a solo, no-AI, timed speed-build where each person recreates a small target UI
mockup as a real `.pmd` page, judged against a rubric, with a running leaderboard across weeks.

This file is the only memory this project has between sessions — each week is a fresh Claude Code
chat with no recollection of prior weeks except what's written here and in the files below. Read
`LEADERBOARD.md` before doing anything else in any session.

## Format (fixed every week — don't change without the organizer asking)

- **No AI tools during the build.** No Claude, Copilot, ChatGPT, or similar — for code, layout, or
  debugging. Official Workday docs, this project's own files, and personal notes are fair game.
- **Solo, one file.** Each participant builds a single `.pmd` view page.
- **Self-contained task — no live business object, no endpoints.** Every value in the target mockup
  is hardcoded. Nobody should ever be blocked on Studio provisioning during the clock.
- **Timed.** 30, 45, or 60 minutes, organizer's call on the day — the brief's countdown timer has all
  three as presets.
- **Judged live**, right after time's up, against the rubric below, by comparing each person's Studio
  Preview to the target mockup.

## Weekly workflow — what to do when this project is opened

1. **Read `LEADERBOARD.md`.** It's the full history — who's played, cumulative scores, current streaks.
2. **Design this week's task.** A new small PMD UI mockup, different from every prior week (check
   `/tasks/` for what's already been used). Keep it solvable in the chosen time box by someone who
   knows the platform, and keep it self-contained (no BO/endpoint). Vary the widget vocabulary being
   tested week to week — see "Task rotation" below for a starting list and how to escalate difficulty.
3. **Write the answer key**: `/tasks/week-NN-<slug>.pmd`, a real, valid, self-contained `.pmd` file.
   Validate it parses (`node -e "JSON.parse(require('fs').readFileSync('path','utf8'))"`) and that it's
   actually buildable solo in the time box — if unsure, build it yourself first as a sanity check.
4. **Update the brief artifact**: `/briefs/week-NN-brief.html`. Reuse the exact design system from
   `/briefs/_template.html` (see "Design system" below) — swap in only this week's mockup, rules text
   if changed, and the week number/date. Do **not** redesign the visual identity each week; the point
   of a recurring competition is that it's recognizably the same show every time.
5. **Publish the brief** as an Artifact so the organizer can project it live.
6. **After the round**, when the organizer reports each participant's score (or you're asked to score
   entries against the rubric yourself), update `LEADERBOARD.md`:
   - Add this week's column with each participant's total (0–100) and a one-line note on what they
     missed, for their own reference.
   - Recompute cumulative totals and rank.
   - Update any streak badges (see leaderboard format below).
7. **Publish/update the leaderboard artifact** (`/briefs/leaderboard.html`) from the same design system,
   so there's a shareable, always-current standings page.

## Scoring rubric — 100 pts (reuse unless the organizer changes it)

| Criterion | Points |
|---|---|
| Right widget for the job (e.g. `fieldSet` vs. plain `section`, `checkBox`, `grid`) | 40 |
| Layout matches (column arrangement, label position, grouping) | 20 |
| Data matches the target exactly | 15 |
| Any grid/list renders correctly (rows, columns, cell values) | 15 |
| Finished, page loads clean, before time's up | 10 |

Adjust the weighting only if a week's task genuinely doesn't exercise one of these dimensions (e.g. a
task with no grid at all) — redistribute those points into the others and note the change in that
week's brief.

## Task rotation — widen and escalate over time

Week 1 was a "Team Member Card" (fieldSet + 2-column aside-label fields, checkBox list, static grid).
Don't repeat a prior week's exact task. Rotate the *widget/skill focus* being tested, and gradually
raise difficulty as the group's floor rises:

- **Easy** (weeks 1–4): single fieldSet, static text/number fields, one checkBox group, one small grid.
- **Medium** (weeks 5–8): add a `dropdown` (real `selectedValues`/`instanceList` shape), a second
  fieldSet with two-column layout, a grid with a computed/derived column (still static input data, but
  the cell does simple math or string logic).
- **Harder** (weeks 9+): multiple `tabs`, an `instanceList`-as-link cell, conditional `visible` logic
  on a field or tab, a small script function the participant has to write themselves (e.g. a status
  label derived from two fields).

Never require a live business object or endpoint, even at the harder tiers — keep every task buildable
and judgeable offline, in Preview, with zero backend dependency.

## Design system (keep consistent across every brief and the leaderboard page)

Token values, carried over from the first brief — reuse verbatim:

- **Color** — light: paper `#f2f4f1`, raised surface `#ffffff`, ink `#1b2430`, ink-soft `#4a5568`,
  hairline `rgba(27,36,48,.14)`; accent (timer/urgency) `#d98a1f`; secondary structural accent (teal)
  `#257a70`; semantic good `#2f7d4f` / bad `#b23b2e` for status pills only, never as the accent.
  Dark mode swaps to paper `#171b22`, raised `#1f242e`, ink `#eef1f5`, accent `#f2a93b`, teal `#59b3a6`
  — full token set is in `/briefs/_template.html`, follow the `:root` / `prefers-color-scheme` /
  `[data-theme]` pattern already there for both themes.
- **Type** — display/headings: `"Arial Black", Arial, sans-serif`, weight 900, tight tracking. Body:
  `"Segoe UI", -apple-system, sans-serif`. Data/mono (timer, scores, mockup field values):
  `"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace` with `font-variant-numeric:
  tabular-nums`.
- **Layout** — a single-column vertical brief: masthead (event name + one-line pitch + rule chips) →
  countdown timer card → two-column rules/scoring cards → the week's mockup rendered inside a
  PMD-styled mock panel (bordered fieldSets, aside labels, matching how the real Workday Extend pages
  actually look) → footer.

Keep `/briefs/_template.html` as the canonical copy of this system (masthead, timer, rubric cards,
footer, all CSS) with a placeholder mockup section — each week's brief is a copy of it with only the
mockup panel and week number swapped in.

## Leaderboard format (`LEADERBOARD.md`)

A markdown table, most recent week as the rightmost column, ranked by cumulative total descending:

```
| Rank | Name | Wk1 | Wk2 | Wk3 | ... | Total | Streak |
|---|---|---|---|---|---|---|---|
| 1 | Priya F. | 88 | 92 | 95 | | 275 | 🔥3 |
| 2 | ... | | | | | | |
```

- **Streak** = consecutive weeks scoring 80+. Reset to 0 on a week below 80, or if they miss a week.
- If someone misses a week, leave that week's cell blank — don't zero it — and don't count it against
  their streak either way (treat a bye as neutral, not a break).
- Keep a one-line "Notes" append under the table per week (e.g. "Wk4: introduced dropdown widget,
  three people hadn't used one before — worth a 5-min refresher next time") — this is the project's
  only running memory of what's actually working, so use it.

## Folder structure

```
/CLAUDE.md
/LEADERBOARD.md
/tasks/
  week-01-team-member-card.pmd
  week-02-<slug>.pmd
/briefs/
  _template.html
  week-01-brief.html
  week-02-brief.html
  leaderboard.html
```

## Enforcing "no AI"

There's no technical enforcement here — it's honor system plus in-person supervision. Don't try to
build detection logic into the brief; it isn't the artifact's job. If the organizer asks for ideas here,
suggest lightweight social ones (screens visible, phones away) rather than anything technical.
