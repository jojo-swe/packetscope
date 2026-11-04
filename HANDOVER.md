# HANDOVER.md

Överlämning mellan agenter och sessioner. Läs innan du börjar, uppdatera innan du slutar.

## Aktuellt läge

*Senast inventerat 2026-11-04 av Claude (Cowork).*

Projekt: PacketScope turns portable JSON, JSONL, or NDJSON flow records into explainable network findings.

- Huvudbranch: `main`
- Senaste commit på `main`: 2026-11-01 `4d53de0` Add privacy-guard scan for the checked-out tree (#2)
- Öppna PR:er: 0
- Andra brancher på remote: 2

## Pågående arbete

| Agent/vem | Branch | Status | Beskrivning |
|-----------|--------|--------|-------------|
| Cursor | `cursor/privacy-guard-kit-3680` | branch utan PR, senaste commit 2026-11-01 | Add privacy-guard scan for the checked-out tree |
| okänd (människa/agent) | `agent/explainable-flow-analysis` | branch utan PR, senaste commit 2026-07-18 | Validate PacketScope CLI in CI |

## Nästa steg

- Gå igenom brancher utan PR: öppna PR, merga eller radera (fråga användaren innan radering).
- Fyll på "Bygga och testa" i AGENTS.md om något saknas eller är fel.

## Kända problem

- Inga dokumenterade ännu.

## Senaste commits

- 2026-11-01 `4d53de0` Add privacy-guard scan for the checked-out tree (#2)
- 2026-10-26 `ce3e7b7` docs: add AGENTS.md with layout, commands and conventions
- 2026-10-26 `87909f9` docs: document thresholds, input fields, limitations and dev setup
- 2026-10-26 `5a98fde` chore: add Apache-2.0 LICENSE file
- 2026-10-26 `e26c92e` feat: add deny_fanout finding for denied flows spread across targets
- 2026-10-26 `15fb7f9` feat: read flows from stdin and detect format by content
- 2026-10-26 `57ff41c` test: cover CLI exit codes and JSONL loading
- 2026-10-26 `68ecdf5` fix: repair broken summary test and pin ruff rule set
- 2026-07-18 `6a3ca15` Merge pull request #1 from jojo-swe/agent/explainable-flow-analysis
- 2026-07-18 `949552d` Validate PacketScope CLI in CI

## Logg

| Datum | Agent | Vad som gjordes |
|-------|-------|-----------------|
| 2026-11-04 | Claude (Cowork) | Lade till AGENTS.md, HANDOVER.md och CLAUDE.md; inventerade PR:er, brancher och commits. |
