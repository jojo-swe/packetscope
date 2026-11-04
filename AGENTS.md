# Working on PacketScope

## Layout

- `src/packetscope/core.py`: heuristics, `Finding`, `analyze`
- `src/packetscope/cli.py`: `load_records`, `render`, `main`
- `tests/`: `test_analysis.py` (heuristics), `test_cli.py` (CLI), `test_core.py` (report shape)
- `examples/incident-flows.json`: bundled example, used by CI as a smoke test
- `.github/workflows/ci.yml`: ruff, pytest and the smoke test on Python 3.11–3.13

## Setup and commands

```bash
pip install -e ".[dev]"
pytest              # pythonpath = ["src"] in pyproject.toml, so no install is strictly needed
ruff check .
packetscope examples/incident-flows.json --fail-on critical
```

## Conventions

- Python ≥ 3.11, `from __future__ import annotations`, standard library only (no runtime deps).
- Line length 100; ruff rules `E`, `F`, `I`, `W` (set in `pyproject.toml`).
- Severity order lives in one place, `core._SEVERITY`; the CLI imports it.

## Adding a heuristic

1. Accumulate inside the single loop in `analyze`; put threshold constants next to `_SEVERITY`.
2. Append a `Finding(code, severity, title, evidence, recommendation)` after the loop.
3. Keep `evidence` JSON-serialisable, with `int` or rounded `float` values.
4. Add a positive and a negative test in `tests/test_analysis.py` with minimal flow lists.
5. Extend `examples/incident-flows.json` if the smoke test should show it; update the README tables.

## CLI contract and don'ts

- Exit codes: `0` below `--fail-on`, `1` threshold reached, `2` invalid input or arguments.
- `--json` output must stay `sort_keys=True` so reports are diffable.
- No new dependencies, no network access, no pcap parsing.
- Do not change finding `code` strings without updating the README and tests.

## Privacy / Integritet

Inga privata uppgifter får committas, och de får inte stå i PR-text (titel, beskrivning eller kommentar). Det gäller:

- personlig e-post — använd GitHubs noreply-adress i stället
- telefonnummer
- postadresser och hemadresser
- namn på privatpersoner
- interna IP-adresser
- Tailscale-värdnamn
- användarnamn i sökvägar
- nycklar och tokens
- innehåll i `.env`

Kör `pre-commit install` lokalt så att gitleaks granskar staged ändringar mot `.gitleaks.toml` före varje commit.

Agenter som hittar privata uppgifter maskerar dem med platshållare och skriver aldrig ut själva värdet i en commit, en pull request eller en logg. Använd till exempel `<email>`, `<user>`, `192.168.x.y`, `10.x.y.z`, `100.64.0.x` och `<host>.ts.net`.

---

<!-- agents-handover:rules -->
## Gemensamma agentregler (multi-agent)
Gemensamma regler för alla AI-agenter (Claude Code, Codex, molnagenter m.fl.) som arbetar i det här repot.
Flera agenter kan jobba här parallellt – utgå alltid från att någon annan kan ha pågående arbete.

### Innan du börjar

1. **Läs `HANDOVER.md`** – aktuellt läge, pågående arbete, nästa steg och kända problem.
2. **Kolla läget i git:**
   ```sh
   git status
   git fetch --all --prune
   git branch -a
   gh pr list --state open
   ```
3. **Gör inte om något som redan pågår.** Finns det en öppen PR, en aktiv branch eller en rad under
   "Pågående arbete" i `HANDOVER.md` som rör samma sak – bygg vidare på den eller fråga användaren.
4. Har arbetskatalogen ocommittade ändringar som inte är dina: rör dem inte. Använd en egen
   `git worktree` eller fråga användaren.

### Under arbetet

- **En branch per uppgift**, namnformat: `agent/<verktyg>/<kort-beskrivning>`
  (t.ex. `agent/claude/fix-login-timeout`, `agent/codex/add-csv-export`).
- Registrera ditt arbete under "Pågående arbete" i `HANDOVER.md` tidigt (agent, branch, status).
- **Committa ofta** med tydliga meddelanden.
- **Fråga alltid användaren innan destruktiva git-kommandon:** `push --force`, `reset --hard`,
  `clean -fd`, radera brancher (lokalt eller remote), `rebase` av delade brancher, `checkout -- .`.

### Innan sessionen avslutas

- **Inget arbete får lämnas ocommittat.** Committa (vid behov som WIP) och **pusha alltid** din branch.
- **Uppdatera `HANDOVER.md`:** aktuellt läge, pågående arbete, nästa steg, kända problem och en ny rad
  i loggen (datum, agent, vad som gjordes).
- Om repot saknar `AGENTS.md` eller `HANDOVER.md`: skapa dem från mallen
  (https://github.com/jojo-swe/repo-template) innan du börjar.

### Repo-specifikt (autodetekterat 2026-11-04)

#### Bygga och testa

- Installera: `pip install -e .`
- Test: `pytest`
- CI: GitHub Actions (`ci.yml`, `privacy-guard.yml`)

#### Struktur

- `.github/` (2 filer)
- `docs/` (1 filer)
- `examples/` (1 filer)
- `src/` (3 filer)
- `tests/` (3 filer)
- Filer i roten: `.gitignore`, `.gitleaks.toml`, `.pre-commit-config.yaml`, `AGENTS.md`, `LICENSE`, `pyproject.toml`, `README.md`

#### Övrigt

<!-- Konventioner, miljövariabler, deploy, saker agenter ska undvika. -->
