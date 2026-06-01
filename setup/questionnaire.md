# Setup Questionnaire

> Answer once at the start of a development cycle. `stages/01_spec` reads these
> answers to scope the work. (MWP §4.4 — the setup questionnaire configures the run.)

## 1. Target

- **Device / lab?** `careotter` | `routcoon` | `owlcam` | other: ______
- **Component(s)?** lab firmware (`src/labs/…`) | cloud API (`src/cloud_api/…`) | Android app (`src/vulnzoo_apps/…`) | docs only

## 2. Change type

- [ ] New vulnerability
- [ ] Fix / change to an existing vulnerability
- [ ] New feature / lab capability (non-vuln)
- [ ] Documentation only

## 3. If a vulnerability

- **OWASP / custom ID?** (e.g. `API7:2023`, `IoT:I5`, `M9`, `IGP-02`) ______
- **CWE(s)?** ______
- **Severity?** Critical | High | Medium | Low
- **Attack surface?** API | IoT/device | Mobile

## 4. Scope & acceptance

- **Affected `src/` paths (best guess):** ______
- **How will we know it works?** (repro step / status code / exposed data) ______
- **Does the lab `.tar.gz` need repackaging?** yes | no

## 5. Output

- **Target status badge on completion:** `🚧 IN PROGRESS` → `✅ DONE`
