# VulnZoo — Global Identity & Routing (Layer 0)

> **⚠️ LAYER 0 — GLOBAL IDENTITY**
>
> This is the canonical, model-agnostic identity file for the VulnZoo workspace.
> Every agent (Claude, Kimi, …) lands here through its Layer 1 entry
> (`CLAUDE.md` / `KIMI.md`). Read this file first to know *where you are* and
> *where to go*, then follow the routing table to the relevant Layer 2 contract.

---

## Identity

**VulnZoo** is an open-source ecosystem of *intentionally vulnerable* IoT devices
for cybersecurity training in embedded, medical, industrial and automotive
environments. Labs run on **OpenWRT v24.10.2** on a **Raspberry Pi 3B/3B+/4**,
managed through a **Device Manager** web UI on port **8080**. Cloud backends run
as **Docker** containers; companion **Android** apps talk to the devices and APIs.

> **The vulnerabilities are intentional.** Do **not** "fix", sanitize, or harden
> any vulnerable code unless the user explicitly asks for it. Each lab ships
> documented attack chains; security improvements break the training material.
> Educational/authorized use only.

## MWP — how this workspace is organized

VulnZoo follows the **Model Workspace Protocol (MWP)**: the folder structure *is*
the agent architecture. You load only the context for the layer you are working
at. Methodology: [`MWP_README.md`](MWP_README.md) (condensed) · [`../MWP.md`](../MWP.md) (full paper).

| Layer | File(s) | Role |
|-------|---------|------|
| **Layer 0** | `AGENTS.md` (this file) | Global identity + routing table |
| **Layer 1** | `CLAUDE.md`, `KIMI.md` | Per-agent entry points (thin routers → here) |
| **Layer 2** | `<component>/CONTEXT.md`, `<component>/<device>/CONTEXT.md` | Stage contracts (Inputs / Process / Outputs) |
| **Layer 3** | `docs/` | Reference material (architecture, vuln specs) |
| **Layer 4** | source under `*/files/`, `*/api_server/`, app code | Working artifacts (the code itself) |

## Workspace map (`src/`)

```
src/
├── AGENTS.md          ← Layer 0 (this file)
├── CLAUDE.md / KIMI.md ← Layer 1 entry points
├── MWP_README.md      ← MWP methodology guide
├── labs/              ← OpenWRT image + lab overlays (.tar.gz): vulnzoo, careotter, routcoon, owlcam, octobot
├── cloud_api/         ← Dockerized Flask backends: careotter (SQLite+IGP), owlcam (MongoDB+C2/SSE)
├── vulnzoo_apps/      ← Android apps: careotter_app (Java/BLE), owlcam_app (Kotlin/Compose)
└── docs/              ← Layer 3 reference: per-device vulnerability docs (OWASP-mapped)
```

## Routing table — where do I go?

| User intent | Go to | Read first |
|-------------|-------|------------|
| Build / package / deploy a lab (OpenWRT image, `.tar.gz`, hooks) | `labs/` → `labs/<device>/` | [`labs/CONTEXT.md`](labs/CONTEXT.md) then `labs/<device>/CONTEXT.md` |
| Work on a cloud API (Flask, Docker, JWT, endpoints) | `cloud_api/` → `cloud_api/<device>/` | [`cloud_api/CONTEXT.md`](cloud_api/CONTEXT.md) then `cloud_api/<device>/CONTEXT.md` |
| Work on an Android app | `vulnzoo_apps/` | [`vulnzoo_apps/CONTEXT.md`](vulnzoo_apps/CONTEXT.md) |
| Understand / document a vulnerability | the device's **doc folder** (see map below) | its `Vulns/` or `.../Vulnerabilities.md` |
| Project-wide overview (ports, network, stack) | `docs/` | [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md) |

**Device → folder map** (code/lab name uses lowercase; doc folders are TitleCase and *not* 1:1):

| Device (lab/code name) | Doc folder (Layer 3) |
|------------------------|----------------------|
| `careotter` (medical) | [`docs/CareOtter/`](docs/CareOtter/) |
| `routcoon` (router) | [`docs/Router/`](docs/Router/) |
| `owlcam` (IP camera) | [`docs/IP Camera/`](docs/IP%20Camera/) |
| `octobot` (industrial) | [`docs/OctoBot/`](docs/OctoBot/) |

## Global conventions

- **OWASP IDs**: API `API1:2023`…`API10:2023`. IoT `IoT:I1`…`IoT:I5` (router) / `IoT1`…`IoT4`. Mobile `M6`, `M9`. Custom: `IGP-01`, `BLE-07`.
- **Status badges** (in vuln docs): `DONE` · `PENDING` · `IN PROGRESS` — plain text, no emoji.
- **Naming**: lab/device folders lowercase (`careotter/`), lab package `<device>.tar.gz`, hooks `##-descriptive-name.sh`.
- **Vuln docs** carry YAML frontmatter (`id`, `title`, `category`, `status`, `severity`, `owasp`, `cwe`, `affected_components`).
- **Language**: production MWP markdown (Layer 0–2 files, `CONTEXT.md`, docs) is written in **English**.
- **Prose style** (informational markdown, not code): write each paragraph on one physical line with no hard wrapping — Obsidian-style readers soft-wrap to their own max width. Do not use the semicolon `;` in prose — use a comma or split into two sentences. Code is exempt: C, shell, JavaScript, inline code, code fences, and command lines keep their semicolons and line structure.

## Hard rules for agents

1. **Read the chain before editing.** Layer 1 → this file (Layer 0) → the relevant Layer 2 `CONTEXT.md` → the Layer 3 docs it points to. Do not assume paths or behaviors.
2. **Keep Layer 3 ↔ Layer 4 in sync.** When you change vulnerable code (Layer 4), update the matching vuln doc (Layer 3), and vice-versa.
3. **Preserve intentional vulnerabilities** (see Identity). Harden only on explicit request.
4. **One stage, one job.** Stay within the component's Layer 2 contract; don't reach across stages unless routed there.

---

*References:* [`MWP_README.md`](MWP_README.md) · [`../MWP.md`](../MWP.md) · [`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md)
