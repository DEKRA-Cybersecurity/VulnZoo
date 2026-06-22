# Promotion Map — output/ → src/ (Layer 3 — factory)

> The **canonical** mapping used by `stages/04_integrate` to adapt pipeline outputs
> into the product `src/`. Nothing reaches `src/` except through this table.
> `<Device>` doc folders are TitleCase (see [`../shared/glossary.md`](../shared/glossary.md)).

## Code & config

| Source (pipeline `output/`) | Destination in `src/` |
|-----------------------------|-----------------------|
| `stages/02_implement/output/code/<path>` | `src/<path>` (verbatim, per that stage's `manifest.md`) |
| Cloud API change | `src/cloud_api/<device>/api_server/…` (or `c2_server/`, `camera_sim/`) |
| Lab overlay change | `src/labs/<device>/files/…` |
| Android app change | `src/vulnzoo_apps/<app>/…` |

## Lab repackaging (when a lab overlay changed)

```bash
cd src/labs/<device>/files
tar -cvzf <device>.tar.gz opt etc usr
mv <device>.tar.gz ../../vulnzoo/files/usr/lib/vulnzoo-devices/<device>.tar.gz
```

## Documentation

| Source | Destination in `src/` |
|--------|-----------------------|
| `stages/03_document/output/<VULN-ID>.md` | `src/docs/<Device>/Vulns/<Category>/<VULN-ID>.md` |
| Index + status badge | `src/docs/<Device>/Vulns/README.md` → set `✅ DONE` |
| New screenshots | `src/docs/<Device>/Vulns/<Category>/images/` |

## Device → product paths

| Device | Lab overlay | Cloud API | Docs folder |
|--------|-------------|-----------|-------------|
| `careotter` | `src/labs/careotter/` | `src/cloud_api/careotter/` | `src/docs/CareOtter/` |
| `routcoon` | `src/labs/routcoon/` | — | `src/docs/Router/` |
| `owlcam` | `src/labs/owlcam/` | `src/cloud_api/owlcam/` | `src/docs/IP Camera/` |
| `octobot` | `src/labs/octobot/` | `src/cloud_api/octobot/` | `src/docs/OctoBot/` |

## Post-promotion checks
1. Lab still loads — see `src/labs/<device>/CONTEXT.md`.
2. `affected_components` in the doc match the real `src/` paths.
3. Record the promotion in `stages/04_integrate/output/integration-log.md`.
