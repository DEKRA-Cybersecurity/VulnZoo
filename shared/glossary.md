# Glossary — Shared Terms (Layer 3)

## Device → doc-folder map

Lab/code names are lowercase; doc folders are TitleCase and **not** 1:1.

| Device (code/lab) | Doc folder (`src/docs/`) | Domain |
|-------------------|--------------------------|--------|
| `careotter` | `CareOtter/` | Medical (ICD + bedside monitor) |
| `routcoon` | `Router/` | Home/enterprise router |
| `owlcam` | `IP Camera/` | IP camera surveillance |

## Service ports

| Lab | Service | Port | Protocol |
|-----|---------|------|----------|
| vulnzoo | Device Manager | 8080 | HTTP |
| routcoon | LUCI Admin | 80 | HTTP |
| routcoon | SSH / FTP / Telnet | 22 / 21 / 5515 | TCP |
| owlcam | RTSP Stream | 8554 | RTSP |
| owlcam | Camera API | 5000 | HTTP |
| owlcam | C2 (SSE) | 4999 | HTTP |
| careotter | Sensor API | 8081 | HTTP |
| careotter | IGP v4 (admin) | 9999 | TCP |
| careotter | Cloud API | 5002 | HTTP |

## Key terms

- **Device Manager** — OpenWRT web UI (`:8080`) that loads/switches labs.
- **Lab overlay** — `<device>.tar.gz` extracted onto the Pi root fs at deploy.
- **Hook** — `##-name.sh` in `profile-init.d/`, run in numeric order on lab load.
- **IGP v4** — CareOtter binary admin protocol (TCP `:9999`, magic `0x43415245`).
- **Promotion** — copying a pipeline `output/` artifact into its `src/` destination (see [`../_config/promotion-map.md`](../_config/promotion-map.md)).
