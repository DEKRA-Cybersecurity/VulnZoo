#!/usr/bin/env bash
# render-cra.sh - render the RoutCoon CRA manufacturer dossier (RC-*.md) to PDF via pandoc + LaTeX.
#
# The Markdown files remain the single source of truth. This script produces the "official
# submission" artifacts on demand into ./build/ (gitignored):
#   - one PDF per manufacturer document (matches the checklist column E references)
#   - one bound dossier PDF (all documents, with a table of contents)
#   - a copy of the Excel checklist and the machine-readable SBOM, so build/ is the full package
#
# It renders ONLY RC-*.md, so the internal plan (00-*) and the trainer-only assessor gap key
# (99-*) are never part of the package.
#
# Requires: pandoc, and a LaTeX engine (xelatex preferred). On Debian/Kali:
#   sudo apt-get install -y pandoc texlive-xetex texlive-latex-recommended texlive-fonts-recommended
set -euo pipefail

cd "$(dirname "$0")"
OUT="build"
mkdir -p "$OUT"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "error: pandoc not found. Install it, e.g.:  sudo apt-get install -y pandoc" >&2
  exit 1
fi

ENGINE=""
for e in xelatex lualatex pdflatex; do
  command -v "$e" >/dev/null 2>&1 && { ENGINE="$e"; break; }
done
[ -n "$ENGINE" ] || { echo "error: no LaTeX engine (xelatex/lualatex/pdflatex) found. Install TeX Live." >&2; exit 1; }
echo "Using pandoc + $ENGINE"

# Shared LaTeX header: a footer marking every page as a fictional training document, and a
# smaller font inside tables so the wide component/traceability tables fit the page width.
HDR="$(mktemp)"
trap 'rm -f "$HDR"' EXIT
cat > "$HDR" <<'TEX'
\usepackage{fancyhdr}
\usepackage{etoolbox}
\usepackage{ragged2e}
% pandoc sizes table columns with \raggedright, which disables hyphenation and lets long
% unbreakable words protrude into the next column. Swap in ragged2e's \RaggedRight, which keeps
% hyphenation on so those words break and stay inside their column.
\let\origraggedright\raggedright
\renewcommand{\raggedright}{\RaggedRight}
\pagestyle{fancy}
\fancyhf{}
\fancyfoot[C]{\footnotesize Fictional training document - VulnZoo - not a real conformity submission}
\fancyfoot[R]{\footnotesize \thepage}
\renewcommand{\headrulewidth}{0pt}
\renewcommand{\footrulewidth}{0.2pt}
\AtBeginEnvironment{longtable}{\footnotesize}
\AtBeginEnvironment{tabular}{\footnotesize}
TEX

common=(
  --pdf-engine="$ENGINE"
  --from=gfm+yaml_metadata_block
  -V geometry:margin=2.3cm
  -V fontsize=11pt
  -V colorlinks=true
  --lua-filter=colwidths.lua
  --include-in-header="$HDR"
)

shopt -s nullglob

# Per-document PDFs. Strip only the first H1 line, which duplicates the frontmatter title that
# pandoc already renders as the document title block.
count=0
for md in RC-*.md; do
  name="${md%.md}"
  tmp="$(mktemp)"
  awk 'BEGIN{done=0} /^# /&&!done{done=1;next} {print}' "$md" > "$tmp"
  pandoc "$tmp" "${common[@]}" -o "$OUT/$name.pdf"
  rm -f "$tmp"
  echo "  rendered $OUT/$name.pdf"
  count=$((count+1))
done

# Bound dossier: TD-000 (the Annex VII index) first, then the rest, with a TOC. Keep the H1 of
# each document so it becomes a chapter heading (documentclass=report).
order=(RC-TD-000*.md RC-RMR-001*.md RC-SCP-002*.md RC-SRS-003*.md RC-SAD-004*.md RC-SDE-005*.md \
       RC-CBL-006*.md RC-VVR-008*.md RC-SDD-009*.md RC-VMP-010*.md RC-DEC-011*.md RC-TPD-012*.md RC-UM-013*.md)
bound=()
for pat in "${order[@]}"; do for f in $pat; do [ -f "$f" ] && bound+=("$f"); done; done
if [ "${#bound[@]}" -gt 0 ]; then
  # pandoc parses only the FIRST file's YAML frontmatter as metadata; the frontmatter of the
  # other files would leak into the body as raw text. Strip each file's leading frontmatter and
  # keep its H1, which becomes a chapter title (documentclass=report).
  dossier_date="$(sed -n 's/^date:[[:space:]]*//p' "${bound[0]}" | head -1)"
  tmps=()
  for f in "${bound[@]}"; do
    t="$(mktemp)"
    awk 'NR==1&&$0=="---"{fm=1;next} fm&&$0=="---"{fm=0;next} !fm{print}' "$f" > "$t"
    tmps+=("$t")
  done
  pandoc "${tmps[@]}" "${common[@]}" --toc --toc-depth=2 -V documentclass=report \
    --metadata title="RoutCoon CRA Technical Documentation Dossier (prEN 40000-1-2)" \
    --metadata date="$dossier_date" \
    -o "$OUT/RoutCoon-CRA-dossier.pdf"
  rm -f "${tmps[@]}"
  echo "  rendered $OUT/RoutCoon-CRA-dossier.pdf (bound, ${#bound[@]} documents)"
fi

# Complete the submission package: the checklist stays Excel, the SBOM stays machine-readable JSON.
[ -f CRA_prEN40000-1-2_RoutCoon.xlsx ] && cp -f CRA_prEN40000-1-2_RoutCoon.xlsx "$OUT/"
[ -f RC-SBOM-007.cdx.json ] && cp -f RC-SBOM-007.cdx.json "$OUT/"

echo "Done: $count document PDFs + bound dossier + checklist + SBOM in $(pwd)/$OUT/"
