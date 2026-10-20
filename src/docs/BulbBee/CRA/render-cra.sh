#!/usr/bin/env bash
# render-cra.sh - render the BulbBee CRA manufacturer dossier (BB-*.md) to PDF via pandoc + LaTeX.
#
# The Markdown files remain the single source of truth. This script produces the "official
# submission" artifacts on demand into ./build/ (gitignored):
#   - one PDF per manufacturer document (BB-TD-000, BB-DOC-001, BB-ERM-002, BB-RMR-005, BB-SCP-006, BB-VVR-007, BB-VMP-008, BB-UM-004)
#   - one bound dossier PDF (all documents, with a table of contents)
#   - a copy of the machine-readable SBOM, so build/ is the full package
#
# BulbBee is a default-category product (Module A, internal control, no notified body), so the submission
# set is proportionate but still covers every Annex VII item (BB-TD-000 maps them). It renders ONLY
# BB-*.md, so the internal plan (00-*) and the trainer-only assessor gap key (99-*) are never part
# of the package.
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
# smaller font inside tables so the wide requirement/traceability tables fit the page width.
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
for md in BB-*.md; do
  name="${md%.md}"
  tmp="$(mktemp)"
  awk 'BEGIN{done=0} /^# /&&!done{done=1;next} {print}' "$md" > "$tmp"
  pandoc "$tmp" "${common[@]}" -o "$OUT/$name.pdf"
  rm -f "$tmp"
  echo "  rendered $OUT/$name.pdf"
  count=$((count+1))
done

# Bound dossier: the DoC first (the declaration), then the requirements evidence and the user
# information, with a TOC. Keep the H1 of each document so it becomes a chapter heading
# (documentclass=report).
order=(BB-TD-000*.md BB-DOC-001*.md BB-ERM-002*.md BB-RMR-005*.md BB-SCP-006*.md BB-VVR-007*.md BB-VMP-008*.md BB-UM-004*.md)
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
    --metadata title="BulbBee CRA Manufacturer Dossier (default category, Module A)" \
    --metadata date="$dossier_date" \
    -o "$OUT/BulbBee-CRA-dossier.pdf"
  rm -f "${tmps[@]}"
  echo "  rendered $OUT/BulbBee-CRA-dossier.pdf (bound, ${#bound[@]} documents)"
fi

# Complete the submission package: the SBOM stays machine-readable JSON.
[ -f BB-SBOM-003.cdx.json ] && cp -f BB-SBOM-003.cdx.json "$OUT/"

echo "Done: $count document PDFs + bound dossier + SBOM in $(pwd)/$OUT/"
