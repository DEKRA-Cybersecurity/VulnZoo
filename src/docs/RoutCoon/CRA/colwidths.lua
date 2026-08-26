-- colwidths.lua - force every table to wrapping, content-proportional column widths.
-- Pandoc otherwise sizes pipe-table columns from the source dash lengths, which makes wide
-- tables overflow the page (and makes the reformatted padded-pipe tables collapse to one
-- column). We override widths from the longest cell per column (capped so one long cell cannot
-- dominate, floored so narrow columns stay readable), normalised below the text width so p{}
-- columns wrap instead of running off the page.
local u = pandoc.utils

local function scan(rows, maxlen)
  for _, row in ipairs(rows) do
    for i, cell in ipairs(row.cells) do
      local l = #u.stringify(cell.contents)
      if l > (maxlen[i] or 0) then maxlen[i] = l end
    end
  end
end

function Table(tbl)
  local ncol = #tbl.colspecs
  if ncol == 0 then return nil end
  local maxlen = {}
  scan(tbl.head.rows, maxlen)
  for _, b in ipairs(tbl.bodies) do scan(b.body, maxlen) end
  local total = 0
  for i = 1, ncol do
    local m = maxlen[i] or 6
    if m > 34 then m = 34 end   -- cap: a very long cell wraps rather than hogging the row
    if m < 6 then m = 6 end     -- floor: keep short columns legible
    m = m + 4                   -- padding: guarantees inter-column gutter for medium words
    maxlen[i] = m
    total = total + m
  end
  for i = 1, ncol do
    tbl.colspecs[i][2] = 0.95 * maxlen[i] / total
  end
  return tbl
end
