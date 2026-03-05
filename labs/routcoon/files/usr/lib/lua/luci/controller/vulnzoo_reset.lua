module("luci.controller.vulnzoo_reset", package.seeall)

function index()
  entry({"admin", "system", "vulnzoo_reset"}, call("reset_page"), _("VulnZoo: Restore"), 60).dependent = false
end

function reset_page()
  local http = require "luci.http"
  local tpl = require "luci.template"
  local sys = require "luci.sys"

  if http.getenv("REQUEST_METHOD") == "POST" then
    local form = http.formvalue("do_reset")
    if form and form == "1" then
      -- Run the reset script in background so the web response returns immediately
      sys.call("nohup /usr/bin/vulnzoo-firstboot-reset.sh >/dev/null 2>&1 &")
      tpl.render("vulnzoo_reset_submitted")
      return
    end
  end

  tpl.render("vulnzoo_reset")
end
