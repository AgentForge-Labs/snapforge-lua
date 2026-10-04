package = "snapforge"
version = "0.2.0-1"

source = {
  url = "git+https://github.com/AgentForge-Labs/snapforge-lua.git",
  tag = "v0.2.0",
}

description = {
  summary = "Official thin Lua client for the SnapForge screenshot API",
  detailed = [[
SnapForge for Lua provides hosted-by-default capture, page-context, job and
artifact helpers with explicit self-hosted overrides, Bearer/API-key auth,
idempotency support, quota metadata and credential-safe structured errors.
It contains client code only; rendering, metering and billing remain server-side.
  ]],
  homepage = "https://snapforge.web-tasarimci.com",
  license = "AGPL-3.0-or-later",
  maintainer = "AgentForge Labs <eurmurat@gmail.com>",
}

dependencies = {
  "lua >= 5.1, < 5.5",
  "luasocket >= 3.1.0",
  "luasec >= 1.3.0",
  "lua-cjson >= 2.1.0",
}

build = {
  type = "builtin",
  modules = {
    ["snapforge"] = "src/snapforge/init.lua",
  },
}
