# SnapForge Lua SDK

Official thin Lua/LuaJIT client for the public SnapForge screenshot API.

The package is free to install. Managed SnapForge usage stays account-bound and metered server-side; the Lua package contains only client request/response code and does not contain rendering workers, billing code, databases, internal/admin APIs, or private backend source.

## Install

After the registry release:

    luarocks install snapforge

The package targets Lua 5.1, 5.2, 5.3, 5.4 and LuaJIT 2.1. Runtime dependencies are intentionally conventional:

- luasocket for HTTP transport
- luasec for TLS-verified HTTPS
- lua-cjson for JSON encoding/decoding

No TLS verification bypass is used.

## Hosted quickstart

Create a free SnapForge account/API key and export SNAPFORGE_API_KEY, then:

    local snapforge = require("snapforge")
    local client = snapforge.new()

    local response = client:capture("https://example.com", {
      device = "both",
      full_page = true,
      idempotency_key = "capture-123",
    })

    print(response.body.jobId)
    print(response.quota.remaining)

The default endpoint is https://snapforge.web-tasarimci.com. Free-account credits and paid quotas are enforced by the hosted API, not by the Lua package.

## Explicit self-hosted mode

SnapForge never silently falls back from hosted service to localhost. Select a self-hosted/community endpoint explicitly:

    local client = snapforge.new({
      base_url = "http://localhost:3010",
      access_token = "",
    })

Compatible URL-secret deployments can use url_secret instead of access_token. Do not configure both.

## API

- client:service_info() reads /api/v1.
- client:capture(url, options) supports device, full_page, delay_ms, ttl_seconds and idempotency_key.
- client:context(url, options) supports viewport, delay_ms, max_text_chars and idempotency_key.
- client:get_job(job_id) reads screenshot job state.
- client:download_job(job_id) downloads the archive.
- client:download_job_file(job_id, file_name, options) downloads one artifact.
- client:download(url) supports absolute or root-relative artifact URLs.
- client:request(path, options) is the forward-compatible public /api/* escape hatch.

Bearer credentials are sent only to the configured SnapForge origin and are never forwarded to explicit third-party/CDN URLs.

## Responses, quota and errors

JSON helpers return status, body, quota and headers. Quota metadata is parsed from X-RateLimit headers and structured quota bodies.

Non-2xx responses raise a structured SnapForgeError table with status, body, quota and message. Configured credentials are recursively redacted from diagnostics.

## Testing

From packages/sdk-lua:

    LUA_PATH="./src/?.lua;./src/?/init.lua;;" lua tests/test_snapforge.lua

Validate and install the rock locally:

    luarocks make snapforge-0.2.0-1.rockspec

## Source and license

Public distribution source: https://github.com/AgentForge-Labs/snapforge-lua

License: AGPL-3.0-or-later.
