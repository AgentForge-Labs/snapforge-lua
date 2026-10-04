local snapforge = require("snapforge")

local passed = 0
local function ok(value, message)
  assert(value, message)
  passed = passed + 1
end
local function equal(actual, expected, message)
  assert(actual == expected, (message or "values differ") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual))
  passed = passed + 1
end
local function contains(text, needle, message)
  assert(tostring(text):find(needle, 1, true), message or ("missing " .. needle))
  passed = passed + 1
end
local function expect_error(fn, matcher)
  local success, err = pcall(fn)
  assert(not success, "expected failure")
  if matcher then contains(tostring(err), matcher) end
  passed = passed + 1
  return err
end

local function fake_transport(options)
  options = options or {}
  local state = { requests = {} }
  local function transport(request)
    state.requests[#state.requests + 1] = request
    return {
      status = options.status or 200,
      headers = options.headers or {
        ["X-RateLimit-Limit"] = "500",
        ["X-RateLimit-Remaining"] = "499",
      },
      body = options.body or { ok = true },
    }
  end
  return transport, state
end

equal(snapforge.VERSION, "0.2.0", "version")
equal(snapforge.HOSTED_ORIGIN, "https://snapforge.web-tasarimci.com", "hosted origin")

do
  local transport, state = fake_transport()
  local client = snapforge.new({ access_token = "unit-test-value", transport = transport })
  local result = client:request("/api/v1/future-endpoint", {
    method = "POST",
    body = { hello = "world" },
    headers = { ["X-Trace"] = "trace-1", Authorization = "malicious" },
    idempotency_key = "idem-1",
    timeout = 4.25,
  })
  local seen = state.requests[#state.requests]
  equal(seen.url, "https://snapforge.web-tasarimci.com/api/v1/future-endpoint", "hosted default")
  equal(seen.headers.Authorization, "Bearer unit-test-value", "bearer auth")
  equal(seen.headers["Idempotency-Key"], "idem-1", "idempotency")
  equal(seen.headers["X-Trace"], "trace-1", "custom header")
  equal(seen.timeout, 4.25, "timeout override")
  equal(result.quota.limit, 500, "quota limit")
  equal(result.quota.remaining, 499, "quota remaining")
end

do
  local transport, state = fake_transport()
  local client = snapforge.new({
    base_url = "http://localhost:3010/",
    access_token = "",
    url_secret = "client secret/+",
    transport = transport,
  })
  client:capture("https://example.com", { idempotency_key = "cap-1" })
  local seen = state.requests[#state.requests]
  equal(seen.url, "http://localhost:3010/client/client%20secret%2F%2B/api/v1/screenshot", "URL-secret capture route")
  ok(seen.headers.Authorization == nil, "URL-secret must not send bearer auth")
  equal(seen.headers["Idempotency-Key"], "cap-1", "capture idempotency")

  client:context("https://example.com")
  contains(state.requests[#state.requests].url, "/api/v1/page/context", "context route")
  client:get_job("job/id")
  contains(state.requests[#state.requests].url, "/api/screenshots/jobs/job%2Fid", "job route")
  client:download_job("job/id")
  contains(state.requests[#state.requests].url, "/api/screenshots/jobs/job%2Fid/download", "archive route")
  client:download_job_file("job/id", "desktop.png", { download = true })
  contains(state.requests[#state.requests].url, "/files/desktop.png?download=1", "file route")
end

do
  local transport = fake_transport()
  local client = snapforge.new({ transport = transport })
  for _, path in ipairs({
    "/api/admin/users",
    "/api/internal/x",
    "/api/saas-admin/x",
    "/api/v1/../admin",
    "/api/v1/%2e%2e/admin",
    "https://evil.example/api/v1",
  }) do
    expect_error(function() client:request(path) end)
  end
end

do
  local transport, state = fake_transport({ body = "binary-data", headers = {} })
  local client = snapforge.new({ access_token = "must-not-leak", transport = transport })
  local external = client:download("https://cdn.example.test/file")
  equal(external.content, "binary-data", "external download")
  ok(state.requests[#state.requests].headers.Authorization == nil, "third-party download must not get bearer auth")
  local local_file = client:download("/api/screenshots/jobs/a/download")
  equal(local_file.content, "binary-data", "same-origin download")
  equal(state.requests[#state.requests].headers.Authorization, "Bearer must-not-leak", "same-origin download auth")
end

do
  local transport = fake_transport({
    status = 429,
    headers = {},
    body = {
      error = "quota exhausted for top-secret",
      quota = { limit = 500, remaining = 0, reset = 1234, used = 500 },
    },
  })
  local client = snapforge.new({ access_token = "top-secret", transport = transport })
  local err = expect_error(function() client:capture("https://example.com") end)
  ok(type(err) == "table", "structured error table")
  equal(err.name, "SnapForgeError", "error type")
  equal(err.status, 429, "error status")
  equal(err.quota.remaining, 0, "error quota")
  ok(not tostring(err):find("top-secret", 1, true), "error message redacts credentials")
  contains(tostring(err), "[REDACTED]", "redaction marker")
  ok(not tostring(err.body.error):find("top-secret", 1, true), "error body redacts credentials")
end

do
  local file = assert(io.open("tests/fixtures/public-api-v1-legacy.json", "rb"))
  local fixture = file:read("*a")
  file:close()
  for _, route in ipairs({
    "/api/v1",
    "/api/v1/screenshot",
    "/api/v1/page/context",
    "/api/screenshots/jobs/{jobId}/download",
    "/api/screenshots/jobs/{jobId}/files/{fileName}",
  }) do
    contains(fixture, route, "conformance fixture route " .. route)
  end
end

expect_error(function() snapforge.new({ base_url = "localhost:3010" }) end, "absolute http(s)")
expect_error(function() snapforge.new({ access_token = "a", url_secret = "b" }) end, "Choose access_token")
expect_error(function() snapforge.new({ timeout = 0 }) end, "positive number")

print(("snapforge Lua tests passed: %d assertions"):format(passed))
