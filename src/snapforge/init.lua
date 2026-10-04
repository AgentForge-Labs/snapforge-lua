local snapforge = {
  VERSION = "0.2.0",
  HOSTED_ORIGIN = "https://snapforge.web-tasarimci.com",
}

local Client = {}
Client.__index = Client

local SnapForgeError = {}
SnapForgeError.__index = SnapForgeError
SnapForgeError.__tostring = function(self)
  return self.message or "SnapForge request failed"
end

local function fail(message, level)
  error(message, (level or 1) + 1)
end

local function trim(value)
  return (tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function nonempty(value, message)
  if trim(value) == "" then fail(message, 2) end
  return tostring(value)
end

local function validate_timeout(value)
  local number = tonumber(value)
  if not number or number <= 0 then
    fail("timeout must be a positive number of seconds", 2)
  end
  return number
end

local function normalize_base_url(value)
  local url = trim(value)
  if not url:match("^https?://[^/]+") then
    fail("base_url must be an absolute http(s) URL", 2)
  end
  return (url:gsub("/+$", ""))
end

local function segment(value)
  local text = tostring(value or "")
  return (text:gsub("([^A-Za-z0-9%-%._~])", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

local function public_path(path)
  path = tostring(path or "")
  if not path:match("^/api/") or path:match("^//") or path:match("^[A-Za-z][A-Za-z0-9+%.%-]*:") then
    fail("request path must be a relative public /api/* path", 2)
  end

  local pathname = path:match("^([^?]*)") or path
  for part in pathname:gmatch("[^/]+") do
    if part == ".." then
      fail("request path must not contain parent traversal", 2)
    end
  end

  local lower = pathname:lower()
  if lower:find("/%2e%2e/", 1, true) or lower:sub(-7) == "/%2e%2e" then
    fail("request path must not contain encoded parent traversal", 2)
  end
  for _, prefix in ipairs({"/api/admin", "/api/internal", "/api/saas-admin"}) do
    if lower == prefix or lower:sub(1, #prefix + 1) == prefix .. "/" then
      fail("request path is not a public API path", 2)
    end
  end
  return path
end

local function header_value(headers, wanted)
  wanted = wanted:lower()
  for name, value in pairs(headers or {}) do
    if tostring(name):lower() == wanted then return value end
  end
  return nil
end

local function as_integer(value)
  if value == nil then return nil end
  local number = tonumber(value)
  if not number or number ~= math.floor(number) then return nil end
  return number
end

local function quota_from(headers, body)
  local quota = {
    limit = as_integer(header_value(headers, "x-ratelimit-limit")),
    remaining = as_integer(header_value(headers, "x-ratelimit-remaining")),
    reset = as_integer(header_value(headers, "x-ratelimit-reset")),
    used = nil,
  }
  local source = body
  if type(body) == "table" and type(body.quota) == "table" then
    source = body.quota
  end
  if type(source) == "table" then
    for _, key in ipairs({"limit", "remaining", "reset", "used"}) do
      if source[key] ~= nil then quota[key] = as_integer(source[key]) end
    end
  end
  return quota
end

local function replace_plain(text, needle, replacement)
  if needle == "" then return text end
  local start = 1
  local out = {}
  while true do
    local first, last = text:find(needle, start, true)
    if not first then
      out[#out + 1] = text:sub(start)
      return table.concat(out)
    end
    out[#out + 1] = text:sub(start, first - 1)
    out[#out + 1] = replacement
    start = last + 1
  end
end

local function redact(value, secrets, seen)
  local kind = type(value)
  if kind == "string" or kind == "number" or kind == "boolean" then
    local text = tostring(value)
    for _, secret in ipairs(secrets) do
      if secret ~= "" then text = replace_plain(text, secret, "[REDACTED]") end
    end
    if kind == "string" then return text end
    if text ~= tostring(value) then return text end
    return value
  end
  if kind ~= "table" then return value end

  seen = seen or {}
  if seen[value] then return "[CIRCULAR]" end
  seen[value] = true
  local copy = {}
  for key, item in pairs(value) do copy[key] = redact(item, secrets, seen) end
  seen[value] = nil
  return copy
end

local function json_codec()
  local ok, cjson = pcall(require, "cjson.safe")
  if not ok then
    fail("SnapForge JSON support requires lua-cjson (module cjson.safe)", 3)
  end
  return cjson
end

local function decode_body(body)
  if body == nil or body == "" then return nil end
  if type(body) == "table" then return body end
  if type(body) ~= "string" then return body end
  local parsed = json_codec().decode(body)
  if parsed == nil then return body end
  return parsed
end

local function readable_file(path)
  if not path or path == "" then return nil end
  local file = io.open(path, "rb")
  if not file then return nil end
  file:close()
  return path
end

local function tls_trust(options)
  local explicit_file = options.ca_file
  if explicit_file and explicit_file ~= "" then
    local file = readable_file(explicit_file)
    if not file then fail("ca_file is not readable: " .. tostring(explicit_file), 3) end
    return file
  end

  local env_ca = readable_file(os.getenv("SNAPFORGE_CA_FILE"))
  if env_ca then return env_ca end

  local ssl_ca = readable_file(os.getenv("SSL_CERT_FILE"))
  if ssl_ca then return ssl_ca end

  for _, candidate in ipairs({
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
  }) do
    local file = readable_file(candidate)
    if file then return file end
  end

  fail("no trusted CA bundle found; set SNAPFORGE_CA_FILE or ca_file", 3)
end

local function normalize_dns_name(value)
  local name = tostring(value or ""):lower()
  name = name:gsub("%.$", "")
  return name
end

local function dns_name_matches(host, pattern)
  host = normalize_dns_name(host)
  pattern = normalize_dns_name(pattern)
  if host == "" or pattern == "" or host:find("%z") or pattern:find("%z") then
    return false
  end
  if host == pattern then return true end

  if pattern:sub(1, 2) ~= "*." then return false end
  if pattern:find("*", 2, true) then return false end

  local suffix = pattern:sub(2)
  if #host <= #suffix or host:sub(-#suffix) ~= suffix then return false end
  local left = host:sub(1, #host - #suffix)
  return left ~= "" and not left:find(".", 1, true)
end

local function certificate_matches_host(cert, host)
  if not cert or type(cert.extensions) ~= "function" then return false end
  host = normalize_dns_name(host)
  local is_ip = host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil or host:find(":", 1, true) ~= nil

  local extensions = cert:extensions() or {}
  local san = extensions["2.5.29.17"]
  if type(san) == "table" then
    local values = is_ip and san.iPAddress or san.dNSName
    if type(values) == "table" and #values > 0 then
      for _, value in ipairs(values) do
        if is_ip then
          if normalize_dns_name(value) == host then return true end
        elseif dns_name_matches(host, value) then
          return true
        end
      end
      return false
    end
  end

  if is_ip or type(cert.subject) ~= "function" then return false end
  local subject = cert:subject() or {}
  for _, entry in ipairs(subject) do
    if type(entry) == "table" and entry.oid == "2.5.4.3" and dns_name_matches(host, entry.value) then
      return true
    end
  end
  return false
end

local function default_transport(spec)
  local ok_ltn12, ltn12 = pcall(require, "ltn12")
  local ok_http, http = pcall(require, "socket.http")
  if not ok_ltn12 or not ok_http then
    fail("SnapForge HTTP support requires LuaSocket", 3)
  end

  local encoded_body
  local headers = {}
  for name, value in pairs(spec.headers or {}) do headers[name] = tostring(value) end
  if spec.body ~= nil then
    local encoded, encode_error = json_codec().encode(spec.body)
    if not encoded then fail("unable to encode JSON request body: " .. tostring(encode_error), 3) end
    encoded_body = encoded
    headers["Content-Type"] = headers["Content-Type"] or "application/json"
    headers["Content-Length"] = tostring(#encoded_body)
  end
  headers["User-Agent"] = headers["User-Agent"] or ("snapforge-lua/" .. snapforge.VERSION)

  local response_chunks = {}
  local request = {
    url = spec.url,
    method = spec.method,
    headers = headers,
    sink = ltn12.sink.table(response_chunks),
    redirect = false,
  }
  if encoded_body then request.source = ltn12.source.string(encoded_body) end

  local old_http_timeout = http.TIMEOUT
  http.TIMEOUT = spec.timeout

  local old_https_timeout
  if spec.url:match("^https://") then
    local ok_https, https = pcall(require, "ssl.https")
    if not ok_https or type(https.tcp) ~= "function" then
      http.TIMEOUT = old_http_timeout
      fail("HTTPS SnapForge requests require LuaSec 1.3+", 3)
    end

    local ca_file = tls_trust(spec)
    local tls = {
      protocol = "any",
      options = {"all", "no_sslv2", "no_sslv3", "no_tlsv1"},
      verify = "peer",
    }
    tls.cafile = ca_file

    local base_create = https.tcp(tls)
    request.create = function()
      local connection = base_create()
      local connect = connection.connect
      function connection:connect(host, port)
        local ok, err = connect(self, host, port)
        if not ok then return ok, err end
        local cert = self:getpeercertificate()
        if not certificate_matches_host(cert, host) then
          pcall(function() self:close() end)
          return nil, "TLS certificate hostname mismatch for " .. tostring(host)
        end
        return ok
      end
      return connection
    end

    old_https_timeout = https.TIMEOUT
    https.TIMEOUT = spec.timeout
  end

  local call_ok, request_ok, code, response_headers, status_line = pcall(http.request, request)

  http.TIMEOUT = old_http_timeout
  if old_https_timeout ~= nil then
    local _, https = pcall(require, "ssl.https")
    if https then https.TIMEOUT = old_https_timeout end
  end

  if not call_ok then
    return {
      status = 599,
      headers = {},
      body = table.concat(response_chunks),
      transport_error = tostring(request_ok),
    }
  end
  if not request_ok then
    return {
      status = tonumber(code) or 599,
      headers = response_headers or {},
      body = table.concat(response_chunks),
      transport_error = tostring(code or status_line or "transport failure"),
    }
  end
  return {
    status = tonumber(code) or 599,
    headers = response_headers or {},
    body = table.concat(response_chunks),
  }
end

local function normalize_transport_response(response)
  if type(response) ~= "table" or response.status == nil then
    fail("transport must return a table with status, headers, and body", 3)
  end
  local status = tonumber(response.status)
  if not status then fail("transport response status must be numeric", 3) end
  return {
    status = status,
    headers = type(response.headers) == "table" and response.headers or {},
    body = response.body,
    transport_error = response.transport_error,
  }
end

function snapforge.new(options)
  options = options or {}
  if type(options) ~= "table" then fail("options must be a table", 2) end

  local base_url = normalize_base_url(options.base_url or snapforge.HOSTED_ORIGIN)
  local access_token = options.access_token
  if access_token == nil then access_token = os.getenv("SNAPFORGE_API_KEY") or "" end
  access_token = tostring(access_token or "")
  local url_secret = tostring(options.url_secret or "")

  if access_token ~= "" and url_secret ~= "" then
    fail("Choose access_token or url_secret, not both", 2)
  end
  if options.transport ~= nil and type(options.transport) ~= "function" then
    fail("transport must be a function", 2)
  end

  return setmetatable({
    base_url = base_url,
    access_token = access_token,
    url_secret = url_secret,
    timeout = validate_timeout(options.timeout or 60),
    ca_file = options.ca_file or os.getenv("SNAPFORGE_CA_FILE"),
    transport = options.transport,
  }, Client)
end

function Client:_endpoint(path)
  if self.url_secret == "" then return self.base_url .. path end
  return self.base_url .. "/client/" .. segment(self.url_secret) .. path
end

function Client:_perform(method, url, options)
  options = options or {}
  local timeout = validate_timeout(options.timeout or self.timeout)
  local headers = { Accept = "application/json" }

  if options.headers ~= nil and type(options.headers) ~= "table" then
    fail("headers must be a table", 3)
  end
  for name, value in pairs(options.headers or {}) do
    if tostring(name):lower() ~= "authorization" then headers[name] = tostring(value) end
  end

  if options.include_auth ~= false and self.access_token ~= "" then
    headers.Authorization = "Bearer " .. self.access_token
  end
  if options.idempotency_key ~= nil and tostring(options.idempotency_key) ~= "" then
    headers["Idempotency-Key"] = tostring(options.idempotency_key)
  end
  if options.body ~= nil then headers["Content-Type"] = "application/json" end

  local spec = {
    method = method,
    url = url,
    headers = headers,
    body = options.body,
    timeout = timeout,
    ca_file = self.ca_file,
  }
  if self.transport then return normalize_transport_response(self.transport(spec)) end
  return normalize_transport_response(default_transport(spec))
end

function Client:_raise_http(status, body, quota, transport_error)
  local safe_body = redact(body, {self.access_token, self.url_secret})
  local detail = ""
  if type(safe_body) == "table" and safe_body.error ~= nil and type(safe_body.error) ~= "table" then
    detail = tostring(safe_body.error)
  elseif type(safe_body) == "string" then
    detail = safe_body
  elseif transport_error then
    detail = tostring(transport_error)
  end

  local message = "SnapForge request failed: HTTP " .. tostring(status)
  if detail ~= "" then message = message .. " " .. detail end
  message = redact(message, {self.access_token, self.url_secret})

  error(setmetatable({
    message = message,
    status = status,
    body = safe_body,
    quota = quota,
    name = "SnapForgeError",
  }, SnapForgeError), 3)
end

function Client:_api_call(method, url, options)
  local response = self:_perform(method, url, options)
  local body = decode_body(response.body)
  local quota = quota_from(response.headers, body)
  if response.status < 200 or response.status >= 300 then
    self:_raise_http(response.status, body, quota, response.transport_error)
  end
  return { status = response.status, body = body, quota = quota, headers = response.headers }
end

function Client:_binary_call(method, url, options)
  local response = self:_perform(method, url, options)
  local quota = quota_from(response.headers, nil)
  if response.status < 200 or response.status >= 300 then
    self:_raise_http(response.status, decode_body(response.body), quota, response.transport_error)
  end
  return {
    status = response.status,
    content = response.body or "",
    quota = quota,
    headers = response.headers,
  }
end

function Client:request(path, options)
  options = options or {}
  local safe_path = public_path(path)
  local method = tostring(options.method or "GET"):upper()
  if not ({GET=true, POST=true, PUT=true, PATCH=true, DELETE=true})[method] then
    fail("method must be GET, POST, PUT, PATCH, or DELETE", 2)
  end
  return self:_api_call(method, self:_endpoint(safe_path), {
    body = options.body,
    headers = options.headers or {},
    idempotency_key = options.idempotency_key,
    timeout = options.timeout or self.timeout,
  })
end

function Client:service_info()
  return self:_api_call("GET", self.base_url .. "/api/v1")
end

function Client:capture(url, options)
  options = options or {}
  nonempty(url, "capture requires a url")
  local device = tostring(options.device or "both")
  if device ~= "desktop" and device ~= "mobile" and device ~= "both" then
    fail("device must be desktop, mobile, or both", 2)
  end
  local body = {
    url = tostring(url),
    device = device,
    fullPage = options.full_page == nil and true or not not options.full_page,
    delayMs = tonumber(options.delay_ms or 1200),
  }
  if options.ttl_seconds ~= nil then body.ttlSeconds = tonumber(options.ttl_seconds) end
  return self:_api_call("POST", self:_endpoint("/api/v1/screenshot"), {
    body = body,
    idempotency_key = options.idempotency_key,
  })
end

function Client:context(url, options)
  options = options or {}
  nonempty(url, "context requires a url")
  local viewport = tostring(options.viewport or "desktop")
  if viewport ~= "desktop" and viewport ~= "mobile" then
    fail("viewport must be desktop or mobile", 2)
  end
  local body = {
    url = tostring(url),
    viewport = viewport,
    delayMs = tonumber(options.delay_ms or 800),
  }
  if options.max_text_chars ~= nil then body.maxTextChars = tonumber(options.max_text_chars) end
  return self:_api_call("POST", self:_endpoint("/api/v1/page/context"), {
    body = body,
    idempotency_key = options.idempotency_key,
  })
end

function Client:get_job(job_id)
  nonempty(job_id, "get_job requires a job_id")
  return self:_api_call("GET", self:_endpoint("/api/screenshots/jobs/" .. segment(job_id)))
end

function Client:download_job(job_id)
  nonempty(job_id, "download_job requires a job_id")
  return self:_binary_call("GET", self:_endpoint("/api/screenshots/jobs/" .. segment(job_id) .. "/download"))
end

function Client:download_job_file(job_id, file_name, options)
  options = options or {}
  nonempty(job_id, "download_job_file requires a job_id")
  nonempty(file_name, "download_job_file requires a file_name")
  local path = "/api/screenshots/jobs/" .. segment(job_id) .. "/files/" .. segment(file_name)
  if options.download then path = path .. "?download=1" end
  return self:_binary_call("GET", self:_endpoint(path))
end

function Client:download(url)
  nonempty(url, "download requires a url")
  url = tostring(url)
  if url:sub(1, 1) == "/" then url = self.base_url .. url end
  if not url:match("^https?://") then
    fail("download url must be absolute http(s) or root-relative", 2)
  end
  local same_origin = url == self.base_url or url:sub(1, #self.base_url + 1) == self.base_url .. "/"
  return self:_binary_call("GET", url, { include_auth = same_origin })
end

snapforge.Client = Client
snapforge.Error = SnapForgeError

return snapforge
