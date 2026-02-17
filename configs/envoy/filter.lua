-- =======================================================================
-- Envoy Lua Filter - Credential Injection, Rate Limiting, Security
-- =======================================================================
-- Talks to agent-manager (local, no auth) for domain policy lookups.
-- Agent-manager handles both standalone and connected mode internally.

-- Configuration
local CACHE_TTL_SECONDS = 300  -- 5 minutes
local CP_FAILURE_BACKOFF = 30  -- Seconds to wait before retrying after failure

-- Unified domain policy cache: domain -> {policy, expires_at}
local domain_policy_cache = {}
local token_buckets = {}     -- domain -> {tokens, last_refill}

-- Agent-manager health tracking
local cp_available = true
local cp_last_failure = 0

-- =======================================================================
-- Utility Functions
-- =======================================================================

-- Check if agent-manager should be contacted
function should_contact_cp()
  -- Backoff after failure
  if not cp_available and (os.time() - cp_last_failure) < CP_FAILURE_BACKOFF then
    return false
  end
  return true
end

-- Mark agent-manager as failed (for backoff)
function mark_cp_failure()
  cp_available = false
  cp_last_failure = os.time()
end

-- Mark agent-manager as available
function mark_cp_success()
  cp_available = true
end

-- Check if host is a devbox.local alias
function is_devbox_local(host)
  local host_clean = string.match(host, "^([^:]+)") or host
  return string.match(host_clean, "%.devbox%.local$") ~= nil
end

-- Clean host (remove port)
function clean_host(host)
  return string.match(host, "^([^:]+)") or host
end

-- DNS Tunneling Detection
function detect_dns_tunneling(host)
  local parts = {}
  for part in string.gmatch(host, "[^%.]+") do
    table.insert(parts, part)
  end

  for _, part in ipairs(parts) do
    if string.len(part) > 63 then
      return true, "Subdomain exceeds 63 characters"
    end
  end

  if string.len(host) > 100 then
    return true, "Hostname unusually long"
  end

  -- Excessive subdomain depth (normal domains rarely exceed 4 levels)
  if #parts > 6 then
    return true, "Excessive subdomain depth"
  end

  -- High entropy / hex-like labels (common in DNS tunneling)
  local suspicious_labels = 0
  for _, part in ipairs(parts) do
    if string.len(part) > 20 and string.match(part, "^[%x%-]+$") then
      suspicious_labels = suspicious_labels + 1
    end
  end
  if suspicious_labels >= 2 then
    return true, "Multiple hex-encoded subdomain labels"
  end

  return false, nil
end

-- URL encode for query params
function url_encode(str)
  if str then
    str = string.gsub(str, "([^%w%-%.%_%~])", function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  end
  return str
end

-- =======================================================================
-- Wildcard Domain Matching Helper
-- =======================================================================

function match_domain_wildcard(domain, tbl)
  local domain_lower = string.lower(domain)
  local exact = tbl[domain_lower]
  if exact ~= nil then return exact end
  for pattern, value in pairs(tbl) do
    if string.sub(pattern, 1, 2) == "*." then
      local suffix = string.sub(pattern, 2)  -- e.g. ".github.com"
      if domain_lower == string.sub(pattern, 3) then
        -- Bare domain match: github.com matches *.github.com
        return value
      elseif string.len(domain_lower) > string.len(suffix)
          and string.sub(domain_lower, -string.len(suffix)) == suffix then
        -- Subdomain match with dot boundary: api.github.com matches,
        -- but notgithub.com does not (length check ensures a preceding char exists)
        return value
      end
    end
  end
  return nil
end

-- =======================================================================
-- Unified Domain Policy (talks to local agent-manager)
-- =======================================================================

function get_domain_policy(request_handle, domain)
  local host_clean = string.match(domain, "^([^:]+)") or domain

  -- Check cache first
  local cached = domain_policy_cache[host_clean]
  if cached and cached.expires_at > os.time() then
    return cached.policy
  end

  local policy = nil

  -- Query agent-manager (local, no auth needed)
  if should_contact_cp() then
    local headers, body = request_handle:httpCall(
      "control_plane_api",
      {
        [":method"] = "GET",
        [":path"] = "/api/v1/domain-policies/for-domain?domain=" .. url_encode(host_clean),
        [":authority"] = "agent-manager"
      },
      "",
      5000,
      false
    )

    if body and string.len(body) > 0 then
      mark_cp_success()
      policy = parse_domain_policy_response(body)
    else
      mark_cp_failure()
    end
  end

  -- If agent-manager is unreachable, create a minimal deny policy
  if not policy then
    policy = {
      matched = false,
      allowed_paths = {},
      requests_per_minute = 120,
      burst_size = 20,
      credential = nil,
      target_domain = nil
    }
  end

  -- Cache the result
  domain_policy_cache[host_clean] = {
    policy = policy,
    expires_at = os.time() + CACHE_TTL_SECONDS
  }

  return policy
end

function parse_domain_policy_response(body)
  if not body or body == "" then
    return nil
  end

  local policy = {
    matched = string.match(body, '"matched"%s*:%s*true') ~= nil,
    allowed_paths = {},
    requests_per_minute = tonumber(string.match(body, '"requests_per_minute"%s*:%s*(%d+)')) or 120,
    burst_size = tonumber(string.match(body, '"burst_size"%s*:%s*(%d+)')) or 20,
    credential = nil,
    target_domain = nil
  }

  -- Parse allowed_paths array
  local paths_str = string.match(body, '"allowed_paths"%s*:%s*%[([^%]]*)%]')
  if paths_str then
    for path in string.gmatch(paths_str, '"([^"]+)"') do
      table.insert(policy.allowed_paths, path)
    end
  end

  -- Parse credential
  local cred_header = string.match(body, '"header_name"%s*:%s*"([^"]*)"')
  local cred_value = string.match(body, '"header_value"%s*:%s*"([^"]*)"')
  local target = string.match(body, '"target_domain"%s*:%s*"([^"]*)"')
  if cred_header and cred_value then
    policy.credential = {
      header_name = cred_header,
      header_value = cred_value
    }
    policy.target_domain = target
  end

  -- Parse alias for domain rewriting
  local alias = string.match(body, '"alias"%s*:%s*"([^"]*)"')
  if alias then
    policy.alias = alias
  end

  return policy
end

-- =======================================================================
-- Path Filtering
-- =======================================================================

function match_path_pattern(pattern, path)
  if string.sub(pattern, -2) == "/*" then
    local prefix = string.sub(pattern, 1, -2)
    return string.sub(path, 1, string.len(prefix)) == prefix
  elseif string.sub(pattern, -1) == "*" then
    local prefix = string.sub(pattern, 1, -2)
    return string.sub(path, 1, string.len(prefix)) == prefix
  else
    return path == pattern
  end
end

function is_path_allowed(policy, path)
  -- No paths defined = all paths allowed
  if not policy.allowed_paths or #policy.allowed_paths == 0 then
    return true, "no_restrictions"
  end

  -- Check each pattern
  for _, pattern in ipairs(policy.allowed_paths) do
    if match_path_pattern(pattern, path) then
      return true, pattern
    end
  end

  return false, "path_not_in_allowlist"
end

-- =======================================================================
-- Rate Limiting
-- =======================================================================

-- Rate limiter with explicit config (for unified policy)
function check_rate_limit_with_config(request_handle, domain, rpm, burst)
  local host_clean = string.match(domain, "^([^:]+)") or domain
  local now = os.time()
  local bucket = token_buckets[host_clean]

  if not bucket then
    bucket = {
      tokens = burst,
      last_refill = now
    }
    token_buckets[host_clean] = bucket
  end

  -- Refill tokens
  local elapsed = now - bucket.last_refill
  local tokens_per_second = rpm / 60.0
  local new_tokens = elapsed * tokens_per_second
  bucket.tokens = math.min(burst, bucket.tokens + new_tokens)
  bucket.last_refill = now

  if bucket.tokens >= 1 then
    bucket.tokens = bucket.tokens - 1
    return true
  end

  request_handle:logWarn(string.format(
    "Rate limit exceeded for %s (limit: %d rpm)",
    host_clean, rpm
  ))
  return false
end

-- =======================================================================
-- Request / Response Handlers
-- =======================================================================

function envoy_on_request(request_handle)
  local host = request_handle:headers():get(":authority") or ""
  local host_clean = string.lower(clean_host(host))
  local credential_injected = "false"
  local rate_limited = "false"
  local devbox_local = is_devbox_local(host)

  -- Skip DNS tunneling check for devbox.local (it's internal)
  if not devbox_local then
    local is_suspicious, reason = detect_dns_tunneling(host)
    if is_suspicious then
      request_handle:logWarn("Potential DNS tunneling: " .. host .. " - " .. reason)
      request_handle:respond(
        {[":status"] = "403"},
        "Request blocked: suspicious hostname pattern"
      )
      return
    end
  end

  -- Get unified domain policy (single call to agent-manager)
  local policy = get_domain_policy(request_handle, host_clean)
  local real_domain = host_clean
  if policy and policy.target_domain then
    real_domain = policy.target_domain
  end

  -- Rate limiting using policy
  local rpm = policy and policy.requests_per_minute or 120
  local burst = policy and policy.burst_size or 20
  if not check_rate_limit_with_config(request_handle, real_domain, rpm, burst) then
    rate_limited = "true"
    request_handle:headers():add("X-Rate-Limited", rate_limited)
    request_handle:respond(
      {[":status"] = "429", ["retry-after"] = "60"},
      '{"error": "rate_limit_exceeded", "message": "Too many requests to this domain"}'
    )
    return
  end

  -- Path allowlist check using policy
  local request_path = request_handle:headers():get(":path") or "/"
  local path_only = string.match(request_path, "^([^?]+)") or request_path
  local path_allowed, path_reason = is_path_allowed(policy, path_only)
  if not path_allowed then
    request_handle:logWarn(string.format(
      "Path not allowed: %s%s (reason: %s)",
      real_domain, path_only, path_reason
    ))
    request_handle:respond(
      {[":status"] = "403"},
      '{"error": "path_not_allowed", "message": "This path is not in the allowlist for this domain"}'
    )
    return
  end

  -- Store domain in per-stream metadata (concurrency-safe)
  request_handle:streamInfo():dynamicMetadata():set(
    "envoy.filters.http.lua", "request_domain", real_domain
  )

  -- Credential injection using policy
  if policy and policy.credential and policy.credential.header_name and policy.credential.header_value then
    request_handle:headers():remove(policy.credential.header_name)
    request_handle:headers():add(policy.credential.header_name, policy.credential.header_value)
    credential_injected = "true"
  end

  -- Add tracking headers for access log
  request_handle:headers():add("X-Credential-Injected", credential_injected)
  request_handle:headers():add("X-Rate-Limited", rate_limited)
  request_handle:headers():add("X-Real-Domain", real_domain)
  request_handle:headers():add("X-Devbox-Timestamp", os.date("!%Y-%m-%dT%H:%M:%SZ"))

  if devbox_local then
    request_handle:logInfo(string.format(
      "Devbox proxy: %s -> %s (credential_injected=%s)",
      host, real_domain, credential_injected
    ))
  end
end

function envoy_on_response(response_handle)
  -- no-op: response handler reserved for future use
end
