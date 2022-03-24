local resty_random = require "resty.random"
local str = require "resty.string"
local mysql = require "resty.mysql"
local cjson = require "cjson"

local _M = {}

function table_size(T)
  local count = 0
  for _ in pairs(T) do count = count + 1 end
  return count
end

function split(input, sep)
  if sep == nil then
    sep = "%s"
  end

  local t = {}

  for str in string.gmatch(input, "([^" .. sep .. "]+)") do
    table.insert(t, str)
  end

  return t
end

function get_apex_domain(hostname)
  local pieces = split(hostname, ".")
  local table_size = table_size(pieces)

  if table_size > 2 then
    return pieces[#pieces - 1] .. "." .. pieces[#pieces]
  elseif table_size == 2 then
    return pieces[1] .. "." .. pieces[2]
  end

  return nil
end

function get_subdomain(hostname)
  local pieces = split(hostname, ".")

  if table_size(pieces) > 2 then
    return pieces[1]
  end

  return nil
end

function mysql_adapter()
  local db = mysql:new()
  local ok, err, errcode, state = db:connect({
    host = "",
    port = 3306,
    database = "",
    user = "",
    password = "",
    ssl = true,
  })

  if not ok then
    ngx.log(ngx.ERR, "failed to connect: ", err, ": ", errcode, " ", state)
    return nil, err
  end

  return db
end

function delete_cert_from_db(hub_domain_id, subdomain)
  local db, err = mysql_adapter()
  local sql = "DELETE FROM m3_hub_domain_certificates WHERE (hub_domain_id = " .. hub_domain_id .. ")"

  if err then
    ngx.log(ngx.ERR, err)
    return false
  end
  
  if subdomain ~= nil then 
    sql = sql .. " AND (subdomain = '" .. subdomain .. "')"
  else
    sql = sql .. " AND (subdomain = '')"
  end
 
  res, err, errcode, state = db:query(sql)

  if err then
    ngx.log(ngx.ERR, "there was an error deleting the certificate for " .. subdomain .. " (hub_domain_id: " .. hub_domain_id .. "): " .. err)
    return false
  end

  return true
end

function get_cert_from_db(apex_domain, subdomain)
  local db, err = mysql_adapter()
  local sql = "SELECT CONCAT(m3_hub_domain_certificates.subdomain, '.', m3_hub_domains.domain) as domain, m3_hub_domain_certificates.hub_domain_id, m3_hub_domain_certificates.cert_pem, m3_hub_domain_certificates.fullchain_pem, m3_hub_domain_certificates.privkey_pem, m3_hub_domain_certificates.expiry FROM m3_hub_domain_certificates INNER JOIN m3_hub_domains ON (m3_hub_domain_certificates.hub_domain_id = m3_hub_domains.id) WHERE (m3_hub_domains.domain = '" .. apex_domain .. "') AND (m3_hub_domain_certificates.deleted_at IS NULL) AND (m3_hub_domains.deleted_at IS NULL)"

  if err then
    return nil, err
  end

  if db == nil then
    return nil
  end

  if subdomain ~= nil then
    sql = sql .. " AND (m3_hub_domain_certificates.subdomain = '" .. subdomain .. "')"
  else
    sql = sql .. " AND (m3_hub_domain_certificates.subdomain = '')"
  end

  res, err, errcode, state = db:query(sql)

  if err then
    return nil, err
  end
  
  if table_size(res) < 1 then
    return nil
  end

  return res
end

function get_hub_domain_id(apex_domain)
  local db, err = mysql_adapter()

  if err then
    ngx.log(ngx.ERR, err)
    return false
  end

  res, err, errcode, state = db:query("SELECT id FROM m3_hub_domains WHERE (domain = '" .. apex_domain .. "') AND (deleted_at IS NULL)")

  if err then
    return nil, err
  end

  if (not res or table_size(res) < 1) then
    return nil
  end

  return res[1]["id"]
end

function set_cert_in_db(apex_domain, subdomain, json)
  local db, err = mysql_adapter()

  if err then
    return false, err
  end

  cert, err = cjson.decode(json)

  if err then
    return false, err
  end

  domain_cert, err = get_cert_from_db(apex_domain, subdomain)

  if err then
    return false, err
  end

  if domain_cert == nil or table_size(domain_cert) < 1 then
    hub_domain_id, err = get_hub_domain_id(apex_domain)

    if err then
      ngx.log(ngx.ERR, err)
      return false
    end

    if hub_domain_id == nil then
      ngx.log(ngx.ERR, "no hub_domain_id found")
      return false
    end

    if subdomain == nil then
      _, err, errcode, state = db:query("INSERT INTO m3_hub_domain_certificates (hub_domain_id, subdomain, cert_pem, privkey_pem, fullchain_pem, expiry) VALUES (" .. hub_domain_id .. ", '', '" .. cert["cert_pem"] .. "', '" .. cert["privkey_pem"] .. "', '" .. cert["fullchain_pem"] .. "', " .. tonumber(cert["expiry"]) .. ") ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), fullchain_pem = VALUES(fullchain_pem), privkey_pem = VALUES(privkey_pem), expiry = VALUES(expiry)")
    else
      _, err, errcode, state = db:query("INSERT INTO m3_hub_domain_certificates (hub_domain_id, subdomain, cert_pem, privkey_pem, fullchain_pem, expiry) VALUES (" .. hub_domain_id .. ", '" .. subdomain .. "', '" .. cert["cert_pem"] .. "', '" .. cert["privkey_pem"] .. "', '" .. cert["fullchain_pem"] .. "', " .. tonumber(cert["expiry"]) .. ") ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), fullchain_pem = VALUES(fullchain_pem), privkey_pem = VALUES(privkey_pem), expiry = VALUES(expiry)")
    end

    if err then
      return false, err
    end
  end

  return true
end

function _M.new(options)
  assert(options)
  assert(options["adapter"])
  assert(options["json_adapter"])

  return setmetatable(options, { __index = _M })
end

function _M.get_challenge(self, domain, path)
  return self.adapter:get(domain .. ":challenge:" .. path)
end

function _M.set_challenge(self, domain, path, value)
  return self.adapter:set(domain .. ":challenge:" .. path, value)
end

function _M.delete_challenge(self, domain, path)
  return self.adapter:delete(domain .. ":challenge:" .. path)
end

function _M.get_cert(self, domain, renewal)
  local json, err = self.adapter:get(domain .. ":latest")
  local apex_domain = get_apex_domain(domain)
  local subdomain = get_subdomain(domain)
  local db = mysql_adapter()

  if (type(json) == 'string' and json ~= "{}") and not err then
    res, err = get_cert_from_db(apex_domain, subdomain)

    if err then
      return nil, err
    end

    if (not res or table_size(res) < 1) then
      _, err = set_cert_in_db(apex_domain, subdomain, json)

      if err then
        ngx.log(ngx.ERR, err)
      end
    end
  elseif err then
    return nil, err
  elseif (not json or json == '{}') then
    res, err = get_cert_from_db(apex_domain, subdomain)

    if err then
      return nil, err
    end

    if (not res or table_size(res) < 1) then
      return nil
    end

    local hub_domain_id = res[1]["hub_domain_id"]
    local expiry = tonumber(res[1]["expiry"])

    ngx.update_time()

    local now = ngx.now()

    ngx.log(ngx.ERR, "cert_expiry: " .. expiry)
    ngx.log(ngx.ERR, "current_timestamp: " .. now)

    -- The certificate is less than or equal to 30 days out (we should just remove from db for renewal)
    if now + (30 * 24 * 60 * 60) >= expiry then
      ok = delete_cert_from_db(hub_domain_id, subdomain)

      if not ok then
        return nil
      end

      return nil
    end

    -- We're going to re-add the "lost" certificate to redis
    json, json_err = self.json_adapter:encode({
      fullchain_pem = res[1]["fullchain_pem"],
      privkey_pem = res[1]["privkey_pem"],
      cert_pem = res[1]["cert_pem"],
      expiry = tonumber(res[1]["expiry"]),
    })

    if json_err then
      return nil, json_err
    end

    if not json then
      return nil
    end
 
    self.adapter:set(domain .. ":latest", json)
  end

  local data, json_err = self.json_adapter:decode(json)
  if json_err then
    return nil, json_err
  end

  return data
end

function _M.set_cert(self, domain, fullchain_pem, privkey_pem, cert_pem, expiry)
  -- Store the public certificate and private key as a single JSON string.
  --
  -- We use a single JSON string so that the storage adapter just has to store
  -- a single string (regardless of implementation), and we don't have to worry
  -- about race conditions with the public cert and private key being stored
  -- separately and getting out of sync.
  local string, err = self.json_adapter:encode({
    fullchain_pem = fullchain_pem,
    privkey_pem = privkey_pem,
    cert_pem = cert_pem,
    expiry = tonumber(expiry),
  })

  if err then
    return nil, err
  end

  local db, err = mysql_adapter()
  local apex_domain = get_apex_domain(domain)
  local subdomain = get_subdomain(domain)
  local sql = "SELECT id FROM m3_hub_domains WHERE (m3_hub_domains.domain = '" .. apex_domain .. "') AND (m3_hub_domains.deleted_at IS NULL)"

  if err then
    return nil, err
  end

  if apex_domain ~= nil and subdomain ~= nil then
    ngx.log(ngx.ERR, "(" .. apex_domain .. ", " .. subdomain .. ")")
  elseif apex_domain ~= nil and subdomain == nil then
    ngx.log(ngx.ERR, "(" .. apex_domain .. ", '')")
  end

  res, err, errcode, state = db:query(sql)
  ngx.log(ngx.ERR, "m3_hub_domain: " .. self.json_adapter:encode(res))

  if err then
    return nil, err
  end

 -- If we can not find domain_hub_id we store cert in redis. its the only thing we can do
  if table_size(res) < 1 then
    return self.adapter:set(domain .. ":latest", string)
  end

  local hub_domain_id = res[1]["id"]

  if subdomain ~= nil then
    sql = "INSERT INTO m3_hub_domain_certificates (hub_domain_id, subdomain, cert_pem, privkey_pem, fullchain_pem, expiry) VALUES (" .. hub_domain_id .. ", '" .. subdomain .. "', '" .. cert_pem .. "', '" .. privkey_pem .. "', '" .. fullchain_pem .. "', " .. expiry .. ") ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), fullchain_pem = VALUES(fullchain_pem), privkey_pem = VALUES(privkey_pem), expiry = VALUES(expiry)"
  else
    sql = "INSERT INTO m3_hub_domain_certificates (hub_domain_id, subdomain, cert_pem, privkey_pem, fullchain_pem, expiry) VALUES (" .. hub_domain_id .. ", '', '" .. cert_pem .. "', '" .. privkey_pem .. "', '" .. fullchain_pem .. "', " .. expiry .. ") ON DUPLICATE KEY UPDATE cert_pem = VALUES(cert_pem), fullchain_pem = VALUES(fullchain_pem), privkey_pem = VALUES(privkey_pem), expiry = VALUES(expiry)"
  end

  res, err, errcode, state = db:query(sql)

  if err then
    return nil, err
  end

  -- Store the cert under the "latest" alias, which is what this app will use.
  return self.adapter:set(domain .. ":latest", string)
end

function _M.delete_cert(self, domain)
  return self.adapter:delete(domain .. ":latest")
end

function _M.all_cert_domains(self)
  local keys, err = self.adapter:keys_with_suffix(":latest")
  if err then
    return nil, err
  end

  local domains = {}
  for _, key in ipairs(keys) do
    local domain = ngx.re.sub(key, ":latest$", "", "jo")
    table.insert(domains, domain)
  end

  return domains
end

-- A simplistic locking mechanism to try and ensure the app doesn't try to
-- register multiple certificates for the same domain simultaneously.
--
-- This is used in conjunction with resty-lock for local in-memory locking in
-- resty/auto-ssl/ssl_certificate.lua. However, this lock uses the configured
-- storage adapter, so it can work across multiple nginx servers if the storage
-- adapter is something like redis.
--
-- This locking algorithm isn't perfect and probably has some race conditions,
-- but in combination with resty-lock, it should prevent the vast majority of
-- double requests.
function _M.issue_cert_lock(self, domain)
  local key = domain .. ":issue_cert_lock"
  local lock_rand_value = str.to_hex(resty_random.bytes(32))

  -- Wait up to 30 seconds for any existing locks to be unlocked.
  local unlocked = false
  local wait_time = 0
  local sleep_time = 0.5
  local max_time = 30
  repeat
    local existing_value = self.adapter:get(key)
    if not existing_value then
      unlocked = true
    else
      ngx.sleep(sleep_time)
      wait_time = wait_time + sleep_time
    end
  until unlocked or wait_time > max_time

  -- Create a new lock.
  local ok, err = self.adapter:set(key, lock_rand_value, { exptime = 30 })
  if not ok then
    return nil, err
  else
    return lock_rand_value
  end
end

function _M.issue_cert_unlock(self, domain, lock_rand_value)
  local key = domain .. ":issue_cert_lock"

  -- Remove the existing lock if it matches the expected value.
  local current_value, err = self.adapter:get(key)
  if lock_rand_value == current_value then
    return self.adapter:delete(key)
  elseif current_value then
    return false, "lock does not match expected value"
  else
    return false, err
  end
end

return _M
