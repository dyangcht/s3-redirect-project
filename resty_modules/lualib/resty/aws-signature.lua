--[[
Copyright 2018 JobTeaser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--]]

local cjson = require('cjson')
local resty_hmac = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local str = require('resty.string')
local http = require('resty.http')

local _M = { _VERSION = '0.1.2' }

local function get_secretKey(accessKey)
  local secretKey = ""
  local url = "http://192.168.61.140:8080/api/users/key/" .. accessKey
  local httpc = http.new()

  local res, err = httpc:request_uri(url, {
    method = "GET"
  })
  if res then
    ngx.log(ngx.INFO, "Status: " .. res.status)
    ngx.log(ngx.INFO, "Body: " .. res.body)
    secretKey = res.body
  else
    ngx.log(ngx.ERR, "Error: " .. err)
  end
  http:close()
  return secretKey
end

local function get_credentials ()
  local access_key = os.getenv('AWS_ACCESS_KEY_ID')
  local secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
  ngx.log(ngx.ERR, "key: " .. access_key .. "\n secret: " .. secret_key)
  local str = ngx.req.get_headers()["authz"]
  ngx.log(ngx.DEBUG, "Authz content: " .. str)
  local start_pos, end_pos = string.find(str, "Credential=(.-)/")
  if start_pos and end_pos then
    local credential = string.sub(str, start_pos + 11, end_pos - 1)
    ngx.log(ngx.INFO, "Credential: " .. credential)
    access_key = credential
    secret_key = get_secretKey(credential)
    ngx.log(ngx.INFO, "Secret Key: " .. secret_key)
  else
    ngx.log(ngx.INFO, "未找到 Credential 字串")
  end
  return {
    access_key = access_key,
    secret_key = secret_key
  }
end

local function get_iso8601_basic(timestamp)
  return os.date('!%Y%m%dT%H%M%SZ', timestamp)
end

local function get_iso8601_basic_short(timestamp)
  return os.date('!%Y%m%d', timestamp)
end

local function get_derived_signing_key(keys, timestamp, region, service)
  local h_date = resty_hmac:new('AWS4' .. keys['secret_key'], resty_hmac.ALGOS.SHA256)
  h_date:update(get_iso8601_basic_short(timestamp))
  local k_date = h_date:final()

  local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
  h_region:update(region)
  local k_region = h_region:final()

  local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
  h_service:update(service)
  local k_service = h_service:final()

  local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
  h:update('aws4_request')
  return h:final()
end

local function get_cred_scope(timestamp, region, service)
  return get_iso8601_basic_short(timestamp)
    .. '/' .. region
    .. '/' .. service
    .. '/aws4_request'
end

local function get_signed_headers()
  return 'host;x-amz-content-sha256;x-amz-date'
end

local function get_sha256_digest(s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end

local function get_endcoded_query_str()
  local uri_args, err = ngx.req.get_uri_args()
  local next = next
  local keys = {}
  local encode_str = ""

  if err then
    ngx.log(ngx.ERR, "... Capture query string error ...")
  end
  if next(uri_args) == nil then
    ngx.log(ngx.ERR, "... No query string ...")
  end
  for key, val in pairs(uri_args) do
    if type(val) == 'table' then
      ngx.log(ngx.ERR, "val is a table...")
    end
    table.insert(keys, key)
  end
  table.sort(keys)
  -- table.sort(uri_args)
  for i, key in pairs(keys) do
    if tostring(uri_args[key]) == "" then
      ngx.log(ngx.ERR, "After Query String............. " .. i .. ": Empry String")
    else
      ngx.log(ngx.ERR, "After Query String............. " .. i .. ": " .. tostring(uri_args[key]))
    end
    if i > 1 then
      encode_str = encode_str .. "&"
    end
    if uri_args[key] == true then
      encode_str = encode_str .. ngx.escape_uri(key)
    else
      encode_str = encode_str .. ngx.escape_uri(key) .. "=" .. ngx.escape_uri(uri_args[key])
    end
  end
  if encode_str ~= "" then
    -- ngx.log(ngx.ERR, "i String............. " .. i) 
    encode_str = encode_str .. "\n"
  else
    encode_str = "\n"
  end
  return encode_str
end

local function get_hashed_canonical_request(timestamp, host, uri)
  local str = get_endcoded_query_str()
  ngx.log(ngx.ERR, "get_hashed_canonical_request: " .. str)
  local digest = get_sha256_digest(ngx.var.request_body)
  local canonical_request = ngx.var.request_method .. '\n'
    -- .. uri .. '\n'
    .. uri .. '\n'
    -- .. ngx.escape_uri('encoding-type') .. '=' .. ngx.escape_uri('url') .. '&'
    -- .. ngx.escape_uri('prefix') .. '=' .. ngx.escape_uri('CTBC/') .. '\n'
    .. str
    -- .. ngx.escape_uri('prefix=CTBC/') .. '\n'
    .. 'host:' .. host .. '\n'
    .. 'x-amz-content-sha256:' .. digest .. '\n'
    .. 'x-amz-date:' .. get_iso8601_basic(timestamp) .. '\n'
    .. '\n'
    .. get_signed_headers() .. '\n'
    .. digest
  return get_sha256_digest(canonical_request)
end

local function get_string_to_sign(timestamp, region, service, host, uri)
  return 'AWS4-HMAC-SHA256\n'
    .. get_iso8601_basic(timestamp) .. '\n'
    .. get_cred_scope(timestamp, region, service) .. '\n'
    .. get_hashed_canonical_request(timestamp, host, uri)
end

local function get_signature(derived_signing_key, string_to_sign)
  local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
  h:update(string_to_sign)
  return h:final(nil, true)
end

local function get_authorization(keys, timestamp, region, service, host, uri)
  local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service)
  local string_to_sign = get_string_to_sign(timestamp, region, service, host, uri)
  local auth = 'AWS4-HMAC-SHA256 '
    .. 'Credential=' .. keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service)
    .. ', SignedHeaders=' .. get_signed_headers()
    .. ', Signature=' .. get_signature(derived_signing_key, string_to_sign)
  return auth
end

local function get_service_and_region(host)
  local patterns = {
    {'s3.amazonaws.com', 's3', 'us-east-1'},
    {'s3-external-1.amazonaws.com', 's3', 'us-east-1'},
    {'s3%-([a-z0-9-]+)%.amazonaws%.com', 's3', 'us-east-1'}
  }

  for i,data in ipairs(patterns) do
    local region = host:match(data[1])
    if region ~= nil and data[3] == nil then
      return data[2], region
    elseif region ~= nil then
      return data[2], data[3]
    end
  end

  return nil, nil
end

function _M.aws_set_headers(host, uri, creds)
  if not creds or not creds.access_key or not creds.secret_key then
    creds = get_credentials()
  end
  local timestamp = tonumber(ngx.time())
  ngx.log(ngx.ERR, "\ntimestamp: " .. get_iso8601_basic(timestamp) .. "\n")
  -- local service, region = get_service_and_region(host)
  local service ='s3'
  local region = 'us-east-1'
  local auth = get_authorization(creds, timestamp, region, service, host, uri)

  ngx.req.set_header('Authorization', auth)
  ngx.req.set_header('Host', host)
  ngx.req.set_header('x-amz-date', get_iso8601_basic(timestamp))
end

function custom_escape_uri(str)
    local encoded_str = ngx.escape_uri(str)
    return string.gsub(encoded_str, "%%2F", "/")
end

function _M.s3_set_headers(host, uri, creds)
  ngx.log(ngx.INFO, "host: " .. host .. "\n custom_uri: " .. custom_escape_uri(uri) .. "\n")
  _M.aws_set_headers(host, custom_escape_uri(uri), creds)
  ngx.req.set_header('x-amz-content-sha256', get_sha256_digest(ngx.var.request_body))
end

return _M
