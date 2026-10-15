local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks which SNMP protocol versions a target device accepts. SNMP
versions 1 and 2c authenticate using a "community string" that is sent
in plain, unencrypted text -- meaning anyone who can observe network
traffic (e.g. on the same LAN) can capture it and gain full read (or
even write) access to the device. SNMPv3 fixes this by supporting real
authentication and encryption.

This script actively tests whether a device responds to SNMPv1 and
SNMPv2c requests using a common default community string ("public"),
and separately checks whether it answers an SNMPv3 request. It reports
a clear warning if the insecure legacy versions are still enabled,
since this is a well-known and still common real-world misconfiguration.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-insecure-version-check <target>
--
-- @output
-- | snmp-insecure-version-check:
-- |   SNMPv1 (community "public"): ACCEPTED  ** INSECURE: cleartext community string **
-- |   SNMPv2c (community "public"): ACCEPTED  ** INSECURE: cleartext community string **
-- |_  SNMPv3: supported

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "safe", "vuln"}

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

-- Tries a GET of sysDescr.0 using the given SNMP version (0 = v1, 1 = v2c)
-- and the given community string. Returns true if the device responds.
-- The version and community are passed to Helper:new, which is how
-- Nmap's snmp library expects them to be set.
local function try_version(host, port, version, community)
  local snmpHelper = snmp.Helper:new(host, port, community,
    {version = version, timeout = 2000})
  snmpHelper:connect()

  local status, response = snmpHelper:get({reqId=1234}, "1.3.6.1.2.1.1.1.0")

  if status and response and response[1] then
    return true
  end
  return false
end

-- Raw SNMPv3 probe packet (same technique used by Nmap's own snmp-info.nse),
-- since the snmp library does not natively build SNMPv3 packets.
local SNMPv3GetRequest = "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\0\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\0\x02\x01\0\x02\x01\0\x04\0\x04\0\x04\0\x30\x12\x04\0\x04\0\xa0\x0c\x02\x02\x37\xf0\x02\x01\0\x02\x01\0\x30\0"

local function try_v3(host, port)
  local status, response = comm.exchange(host, port, SNMPv3GetRequest)
  if not status then
    return false
  end

  local decoded = snmp.decode(response)
  -- A valid SNMPv3 response starts with version number 3
  if decoded and decoded[1] == 3 then
    return true
  end
  return false
end

action = function(host, port)

  local results = {}
  local insecure_found = false

  -- Test SNMPv1
  local v1_ok = try_version(host, port, 0, "public")
  if v1_ok then
    table.insert(results, "SNMPv1 (community \"public\"): ACCEPTED  ** INSECURE: cleartext community string **")
    insecure_found = true
  else
    table.insert(results, "SNMPv1 (community \"public\"): not accepted")
  end

  -- Test SNMPv2c
  local v2c_ok = try_version(host, port, 1, "public")
  if v2c_ok then
    table.insert(results, "SNMPv2c (community \"public\"): ACCEPTED  ** INSECURE: cleartext community string **")
    insecure_found = true
  else
    table.insert(results, "SNMPv2c (community \"public\"): not accepted")
  end

  -- Test SNMPv3
  local v3_ok = try_v3(host, port)
  if v3_ok then
    table.insert(results, "SNMPv3: supported")
  else
    table.insert(results, "SNMPv3: not detected")
  end

  if v1_ok or v2c_ok then
    nmap.set_port_state(host, port, "open")
  end

  if insecure_found then
    table.insert(results, "")
    table.insert(results, "Recommendation: disable SNMPv1/v2c and use SNMPv3 with authentication and encryption.")
  end

  return stdnse.format_output(true, results)
end
