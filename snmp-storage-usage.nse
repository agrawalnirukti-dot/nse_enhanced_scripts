local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates storage units (disks, memory, swap) on a target via SNMP,
using the HOST-RESOURCES-MIB storage table. Reports each unit's name,
total size, used space, and percentage used. Flags any unit that is
dangerously close to full (over 90% used), which could indicate a
storage-exhaustion risk or a misconfigured/overloaded system.

This information is exposed via SNMP without authentication in many
default configurations (e.g. community string "public"), making it
useful both for system monitoring and for security reconnaissance,
since it reveals internal drive/mount names and resource pressure
without needing any credentials.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-storage-usage <target>
--
-- @output
-- | snmp-storage-usage:
-- |   Physical Memory: 3.85 GB total, 2.10 GB used (54.5%)
-- |   C:\: 250.00 GB total, 235.00 GB used (94.0%)  ** WARNING: nearly full **
-- |_  Virtual Memory: 8.00 GB total, 1.20 GB used (15.0%)

author = "Your Name"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

-- Pulls a value out of the walk() results table for a given OID
local function get_value(tbl, oid)
  for _, entry in ipairs(tbl) do
    if entry.oid == oid then
      return entry.value
    end
  end
  return nil
end

-- Converts raw byte counts into a human-readable size
local function human_size(bytes)
  if bytes >= 1024*1024*1024 then
    return string.format("%.2f GB", bytes / (1024*1024*1024))
  elseif bytes >= 1024*1024 then
    return string.format("%.2f MB", bytes / (1024*1024))
  else
    return string.format("%.2f KB", bytes / 1024)
  end
end

action = function(host, port)

  -- HOST-RESOURCES-MIB::hrStorageTable
  local storage_oid   = "1.3.6.1.2.1.25.2.3.1"
  local descr_field    = "1.3.6.1.2.1.25.2.3.1.3."  -- hrStorageDescr
  local units_field     = "1.3.6.1.2.1.25.2.3.1.4."  -- hrStorageAllocationUnits (bytes per unit)
  local size_field     = "1.3.6.1.2.1.25.2.3.1.5."  -- hrStorageSize (in allocation units)
  local used_field     = "1.3.6.1.2.1.25.2.3.1.6."  -- hrStorageUsed (in allocation units)

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  local status, storageTable = snmpHelper:walk(storage_oid)

  if not status or storageTable == nil or #storageTable == 0 then
    return
  end

  nmap.set_port_state(host, port, "open")

  local results = {}

  for _, entry in ipairs(storageTable) do
    -- Only trigger once per row, on the "descr" field, then pull the rest by index
    if entry.oid:match("^" .. descr_field) then
      local index = entry.oid:sub(#descr_field + 1)
      local descr = entry.value

      local allocUnits = get_value(storageTable, units_field .. index)
      local size        = get_value(storageTable, size_field .. index)
      local used         = get_value(storageTable, used_field .. index)

      if descr and allocUnits and size and used then
        local totalBytes = size * allocUnits
        local usedBytes  = used * allocUnits
        local percent
        if totalBytes > 0 then
          percent = (usedBytes / totalBytes) * 100
        else
          percent = 0
        end

        local line = string.format("%s: %s total, %s used (%.1f%%)",
          descr, human_size(totalBytes), human_size(usedBytes), percent)

        if percent >= 90 then
          line = line .. "  ** WARNING: nearly full **"
        end

        table.insert(results, line)
      end
    end
  end

  if #results == 0 then
    return "Could not retrieve storage information."
  end

  return stdnse.format_output(true, results)
end
