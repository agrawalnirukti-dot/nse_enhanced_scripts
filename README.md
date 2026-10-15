# nse_enhanced_scripts
# Enhanced Nmap SNMP Scripts

Two new Nmap NSE scripts inspired by the reference script `snmp-sysdescr.nse`
by Thomas Buchanan (Nmap project). Created for the Cyber Security course
(Fall Semester 2026-2027), SCOPE, VIT Chennai.

Author: Nirukti Agrawal

## Reference script

`snmp-sysdescr.nse` ships with Nmap and reads only two values over SNMP:
sysDescr and sysUpTime. These scripts are new work inspired by it, not edits
of its code.

## Scripts

### 1. snmp-storage-usage.nse (Enhancement 1: more MIB data)
Walks the HOST-RESOURCES-MIB storage table and reports each disk, memory and
swap unit with total size, used space and percentage used. Flags any unit
over 90% full.

### 2. snmp-insecure-version-check.nse (Enhancement 2: security check)
Tests whether the target accepts SNMPv1 and SNMPv2c with the default
community string "public", and whether it answers an SNMPv3 request.
Warns that v1/v2c send community strings in cleartext.

Note: "SNMPv3: supported" only means the agent replied to a v3 probe. It does
not prove v3 is configured securely.

## Usage

Copy the scripts into Nmap's scripts folder and update the script database:

    sudo cp *.nse /opt/homebrew/share/nmap/scripts/
    sudo nmap --script-updatedb

Run them:

    sudo nmap -sU -p 161 --script snmp-storage-usage <target>
    sudo nmap -sU -p 161 --script snmp-insecure-version-check <target>

The scripts only send read requests. Use them only on systems you are
authorised to test.

## License

Same as Nmap: https://nmap.org/book/man-legal.html
