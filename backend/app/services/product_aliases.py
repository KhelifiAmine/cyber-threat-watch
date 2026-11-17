"""
Product Alias Registry — Static lookup for normalizing vendor and product names.

Used by:
- inventory_parser.py: normalize Excel imports
- matching_engine.py: normalize before exact matching
- vendor spiders: can import for consistency
"""

import re

# ─── Vendor Normalization ──────────────────────────────────

VENDOR_ALIASES = {
    "fortinet": "Fortinet",
    "forti": "Fortinet",
    "cisco": "Cisco",
    "cisco systems": "Cisco",
    "microsoft": "Microsoft",
    "microsoft corp": "Microsoft",
    "microsoft corporation": "Microsoft",
    "vmware": "VMware",
    "broadcom": "VMware",  # VMware is now Broadcom
    "red hat": "Red Hat",
    "redhat": "Red Hat",
    "linux": "Linux",
    "canonical": "Linux",  # Ubuntu
    "debian": "Linux",
    "centos": "Linux",
    "sophos": "Sophos",
    "baracuda": "Barracuda",
    "barracuda": "Barracuda",
    "barracuda networks": "Barracuda",
}

# ─── Product Family Normalization ──────────────────────────

PRODUCT_FAMILY_MAP = {
    # Fortinet
    ("Fortinet", "fortigate"): "FortiGate",
    ("Fortinet", "fortios"): "FortiGate",  # FortiOS runs on FortiGate
    ("Fortinet", "fortiweb"): "FortiWeb",
    ("Fortinet", "fortianalyzer"): "FortiAnalyzer",
    ("Fortinet", "fortiadc"): "FortiADC",
    ("Fortinet", "forticlient"): "FortiClient",
    ("Fortinet", "forticlientems"): "FortiClientEMS",
    ("Fortinet", "fortimanager"): "FortiManager",
    ("Fortinet", "fortimail"): "FortiMail",
    ("Fortinet", "fortisandbox"): "FortiSandbox",
    ("Fortinet", "fortiswitch"): "FortiSwitch",
    ("Fortinet", "fortiap"): "FortiAP",
    ("Fortinet", "fortiproxy"): "FortiProxy",
    ("Fortinet", "fortisiem"): "FortiSIEM",
    ("Fortinet", "fortisoar"): "FortiSOAR",
    ("Fortinet", "fortiedr"): "FortiEDR",
    ("Fortinet", "fortivoice"): "FortiVoice",
    ("Fortinet", "fortiddos"): "FortiDDoS",
    ("Fortinet", "fortiextender"): "FortiExtender",
    ("Fortinet", "fortipam"): "FortiPAM",
    ("Fortinet", "fortiportal"): "FortiPortal",
    ("Fortinet", "fortitester"): "FortiTester",
    ("Fortinet", "fortirecorder"): "FortiRecorder",
    ("Fortinet", "fortideceptor"): "FortiDeceptor",
    ("Fortinet", "fortitoken"): "FortiToken",
    ("Fortinet", "fortiauthenticator"): "FortiAuthenticator",
    ("Fortinet", "fortiwan"): "FortiWAN",
    # Cisco
    ("Cisco", "ios xe"): "IOS XE",
    ("Cisco", "ios xr"): "IOS XR",
    ("Cisco", "ios"): "IOS",
    ("Cisco", "nx-os"): "NX-OS",
    ("Cisco", "nxos"): "NX-OS",
    ("Cisco", "asa"): "ASA",
    ("Cisco", "adaptive security appliance"): "ASA",
    ("Cisco", "firepower"): "Firepower",
    ("Cisco", "ftd"): "Firepower",
    ("Cisco", "firepower threat defense"): "Firepower",
    ("Cisco", "ise"): "ISE",
    ("Cisco", "cisco ise"): "ISE",
    ("Cisco", "identity services engine"): "ISE",
    ("Cisco", "webex"): "Webex",
    ("Cisco", "meraki"): "Meraki",
    ("Cisco", "duo"): "Duo",
    ("Cisco", "anyconnect"): "AnyConnect",
    ("Cisco", "umbrella"): "Umbrella",
    # Microsoft
    ("Microsoft", "windows server"): "Windows Server",
    ("Microsoft", "windows 10"): "Windows 10",
    ("Microsoft", "windows 11"): "Windows 11",
    ("Microsoft", "windows 7"): "Windows 7",
    ("Microsoft", "windows 8"): "Windows 8",
    ("Microsoft", "exchange server"): "Exchange Server",
    ("Microsoft", "exchange"): "Exchange Server",
    ("Microsoft", "sharepoint"): "SharePoint",
    ("Microsoft", "azure"): "Azure",
    ("Microsoft", "office"): "Office",
    ("Microsoft", "365"): "Office",
    ("Microsoft", ".net"): ".NET",
    ("Microsoft", "sql server"): "SQL Server",
    ("Microsoft", "edge"): "Edge",
    # VMware
    ("VMware", "esxi"): "ESXi",
    ("VMware", "vsphere"): "vSphere",
    ("VMware", "vcenter"): "vCenter",
    ("VMware", "nsx"): "NSX",
    ("VMware", "horizon"): "Horizon",
    ("VMware", "workstation"): "Workstation",
    # Linux / Red Hat
    ("Linux", "rhel"): "RHEL",
    ("Linux", "red hat enterprise"): "RHEL",
    ("Linux", "ubuntu"): "Ubuntu",
    ("Linux", "debian"): "Debian",
    ("Linux", "centos"): "CentOS",
    ("Linux", "centos stream"): "CentOS",
    ("Red Hat", "rhel"): "RHEL",
    ("Red Hat", "red hat enterprise"): "RHEL",
    ("Red Hat", "openshift"): "OpenShift",
    ("Red Hat", "ansible"): "Ansible",
    # Sophos
    ("Sophos", "sfos"): "Sophos Firewall",
    ("Sophos", "sophos firewall"): "Sophos Firewall",
    ("Sophos", "xg firewall"): "Sophos Firewall",
    ("Sophos", "intercept x"): "Intercept X",
    # Barracuda
    ("Barracuda", "load balancer"): "Load Balancer ADC",
    ("Barracuda", "load balancer adc"): "Load Balancer ADC",
    ("Barracuda", "waf"): "WAF",
    ("Barracuda", "web application firewall"): "WAF",
    ("Barracuda", "email security gateway"): "Email Security Gateway",
}


def normalize_vendor(raw: str):
    """Returns clean vendor name or None if not recognized."""
    if not raw:
        return None
    key = raw.strip().lower()
    return VENDOR_ALIASES.get(key)


def normalize_product_family(vendor: str, product_raw: str):
    """Returns product family or None if not in the alias map."""
    if not vendor or not product_raw:
        return None
    # Strip hardware model suffixes, version numbers, etc.
    cleaned = product_raw
    # Remove vendor prefix if present
    cleaned = re.sub(re.escape(vendor), '', cleaned, flags=re.IGNORECASE)
    # Remove model suffixes: "HA", "LP", "DC", "64-bit", build numbers, version numbers
    cleaned = re.sub(
        r'\b(ha|lp|dc|64-bit|32-bit|build\s*\d+|v\d[\d.]*|\d+[\d.]*[a-z]*)\b',
        '', cleaned, flags=re.IGNORECASE
    )
    # Remove parenthesized suffixes
    cleaned = re.sub(r'\([^)]*\)', '', cleaned)
    # Collapse whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip().lower()

    return PRODUCT_FAMILY_MAP.get((vendor, cleaned))
