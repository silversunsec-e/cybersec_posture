#!/bin/bash

# Script: initial_posture_assessment.sh
# Description: Performs a quick, high-impact scan on a subnet to discover easy-to-find
# security misconfigurations and information leakage, suitable for an initial security
# posture assessment.
#
# Usage: ./initial_posture_assessment.sh <subnet_cidr>
# Example: ./initial_posture_assessment.sh 10.0.0.0/24

# --- Configuration ---
SUBNET_CIDR=$1
SCAN_NAME="initial_posture_$(echo $SUBNET_CIDR | sed 's/\//_/g')_$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="posture_reports/$SCAN_NAME"
LIVE_HOSTS_FILE="$OUTPUT_DIR/1_live_hosts.txt"
FULL_SCAN_REPORT="$OUTPUT_DIR/2_security_posture_scan" # Nmap will append .nmap, .xml, .gnmap

# --- FIXED SECTION ---
# Correct Nmap script combination syntax (comma-separated list, properly quoted)
# Using -sC to include the 'default' script set, plus custom scripts.
NMAP_OPTIONS="-sV -T4 -Pn -sC --script ftp-anon,smb-enum-shares,ssl-enum-ciphers"
# --- Configuration End ---

# Function to display the usage message
usage() {
    echo "Usage: $0 <subnet_cidr>"
    echo "Performs a two-step initial security posture assessment."
    exit 1
}

# Pre-flight checks
if [ -z "$SUBNET_CIDR" ]; then
    usage
fi
if ! command -v nmap &> /dev/null; then
    echo "[-] Error: nmap could not be found. Please install it."
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo "[*] Output directory created: $OUTPUT_DIR"
echo "[*] Target Subnet: $SUBNET_CIDR"

# -----------------------------------------------------------
# PHASE 1: Host Discovery (Ping Sweep)
# Find all live hosts quickly before running the deeper scan.
# -----------------------------------------------------------
echo -e "\n--- Phase 1: Host Discovery (Ping Sweep) ---"
echo "[*] Finding all live hosts..."
nmap -sn "$SUBNET_CIDR" -oG - | grep 'Up' | awk '{print $2}' > "$LIVE_HOSTS_FILE"

HOST_COUNT=$(wc -l < "$LIVE_HOSTS_FILE")

if [ $HOST_COUNT -eq 0 ]; then
    echo "[-] No live hosts found in $SUBNET_CIDR. Exiting."
    exit 1
else
    echo "[+] Found $HOST_COUNT live hosts. List saved to $LIVE_HOSTS_FILE"
fi

# -----------------------------------------------------------
# PHASE 2: Deep Security Posture Scan
# Run targeted service version detection and high-impact NSE scripts.
# -----------------------------------------------------------
echo -e "\n--- Phase 2: Targeted Security Scan ---"
echo "[*] Running deep scan with scripts: default + ftp-anon + smb-enum-shares + ssl-enum-ciphers..."
echo "[*] Execution command: nmap $NMAP_OPTIONS -iL $LIVE_HOSTS_FILE -oA $FULL_SCAN_REPORT"

# Execute the Nmap scan
eval nmap $NMAP_OPTIONS -iL "$LIVE_HOSTS_FILE" -oA "$FULL_SCAN_REPORT"

if [ $? -ne 0 ]; then
    echo "[-] Error: Nmap scan failed during execution. Please check your network connectivity."
    exit 1
fi

# -----------------------------------------------------------
# PHASE 3: Summary and High-Impact Findings
# Parse the results for presentation-ready evidence.
# -----------------------------------------------------------
echo -e "\n========================================================================="
echo "               [+] Initial Security Posture Scan Complete [+]             "
echo "========================================================================="

# 1. Look for ANONYMOUS FTP Access (Critical Fail)
ANON_FTP=$(grep -A 5 'Anonymous FTP login allowed' "$FULL_SCAN_REPORT.nmap" | grep 'Host:')
if [ ! -z "$ANON_FTP" ]; then
    echo -e "\n!!! CRITICAL FINDING: ANONYMOUS FTP ACCESS DETECTED !!!"
    echo "Evidence of anonymous FTP access, which allows unauthorized file transfer."
    echo "$ANON_FTP"
else
    echo "[+] FTP: No anonymous login issues found in this initial scan."
fi

# 2. Look for ANONYMOUS SMB Shares (Data Leakage)
ANON_SMB=$(grep -A 10 'Read access: anonymous' "$FULL_SCAN_REPORT.nmap" | grep -E 'Host:|Sharename:')
if [ ! -z "$ANON_SMB" ]; then
    echo -e "\n!!! HIGH FINDING: ANONYMOUS SMB SHARES DETECTED !!!"
    echo "Evidence of publicly readable Windows/Samba shares exposing potential data."
    echo "$ANON_SMB"
else
    echo "[+] SMB: No anonymous share issues found in this initial scan."
fi

# 3. Look for WEAK SSL/TLS Ciphers (Outdated Encryption)
WEAK_SSL=$(grep 'TLSv1.0' "$FULL_SCAN_REPORT.nmap" | grep 'Host:')
if [ ! -z "$WEAK_SSL" ]; then
    echo -e "\n!!! WARNING: WEAK SSL/TLS DETECTED !!!"
    echo "Evidence of hosts supporting obsolete, insecure protocols (e.g., TLSv1.0)."
    echo "$WEAK_SSL"
else
    echo "[+] SSL/TLS: No severe protocol weaknesses found (e.g., TLSv1.0/v1.1) in this initial scan."
fi

# 4. List all open ports and identified services (Overall Exposure)
echo -e "\n--- NETWORK EXPOSURE SUMMARY (Open Ports & Versions) ---"
grep 'Host:' "$FULL_SCAN_REPORT.gnmap" | awk -F '[()]' '{
    ip=$1;
    match(ip, /Host: ([0-9\.]+)/, arr);
    ip=arr[1];

    if (match($0, /Ports: /, port_arr)) {
        printf "Host: %-15s | ", ip;

        ports_list="";
        split(port_arr[0], ports, ", ");

        for (i=1; i<=length(ports); i++) {
            if (ports[i] ~ /open/) {
                match(ports[i], /([0-9]+\/[a-z]+)\/\/[^/]+\/([a-z0-9\-\.]+)\/([^\/]+)/, port_info);
                if (port_info[1] != "") {
                    ports_list = ports_list port_info[1] " (" port_info[3] " / " port_info[2] "), ";
                }
            }
        }
        print substr(ports_list, 1, length(ports_list)-2);
    }
}' | grep -v "0 ports"

echo -e "\n[+] Full XML, NMAP, and Greppable reports are saved in: $OUTPUT_DIR"
echo "[*] Use the .nmap and .xml files for detailed reporting on all services found."

exit 0
