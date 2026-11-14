/**
 * The ruleset the sensor starts with. Local rules use sids 1000000–1999999, as in Suricata.
 * Edit them live on the Rules page or with PUT /api/rules.
 */
export const DEFAULT_RULES = String.raw`# PacketEye default rules (Suricata syntax)

# TLS client fingerprints (JA4) of non-browser stacks often used by implants.
# Matching the two hashes (JA4_b and JA4_c) catches the client with or without a server name.
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Go TLS client talking to the internet"; ja4.hash; content:"_9dc949149365_97f8aa674fd9"; endswith; classtype:trojan-activity; priority:1; sid:1000001; rev:2; metadata:mitre_technique_id T1573, mitre_tactic_name Command_and_Control;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Python HTTP client talking to the internet"; ja4.hash; content:"_e8f1e7e78f70_78f1d400d464"; endswith; classtype:policy-violation; priority:2; sid:1000002; rev:2; metadata:mitre_technique_id T1071.001;)

# Suspicious names
alert dns $HOME_NET any -> any 53 (msg:"DNS query for a dynamic-DNS domain"; dns.query; pcre:"/\.(duckdns\.org|no-ip\.(com|org)|ddns\.net)$/i"; classtype:bad-unknown; sid:1000010; rev:1; metadata:mitre_technique_id T1568;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"TLS to a paste site"; tls.sni; content:"pastebin.com"; endswith; nocase; classtype:policy-violation; priority:3; sid:1000011; rev:1; metadata:mitre_technique_id T1102;)

# Services that should never face the internet
alert tcp $EXTERNAL_NET any -> $HOME_NET [23,2323] (msg:"Inbound Telnet attempt"; flags:S; classtype:attempted-admin; priority:1; sid:1000020; rev:1; metadata:mitre_technique_id T1021;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"Inbound RDP from the internet"; flags:S; threshold:type limit, track by_src, count 1, seconds 300; classtype:attempted-admin; sid:1000021; rev:1; metadata:mitre_technique_id T1133;)
alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,1337,31337] (msg:"Outbound connection to a common backdoor port"; flags:S; classtype:trojan-activity; priority:1; sid:1000022; rev:1; metadata:mitre_technique_id T1571;)

# Volume
alert icmp any any -> $HOME_NET any (msg:"ICMP flood"; threshold:type both, track by_src, count 200, seconds 10; classtype:attempted-dos; sid:1000030; rev:1; metadata:mitre_technique_id T1498;)
`;
