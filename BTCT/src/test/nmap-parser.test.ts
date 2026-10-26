import { describe, it, expect } from 'vitest';
import { parseNmapXml } from '../lib/nmap-parser';

// Inline test XML matching the structure of a yumscan-wrapped nmap scan
const testXml = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun_combined generator="yumscan" start="1776514364">
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" start="1776514320" startstr="Sat Apr 18 08:12:00 2026" version="7.98" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
<host starttime="1776514321" endtime="1776514361"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="10.129.244.95" addrtype="ipv4"/>
<hostnames></hostnames>
<ports>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="domain" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="126"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="88"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="kerberos-sec" method="table" conf="3"/></port>
<port protocol="tcp" portid="135"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="msrpc" method="table" conf="3"/></port>
<port protocol="tcp" portid="139"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="netbios-ssn" method="table" conf="3"/></port>
<port protocol="tcp" portid="389"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ldap" method="table" conf="3"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="microsoft-ds" method="table" conf="3"/></port>
<port protocol="tcp" portid="464"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="kpasswd5" method="table" conf="3"/></port>
<port protocol="tcp" portid="593"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="http-rpc-epmap" method="table" conf="3"/></port>
<port protocol="tcp" portid="636"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="ldapssl" method="table" conf="3"/></port>
<port protocol="tcp" portid="2179"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="vmrdp" method="table" conf="3"/></port>
<port protocol="tcp" portid="3268"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="globalcatLDAP" method="table" conf="3"/></port>
<port protocol="tcp" portid="3269"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="globalcatLDAPssl" method="table" conf="3"/></port>
<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="wsman" method="table" conf="3"/></port>
<port protocol="tcp" portid="9389"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="adws" method="table" conf="3"/></port>
<port protocol="tcp" portid="49667"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49689"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49690"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49692"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49693"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49915"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
<port protocol="tcp" portid="49941"><state state="open" reason="syn-ack" reason_ttl="127"/></port>
</ports>
</host>
</nmaprun>
</nmaprun_combined>`;

// XML with script output (simulates -sV -sC scan)
const testXmlWithScripts = `<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.98">
<host><status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="webserver.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.6"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4.52"/>
<script id="http-title" output="Apache2 Ubuntu Default Page: It works"/>
<script id="http-server-header" output="Apache/2.4.52 (Ubuntu)"/>
</port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0"/>
<script id="ssl-cert" output="Subject: commonName=webserver.local"/>
</port>
</ports>
</host>
</nmaprun>`;

describe('nmap-parser with real scan XML', () => {
  it('should parse hosts from yumscan-wrapped XML', () => {
    const hosts = parseNmapXml(testXml);
    expect(hosts.length).toBeGreaterThanOrEqual(1);
  });

  it('should extract the correct IP', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95');
    expect(host).toBeDefined();
  });

  it('should parse all open ports', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95');
    expect(host).toBeDefined();
    // 22 open ports in the scan
    const openPorts = host!.ports.filter((p) => p.state === 'open');
    expect(openPorts.length).toBe(22);
  });

  it('should extract service names from table lookup', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95')!;
    const port80 = host.ports.find((p) => p.port === 80);
    expect(port80).toBeDefined();
    expect(port80!.service).toBe('http');
    expect(port80!.protocol).toBe('tcp');

    const port445 = host.ports.find((p) => p.port === 445);
    expect(port445).toBeDefined();
    expect(port445!.service).toBe('microsoft-ds');
  });

  it('should handle ports without service element', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95')!;
    const port49667 = host.ports.find((p) => p.port === 49667);
    expect(port49667).toBeDefined();
    expect(port49667!.service).toBe('');
    expect(port49667!.state).toBe('open');
  });

  it('should infer Windows OS from port signatures (135, 445, kerberos)', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95')!;
    expect(host.os).toBe('windows');
  });
});

describe('nmap-parser script output', () => {
  it('should extract script output from ports', () => {
    const hosts = parseNmapXml(testXmlWithScripts);
    expect(hosts.length).toBe(1);
    const host = hosts[0]!;
    const port80 = host.ports.find((p) => p.port === 80)!;
    expect(port80.scripts).toBeDefined();
    expect(port80.scripts!.length).toBe(2);
    expect(port80.scripts![0]!.id).toBe('http-title');
    expect(port80.scripts![0]!.output).toContain('It works');
    expect(port80.scripts![1]!.id).toBe('http-server-header');
  });

  it('should extract product/version/extrainfo into version string', () => {
    const hosts = parseNmapXml(testXmlWithScripts);
    const host = hosts[0]!;
    const port22 = host.ports.find((p) => p.port === 22)!;
    expect(port22.version).toBe('OpenSSH 8.9p1 Ubuntu 3ubuntu0.6');
    expect(port22.service).toBe('ssh');
  });

  it('should infer Linux OS from SSH + no Windows ports', () => {
    const hosts = parseNmapXml(testXmlWithScripts);
    const host = hosts[0]!;
    expect(host.os).toBe('linux');
  });

  it('should extract hostname from hostname element', () => {
    const hosts = parseNmapXml(testXmlWithScripts);
    const host = hosts[0]!;
    expect(host.hostname).toBe('webserver.local');
  });

  it('should not add scripts field when no scripts present', () => {
    const hosts = parseNmapXml(testXml);
    const host = hosts.find((h) => h.ip === '10.129.244.95')!;
    const port53 = host.ports.find((p) => p.port === 53)!;
    expect(port53.scripts).toBeUndefined();
  });
});
