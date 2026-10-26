import type { NmapPort, NmapScriptResult, MachineOS } from '@/types';

export interface ParsedHost {
  ip: string;
  hostname: string;
  os: MachineOS;
  ports: NmapPort[];
}

function guessOS(osName: string): MachineOS {
  const lower = osName.toLowerCase();
  if (lower.includes('windows')) return 'windows';
  if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian') || lower.includes('centos') || lower.includes('fedora') || lower.includes('red hat')) return 'linux';
  return 'unknown';
}

export function parseNmapXml(xml: string): ParsedHost[] {
  // Pre-process: strip DOCTYPE declarations and xml-stylesheet PIs that may
  // appear inside wrapper elements (e.g. yumscan's <nmaprun_combined>),
  // which would make the XML invalid for DOMParser.
  const cleaned = xml
    .replace(/<!DOCTYPE[^>]*>/gi, '')
    .replace(/<\?xml-stylesheet[^?]*\?>/gi, '');

  const parser = new DOMParser();
  const doc = parser.parseFromString(cleaned, 'text/xml');
  const hosts: ParsedHost[] = [];

  const hostEls = doc.getElementsByTagName('host');
  for (let i = 0; i < hostEls.length; i++) {
    const hostEl = hostEls[i]!;

    // Skip hosts that are down
    const statusEl = hostEl.getElementsByTagName('status')[0];
    if (statusEl && statusEl.getAttribute('state') !== 'up') continue;

    // IP address
    let ip = '';
    const addrEls = hostEl.getElementsByTagName('address');
    for (let a = 0; a < addrEls.length; a++) {
      const addrEl = addrEls[a]!;
      if (addrEl.getAttribute('addrtype') === 'ipv4' || addrEl.getAttribute('addrtype') === 'ipv6') {
        ip = addrEl.getAttribute('addr') ?? '';
        break;
      }
    }
    if (!ip) continue;

    // Hostname
    let hostname = '';
    const hostnameEls = hostEl.getElementsByTagName('hostname');
    if (hostnameEls.length > 0) {
      hostname = hostnameEls[0]!.getAttribute('name') ?? '';
    }

    // OS detection
    let os: MachineOS = 'unknown';
    const osMatchEls = hostEl.getElementsByTagName('osmatch');
    if (osMatchEls.length > 0) {
      os = guessOS(osMatchEls[0]!.getAttribute('name') ?? '');
    }
    // Fallback: check osclass
    if (os === 'unknown') {
      const osClassEls = hostEl.getElementsByTagName('osclass');
      for (let o = 0; o < osClassEls.length; o++) {
        const osfamily = osClassEls[o]!.getAttribute('osfamily') ?? '';
        const guessed = guessOS(osfamily);
        if (guessed !== 'unknown') { os = guessed; break; }
      }
    }

    // Ports
    const ports: NmapPort[] = [];
    const portEls = hostEl.getElementsByTagName('port');
    for (let p = 0; p < portEls.length; p++) {
      const portEl = portEls[p]!;
      const stateEl = portEl.getElementsByTagName('state')[0];
      const serviceEl = portEl.getElementsByTagName('service')[0];

      // Extract script output (from -sC / --script scans)
      const scripts: NmapScriptResult[] = [];
      const scriptEls = portEl.getElementsByTagName('script');
      for (let s = 0; s < scriptEls.length; s++) {
        const scriptEl = scriptEls[s]!;
        const id = scriptEl.getAttribute('id') ?? '';
        const output = scriptEl.getAttribute('output') ?? scriptEl.textContent ?? '';
        if (id) scripts.push({ id, output });
      }

      ports.push({
        port: parseInt(portEl.getAttribute('portid') ?? '0', 10),
        protocol: portEl.getAttribute('protocol') ?? 'tcp',
        state: stateEl?.getAttribute('state') ?? 'unknown',
        service: serviceEl?.getAttribute('name') ?? '',
        version: [
          serviceEl?.getAttribute('product') ?? '',
          serviceEl?.getAttribute('version') ?? '',
          serviceEl?.getAttribute('extrainfo') ?? '',
        ].filter(Boolean).join(' '),
        ...(scripts.length > 0 ? { scripts } : {}),
      });
    }

    hosts.push({ ip, hostname, os, ports });
  }

  // Post-process: infer OS from port signatures when OS detection is unavailable
  for (const host of hosts) {
    if (host.os !== 'unknown') continue;
    const openPorts = new Set(host.ports.filter((p) => p.state === 'open').map((p) => p.port));
    const serviceNames = new Set(host.ports.map((p) => p.service));
    // Windows indicators: msrpc (135), netbios (139), microsoft-ds (445), kerberos (88)
    if (serviceNames.has('msrpc') || serviceNames.has('microsoft-ds') ||
        (openPorts.has(135) && openPorts.has(445))) {
      host.os = 'windows';
    // Linux indicators: ssh (22) without Windows-typical ports
    } else if ((openPorts.has(22) || serviceNames.has('ssh')) &&
               !openPorts.has(135) && !openPorts.has(445)) {
      host.os = 'linux';
    }
  }

  return hosts;
}
