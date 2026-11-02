import { Router, Request, Response } from 'express';
import dns from 'dns';
import net from 'net';
import { geoIPService } from '../threat/geoip-service';
import { getWATFormattedDate } from '../db/database';

export const scannerRouter = Router();

export interface PortScanResult {
  port: number;
  protocol: 'TCP';
  service: string;
  state: 'OPEN' | 'CLOSED';
  bannerOrVersion: string;
  recommendation: 'LEAVE_OPEN' | 'RESTRICT_ACCESS' | 'CLOSE_IMMEDIATELY';
  riskLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  whyRecommendation: string;
  firewallActionCommand: string;
}

export interface VulnerabilityFinding {
  id: string;
  cveOrCwe: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore: number;
  category: 'PORT_EXPOSURE' | 'TLS_CRYPTO' | 'HTTP_SECURITY_HEADERS' | 'INFORMATION_DISCLOSURE' | 'ACCESS_CONTROL';
  affectedComponent: string;
  description: string;
  howToPatch: string;
  patchSnippet: string;
}

interface PortSpec {
  port: number;
  service: string;
  defaultRecommendation: 'LEAVE_OPEN' | 'RESTRICT_ACCESS' | 'CLOSE_IMMEDIATELY';
  openRisk: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  whyIfOpen: string;
  whyIfClosed: string;
  firewallCmd: string;
  banner: string;
}

const PORT_CATALOG: PortSpec[] = [
  {
    port: 21,
    service: 'FTP (File Transfer Protocol)',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: FTP transmits credentials and files in unencrypted plaintext. Replace with SFTP (Port 22) or HTTPS uploads.',
    whyIfClosed: 'CLOSED (Secure): Plaintext FTP service is disabled.',
    firewallCmd: 'sudo ufw deny 21/tcp && sudo systemctl disable vsftpd',
    banner: 'vsFTPd / Plaintext File Transfer',
  },
  {
    port: 22,
    service: 'SSH (Secure Shell Remote Admin)',
    defaultRecommendation: 'RESTRICT_ACCESS',
    openRisk: 'MEDIUM',
    whyIfOpen: 'RESTRICT TO ADMIN VPN/IP ONLY: Leaving Port 22 open to 0.0.0.0/0 invites continuous automated brute-force attacks. Enforce Ed25519 SSH keys, disable root/password login, and restrict to your admin IP.',
    whyIfClosed: 'CLOSED (Secure): Public SSH administration port is not exposed to the open internet.',
    firewallCmd: 'sudo ufw limit 22/tcp # Or restrict: sudo ufw allow from <ADMIN_IP> to any port 22',
    banner: 'OpenSSH 8.9p1 Ubuntu-3ubuntu0.10',
  },
  {
    port: 23,
    service: 'Telnet (Unencrypted Remote Console)',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: Telnet sends all administrative commands and passwords in cleartext over the network.',
    whyIfClosed: 'CLOSED (Secure): Legacy Telnet service is disabled.',
    firewallCmd: 'sudo ufw deny 23/tcp',
    banner: 'Linux Telnetd',
  },
  {
    port: 25,
    service: 'SMTP (Mail Transfer Agent)',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'HIGH',
    whyIfOpen: 'CLOSE UNLESS DEDICATED MAIL SERVER: Open Port 25 on web/application servers risks SMTP open-relay abuse and domain blacklisting. Use authenticated TLS submission (Port 587) or transactional API.',
    whyIfClosed: 'CLOSED (Secure): Direct unencrypted SMTP relay is disabled.',
    firewallCmd: 'sudo ufw deny 25/tcp',
    banner: 'Postfix ESMTP Mail Relay',
  },
  {
    port: 53,
    service: 'DNS (Domain Name System)',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'MEDIUM',
    whyIfOpen: 'CLOSE UNLESS AUTHORITATIVE DNS SERVER: Application servers should not expose Port 53 publicly to prevent DNS amplification DDoS attacks.',
    whyIfClosed: 'CLOSED (Secure): Open DNS resolver is not exposed.',
    firewallCmd: 'sudo ufw deny 53/tcp && sudo ufw deny 53/udp',
    banner: 'ISC BIND / systemd-resolved',
  },
  {
    port: 80,
    service: 'HTTP (Web Traffic / TLS Redirect)',
    defaultRecommendation: 'LEAVE_OPEN',
    openRisk: 'LOW',
    whyIfOpen: 'LEAVE OPEN (WITH 301 HTTPS REDIRECT ONLY): Port 80 should remain open on public web servers strictly to redirect users via HTTP 301 Permanent Redirect to HTTPS (Port 443). Never serve login forms over Port 80.',
    whyIfClosed: 'CLOSED: Direct HTTP port is closed; clients must connect directly via HTTPS (Port 443).',
    firewallCmd: 'sudo ufw allow 80/tcp # Ensure Nginx/Express enforces 301 redirect to https://',
    banner: 'HTTP/1.1 Edge Redirector (301 -> HTTPS)',
  },
  {
    port: 443,
    service: 'HTTPS (Encrypted TLSv1.3 Web Service)',
    defaultRecommendation: 'LEAVE_OPEN',
    openRisk: 'SAFE',
    whyIfOpen: 'LEAVE OPEN (REQUIRED): Primary encrypted HTTPS ingress port for production web applications and REST APIs. Ensure TLS 1.2 / 1.3 and strong cipher suites are enforced.',
    whyIfClosed: 'CLOSED (WARNING): HTTPS Port 443 is closed. Public web/API clients cannot establish encrypted TLS connections.',
    firewallCmd: 'sudo ufw allow 443/tcp # Required for encrypted HTTPS traffic',
    banner: 'TLSv1.3 / ECDHE-RSA-AES256-GCM-SHA384',
  },
  {
    port: 3306,
    service: 'MySQL / MariaDB Database Engine',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: Database port 3306 must NEVER be exposed to the public internet. Bind MySQL to 127.0.0.1 or a private VPC subnet.',
    whyIfClosed: 'CLOSED (Secure): MySQL database port is hidden from public network access.',
    firewallCmd: 'sudo ufw deny 3306/tcp # In my.cnf set: bind-address = 127.0.0.1',
    banner: 'MySQL 8.0.x Protocol v10',
  },
  {
    port: 3389,
    service: 'RDP (Microsoft Remote Desktop)',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: Publicly exposed RDP (Port 3389) is the #1 vector for ransomware and credential brute-forcing. Place behind WireGuard/OpenVPN.',
    whyIfClosed: 'CLOSED (Secure): Remote Desktop Protocol is not exposed.',
    firewallCmd: 'sudo ufw deny 3389/tcp',
    banner: 'Microsoft Terminal Services / RDP',
  },
  {
    port: 4000,
    service: 'The Watch SOC API (Node.js Telemetry Port)',
    defaultRecommendation: 'RESTRICT_ACCESS',
    openRisk: 'LOW',
    whyIfOpen: 'RESTRICT BEHIND TLS REVERSE PROXY (443): In production, expose through HTTPS Port 443 (Nginx/Cloudflare/Render) and restrict raw port 4000 to internal upstream proxies.',
    whyIfClosed: 'CLOSED (Secure): Internal Node.js port 4000 is shielded behind HTTPS reverse proxy (Port 443).',
    firewallCmd: 'sudo ufw deny 4000/tcp # Proxy via Nginx on Port 443 -> http://127.0.0.1:4000',
    banner: 'Node.js v20 / Express (The Watch SOC Engine)',
  },
  {
    port: 5055,
    service: 'NOUN-HRMS Application API Port',
    defaultRecommendation: 'RESTRICT_ACCESS',
    openRisk: 'LOW',
    whyIfOpen: 'RESTRICT BEHIND TLS REVERSE PROXY (443): Keep internal app port 5055 bound to localhost/reverse-proxy and serve public traffic over HTTPS (443).',
    whyIfClosed: 'CLOSED (Secure): Internal HRMS port 5055 is shielded behind HTTPS Port 443.',
    firewallCmd: 'sudo ufw deny 5055/tcp # Proxy via HTTPS Port 443 -> http://127.0.0.1:5055',
    banner: 'Node.js / Express (NOUN-HRMS Core API)',
  },
  {
    port: 5432,
    service: 'PostgreSQL Relational Database',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: PostgreSQL (Port 5432) must never be reachable from untrusted public networks. Restrict to internal VPC / application server IP and enforce sslmode=require.',
    whyIfClosed: 'CLOSED (Secure): PostgreSQL Port 5432 is not publicly exposed.',
    firewallCmd: 'sudo ufw deny 5432/tcp # In postgresql.conf: listen_addresses = \'localhost\'',
    banner: 'PostgreSQL 16.x Wire Protocol',
  },
  {
    port: 6379,
    service: 'Redis In-Memory Session & Cache Store',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: Publicly exposed Redis (Port 6379) allows unauthorized session hijacking and memory dumping. Bind strictly to 127.0.0.1 and set requirepass.',
    whyIfClosed: 'CLOSED (Secure): Redis Port 6379 is isolated from external networks.',
    firewallCmd: 'sudo ufw deny 6379/tcp # In redis.conf: bind 127.0.0.1 -::1',
    banner: 'Redis 7.2 In-Memory Store',
  },
  {
    port: 8080,
    service: 'HTTP Alternate / Application Proxy / Admin Panel',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'MEDIUM',
    whyIfOpen: 'CLOSE OR RESTRICT: Unencrypted alternate HTTP port 8080 often exposes staging servers, Tomcat/Jenkins consoles, or unhardened debug APIs. Route all web traffic through 443.',
    whyIfClosed: 'CLOSED (Secure): Alternate HTTP debug port 8080 is closed.',
    firewallCmd: 'sudo ufw deny 8080/tcp',
    banner: 'HTTP-Alt / Internal Proxy',
  },
  {
    port: 27017,
    service: 'MongoDB Document Database',
    defaultRecommendation: 'CLOSE_IMMEDIATELY',
    openRisk: 'CRITICAL',
    whyIfOpen: 'CLOSE IMMEDIATELY: Exposed MongoDB port 27017 risks unauthorized collection dumps and ransomware wiping.',
    whyIfClosed: 'CLOSED (Secure): MongoDB Port 27017 is closed to public networks.',
    firewallCmd: 'sudo ufw deny 27017/tcp # In mongod.conf: bindIp: 127.0.0.1',
    banner: 'MongoDB Wire Protocol',
  },
];

function checkTcpPort(host: string, port: number, timeoutMs = 1100): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;

    const done = (isOpen: boolean) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(isOpen);
      }
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));

    try {
      socket.connect(port, host);
    } catch {
      done(false);
    }
  });
}

function parseTargetInput(rawInput: string): {
  cleanHost: string;
  targetUrl: string;
  explicitPort?: number;
} {
  const trimmed = rawInput.trim();
  let urlStr = trimmed;
  if (!/^https?:\/\//i.test(urlStr)) {
    // Use http:// for localhost or private IPs, https:// for domains/public hosts
    if (/^(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/i.test(urlStr)) {
      urlStr = `http://${urlStr}`;
    } else {
      urlStr = `https://${urlStr}`;
    }
  }

  try {
    const parsed = new URL(urlStr);
    const explicitPort = parsed.port ? parseInt(parsed.port, 10) : undefined;
    return {
      cleanHost: parsed.hostname,
      targetUrl: parsed.origin + (parsed.pathname !== '/' ? parsed.pathname : ''),
      explicitPort,
    };
  } catch {
    const hostOnly = trimmed.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    return {
      cleanHost: hostOnly || '127.0.0.1',
      targetUrl: `https://${hostOnly}`,
    };
  }
}

scannerRouter.post('/inspect', async (req: Request, res: Response) => {
  const rawTarget = String(req.body?.target || '').trim();
  if (!rawTarget) {
    res.status(400).json({ error: 'Please provide a valid server IP address or URL to inspect.' });
    return;
  }

  const startedAt = Date.now();
  const { cleanHost, targetUrl, explicitPort } = parseTargetInput(rawTarget);

  // 1. Resolve hostname to IPv4 if domain name provided
  let resolvedIp = cleanHost;
  const isIpLiteral = net.isIP(cleanHost) !== 0;
  if (!isIpLiteral) {
    try {
      const lookup = await dns.promises.lookup(cleanHost, { family: 4 });
      resolvedIp = lookup.address;
    } catch {
      resolvedIp = cleanHost;
    }
  }

  // 2. GeoIP & ASN Enrichment
  const geo = await geoIPService.resolve(resolvedIp);

  // 3. Parallel Non-Intrusive TCP Port Probes
  const portChecks = await Promise.all(
    PORT_CATALOG.map(async (spec) => {
      const isOpen = await checkTcpPort(resolvedIp, spec.port, 1100);
      return { spec, isOpen };
    })
  );

  // 4. Live HTTP / HTTPS Security Header & TLS Posture Probe
  let httpReachable = false;
  let httpStatusCode = 0;
  let responseHeaders: Record<string, string> = {};
  let serverBanner = '';
  let tlsEnabled = targetUrl.startsWith('https://');

  const urlsToTry = [targetUrl];
  if (targetUrl.startsWith('https://')) {
    urlsToTry.push(targetUrl.replace(/^https:\/\//i, 'http://'));
  } else {
    urlsToTry.push(targetUrl.replace(/^http:\/\//i, 'https://'));
  }

  for (const probeUrl of urlsToTry) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
      const response = await fetch(probeUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'TheWatch-SOC-SurfaceAuditor/2.4 (Defensive Security Posture Scanner)',
        },
      });
      clearTimeout(timer);
      httpReachable = true;
      httpStatusCode = response.status;
      tlsEnabled = probeUrl.startsWith('https://');
      response.headers.forEach((val, key) => {
        responseHeaders[key.toLowerCase()] = val;
      });
      serverBanner = responseHeaders['server'] || responseHeaders['x-powered-by'] || 'HTTPS / Edge Gateway';
      break;
    } catch {
      // Try next protocol fallback
    }
  }

  // Build final Port Scan Results
  const ports: PortScanResult[] = portChecks.map(({ spec, isOpen }) => {
    // If HTTP/HTTPS probe succeeded or explicitPort matched, ensure 80/443/explicitPort reflects active state
    let effectiveOpen = isOpen;
    if (httpReachable && tlsEnabled && spec.port === 443) effectiveOpen = true;
    if (httpReachable && !tlsEnabled && spec.port === 80) effectiveOpen = true;
    if (explicitPort && spec.port === explicitPort && httpReachable) effectiveOpen = true;

    const state: 'OPEN' | 'CLOSED' = effectiveOpen ? 'OPEN' : 'CLOSED';
    const riskLevel = effectiveOpen ? spec.openRisk : 'SAFE';

    return {
      port: spec.port,
      protocol: 'TCP',
      service: spec.service,
      state,
      bannerOrVersion: effectiveOpen
        ? (spec.port === 80 || spec.port === 443) && serverBanner
          ? `${serverBanner} (${spec.banner})`
          : spec.banner
        : 'Port Closed / Filtered by Firewall',
      recommendation: spec.defaultRecommendation,
      riskLevel,
      whyRecommendation: effectiveOpen ? spec.whyIfOpen : spec.whyIfClosed,
      firewallActionCommand: spec.firewallCmd,
    };
  });

  // 5. Build Vulnerability Findings & Patch Blueprints
  const vulnerabilities: VulnerabilityFinding[] = [];

  // Check A: Any dangerous open ports (21, 22, 23, 25, 3306, 3389, 5432, 6379, 8080, 27017)
  for (const p of ports) {
    if (p.state === 'OPEN' && (p.recommendation === 'CLOSE_IMMEDIATELY' || p.recommendation === 'RESTRICT_ACCESS')) {
      if (p.port === 80 || p.port === 443) continue;
      vulnerabilities.push({
        id: `VULN-PORT-${p.port}`,
        cveOrCwe: 'CWE-284 (Improper Network Access Control)',
        title: `Exposed Service on TCP Port ${p.port}: ${p.service}`,
        severity: p.riskLevel === 'CRITICAL' ? 'CRITICAL' : p.riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM',
        cvssScore: p.riskLevel === 'CRITICAL' ? 9.1 : p.riskLevel === 'HIGH' ? 7.8 : 5.6,
        category: 'PORT_EXPOSURE',
        affectedComponent: `${resolvedIp}:${p.port} (${p.service})`,
        description: p.whyRecommendation,
        howToPatch: `Close TCP Port ${p.port} on the perimeter firewall or bind the service strictly to localhost (127.0.0.1) so external attackers cannot probe or brute-force it directly.`,
        patchSnippet: `# Linux UFW / Firewall Hardening for Port ${p.port}\n${p.firewallActionCommand}\nsudo ufw reload`,
      });
    }
  }

  // Check B: HTTP Security Headers & TLS Posture if HTTP/HTTPS is active (or general web server audit)
  const hsts = responseHeaders['strict-transport-security'];
  if (!hsts) {
    vulnerabilities.push({
      id: 'VULN-TLS-HSTS',
      cveOrCwe: 'CWE-319 (Cleartext Transmission / SSL Stripping Risk)',
      title: 'Missing HTTP Strict-Transport-Security (HSTS) Header',
      severity: 'MEDIUM',
      cvssScore: 6.5,
      category: 'TLS_CRYPTO',
      affectedComponent: `${targetUrl} (Response Headers)`,
      description: 'The server does not return a Strict-Transport-Security header, allowing man-in-the-middle (MITM) attackers on public Wi-Fi networks to attempt SSL-stripping downgrade attacks.',
      howToPatch: 'Add the Strict-Transport-Security header with a minimum max-age of 1 year (31536000 seconds), includeSubDomains, and preload.',
      patchSnippet: `// Express.js / Node.js Patch:\napp.use((req, res, next) => {\n  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');\n  next();\n});\n\n# Or Nginx Configuration:\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
    });
  }

  const csp = responseHeaders['content-security-policy'];
  if (!csp) {
    vulnerabilities.push({
      id: 'VULN-HDR-CSP',
      cveOrCwe: 'CWE-693 (Protection Mechanism Failure / XSS Mitigation Missing)',
      title: 'Missing Content-Security-Policy (CSP) Defense Header',
      severity: 'HIGH',
      cvssScore: 7.2,
      category: 'HTTP_SECURITY_HEADERS',
      affectedComponent: `${targetUrl} (HTTP Response Header)`,
      description: 'No Content-Security-Policy header was detected. Without CSP, browsers cannot restrict unauthorized inline scripts or malicious third-party data exfiltration domains if an XSS injection occurs.',
      howToPatch: 'Configure a strict Content-Security-Policy header restricting default-src, script-src, and connect-src to trusted institutional origins.',
      patchSnippet: `// Express.js (Helmet or Custom Middleware):\nres.setHeader(\n  'Content-Security-Policy',\n  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-ancestors 'none';"\n);`,
    });
  }

  const xfo = responseHeaders['x-frame-options'];
  if (!xfo && (!csp || !csp.includes('frame-ancestors'))) {
    vulnerabilities.push({
      id: 'VULN-HDR-XFO',
      cveOrCwe: 'CWE-1021 (Improper Restriction of Rendered UI Layers / Clickjacking)',
      title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
      severity: 'MEDIUM',
      cvssScore: 5.4,
      category: 'HTTP_SECURITY_HEADERS',
      affectedComponent: `${targetUrl} (UI Framing Policy)`,
      description: 'The application does not send X-Frame-Options: DENY or SAMEORIGIN, allowing external malicious pages to embed the portal inside a transparent iframe to hijack user clicks.',
      howToPatch: 'Set X-Frame-Options to DENY (or SAMEORIGIN) and include frame-ancestors \'none\' in your Content-Security-Policy.',
      patchSnippet: `// Express.js / Next.js Header Patch:\nres.setHeader('X-Frame-Options', 'DENY');\n\n# Nginx:\nadd_header X-Frame-Options "DENY" always;`,
    });
  }

  const xcto = responseHeaders['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    vulnerabilities.push({
      id: 'VULN-HDR-NOSNIFF',
      cveOrCwe: 'CWE-16 (MIME-Type Sniffing Exposure)',
      title: 'Missing X-Content-Type-Options: nosniff Header',
      severity: 'LOW',
      cvssScore: 4.3,
      category: 'HTTP_SECURITY_HEADERS',
      affectedComponent: `${targetUrl} (Content-Type Handling)`,
      description: 'Without X-Content-Type-Options: nosniff, browsers may attempt to MIME-sniff uploaded documents and execute disguised HTML/JavaScript payloads.',
      howToPatch: 'Enforce X-Content-Type-Options: nosniff across all HTTP responses.',
      patchSnippet: `res.setHeader('X-Content-Type-Options', 'nosniff');`,
    });
  }

  const poweredBy = responseHeaders['x-powered-by'];
  if (poweredBy) {
    vulnerabilities.push({
      id: 'VULN-INFO-POWEREDBY',
      cveOrCwe: 'CWE-200 (Information Exposure Through Server Headers)',
      title: `Technology Stack Fingerprinting Exposed (X-Powered-By: ${poweredBy})`,
      severity: 'LOW',
      cvssScore: 3.7,
      category: 'INFORMATION_DISCLOSURE',
      affectedComponent: `${targetUrl} (X-Powered-By: ${poweredBy})`,
      description: `The server explicitly advertises "X-Powered-By: ${poweredBy}", helping automated reconnaissance tools tailor framework-specific exploits.`,
      howToPatch: 'Disable the X-Powered-By header in Express.js or strip it at the reverse proxy layer.',
      patchSnippet: `// Express.js Hardening:\napp.disable('x-powered-by');`,
    });
  }

  const corsHeader = responseHeaders['access-control-allow-origin'];
  if (corsHeader === '*') {
    vulnerabilities.push({
      id: 'VULN-CORS-WILDCARD',
      cveOrCwe: 'CWE-942 (Overly Permissive Cross-Domain Whitelist)',
      title: 'Wildcard CORS Policy Detected (Access-Control-Allow-Origin: *)',
      severity: 'MEDIUM',
      cvssScore: 5.8,
      category: 'ACCESS_CONTROL',
      affectedComponent: `${targetUrl} (CORS Middleware)`,
      description: 'The server permits any external origin (*) to read API responses via browser fetch/XHR requests.',
      howToPatch: 'Restrict Access-Control-Allow-Origin to explicit trusted institutional domains (e.g., https://noun-hrms.onrender.com and https://the-watch.vercel.app).',
      patchSnippet: `// Express.js Strict CORS Whitelist:\napp.use(cors({\n  origin: ['https://noun-hrms.onrender.com', 'https://the-watch.vercel.app'],\n  credentials: true\n}));`,
    });
  }

  // Compute Security Score & Grade
  const openPortsList = ports.filter((p) => p.state === 'OPEN');
  const portsToCloseCount = openPortsList.filter((p) => p.recommendation !== 'LEAVE_OPEN').length;
  const criticalVulns = vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const highVulns = vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const mediumVulns = vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const lowVulns = vulnerabilities.filter((v) => v.severity === 'LOW').length;

  let score = 100 - criticalVulns * 25 - highVulns * 12 - mediumVulns * 7 - lowVulns * 3;
  score = Math.max(15, Math.min(100, score));

  const securityGrade =
    score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 68 ? 'C' : score >= 50 ? 'D' : 'F';

  res.json({
    targetInput: rawTarget,
    cleanHost,
    resolvedIp,
    targetUrl,
    scannedAtWat: getWATFormattedDate(),
    scanDurationMs: Date.now() - startedAt,
    geo: {
      country: geo.country,
      region: geo.region,
      city: geo.city,
      isp: geo.isp,
      asn: geo.asn,
      isProxyOrVpn: geo.isProxyOrVpn,
    },
    httpProbe: {
      reachable: httpReachable,
      statusCode: httpStatusCode,
      tlsEnabled,
      serverBanner: serverBanner || 'Undisclosed / Hardened',
      headersCaptured: responseHeaders,
    },
    summary: {
      securityScore: score,
      securityGrade,
      totalPortsScanned: ports.length,
      openPortsCount: openPortsList.length,
      portsRecommendedToCloseCount: portsToCloseCount,
      portsSafeToLeaveOpenCount: openPortsList.length - portsToCloseCount,
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: criticalVulns,
      highCount: highVulns,
      mediumCount: mediumVulns,
      lowCount: lowVulns,
    },
    ports,
    vulnerabilities,
  });
});
