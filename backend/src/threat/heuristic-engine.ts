export interface HeuristicMatchResult {
  detected: boolean;
  incidentType: string;
  threatClassification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  matchedRule: string;
  mitigationBlueprint: string;
  remediationSummary: string;
}

export class HeuristicEngine {
  // Regex rules for SQL Injection signatures
  private sqliPatterns = [
    { regex: /UNION(\s+ALL)?\s+SELECT/i, name: 'SQLi UNION-Based Data Extraction' },
    { regex: /('|"|`)\s*(OR|AND)\s+(['"]?\d+['"]?\s*=\s*['"]?\d+|['"]?[a-z]+['"]?\s*=\s*['"]?[a-z]+)/i, name: 'SQLi Tautology Bypass' },
    { regex: /;\s*(DROP|ALTER|TRUNCATE|DELETE)\s+TABLE/i, name: 'SQLi Destructive DDL/DML' },
    { regex: /pg_sleep\s*\(\s*\d+\s*\)/i, name: 'PostgreSQL Time-Based Blind Injection' },
    { regex: /waitfor\s+delay\s+['"]\d+:\d+:\d+['"]/i, name: 'MSSQL Time-Based Injection' },
    { regex: /xp_cmdshell/i, name: 'RCE via Database Command Shell' },
    { regex: /(--|#|\/\*).*?(\*\/)?/i, name: 'SQL Comment Truncation Attack' },
  ];

  // Regex rules for Cross-Site Scripting (XSS)
  private xssPatterns = [
    { regex: /<script\b[^>]*>([\s\S]*?)<\/script>/i, name: 'Explicit Script Tag Injection' },
    { regex: /javascript:\s*[a-z0-9_]+\s*\(/i, name: 'JavaScript Protocol URI Injection' },
    { regex: /(onerror|onload|onclick|onmouseover|onfocus)\s*=\s*['"][^'"]*['"]/i, name: 'DOM Inline Event Handler Hijack' },
    { regex: /<svg\b[^>]*onload\s*=/i, name: 'SVG-Based Vector Execution' },
    { regex: /<iframe\b[^>]*src\s*=/i, name: 'Malicious iFrame Embedding' },
    { regex: /document\.(cookie|location|write)/i, name: 'Session Token / Cookie Exfiltration Attempt' },
  ];

  // Regex rules for Path Traversal & LFI
  private pathTraversalPatterns = [
    { regex: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)/i, name: 'Relative Directory Traversal (../)' },
    { regex: /(\/etc\/passwd|etc\/shadow|\/proc\/self\/environ)/i, name: 'UNIX System File Access Probe' },
    { regex: /(win\.ini|boot\.ini|windows\\system32)/i, name: 'Windows Core File Access Probe' },
    { regex: /%00/i, name: 'Null Byte File Extension Poisoning' },
  ];

  /**
   * Evaluates incoming request parameters, headers, URL, and body for attack vectors
   */
  public evaluate(data: {
    method: string;
    path: string;
    payload?: string;
    userAgent?: string;
    clientIp: string;
  }): HeuristicMatchResult {
    const combinedTarget = `${data.method} ${data.path} ${data.payload || ''} ${data.userAgent || ''}`;

    // 1. Check SQL Injection
    for (const rule of this.sqliPatterns) {
      if (rule.regex.test(combinedTarget)) {
        return {
          detected: true,
          incidentType: 'SQL_INJECTION',
          threatClassification: rule.name,
          severity: 'CRITICAL',
          matchedRule: rule.regex.toString(),
          mitigationBlueprint: this.generateWafMitigation(data.clientIp, data.path, 'SQLi'),
          remediationSummary: `Detected malicious SQL pattern "${rule.name}" targeting ${data.path}. Ensure all queries use parameterized statements (pg query params $1, $2 or ORM binding) and reject raw string concatenation.`,
        };
      }
    }

    // 2. Check XSS
    for (const rule of this.xssPatterns) {
      if (rule.regex.test(combinedTarget)) {
        return {
          detected: true,
          incidentType: 'XSS_ATTACK',
          threatClassification: rule.name,
          severity: 'HIGH',
          matchedRule: rule.regex.toString(),
          mitigationBlueprint: this.generateWafMitigation(data.clientIp, data.path, 'XSS'),
          remediationSummary: `Detected Cross-Site Scripting payload "${rule.name}" in request body/URI. Sanitize user input using DOMPurify / Content-Security-Policy (CSP) headers and HTML entity encoding.`,
        };
      }
    }

    // 3. Check Path Traversal
    for (const rule of this.pathTraversalPatterns) {
      if (rule.regex.test(combinedTarget)) {
        return {
          detected: true,
          incidentType: 'PATH_TRAVERSAL',
          threatClassification: rule.name,
          severity: 'HIGH',
          matchedRule: rule.regex.toString(),
          mitigationBlueprint: this.generateWafMitigation(data.clientIp, data.path, 'Traversal'),
          remediationSummary: `Detected Path Traversal probe targeting ${data.path}. Enforce path normalization via path.resolve() and verify the target path strictly remains inside the designated whitelist directory root.`,
        };
      }
    }

    return {
      detected: false,
      incidentType: 'NONE',
      threatClassification: 'Clean Traffic',
      severity: 'LOW',
      matchedRule: '',
      mitigationBlueprint: '',
      remediationSummary: '',
    };
  }

  /**
   * Generates production-ready WAF expressions and Nginx/iptables rules
   */
  public generateWafMitigation(ip: string, targetPath: string, vector: string): string {
    return [
      `# ================= THE WATCH AUTOMATED WAF MITIGATION =================`,
      `# Threat Vector: ${vector} | Offending IP: ${ip} | Target: ${targetPath}`,
      ``,
      `# 1. Cloudflare WAF Custom Rule (Expression):`,
      `(http.request.uri.path eq "${targetPath}" and ip.src eq ${ip}) or (ip.src eq ${ip} and http.request.body matches "(?i)(union.*select|<script|\\.\\./)")`,
      `Action: BLOCK (Score: 100, Log: True)`,
      ``,
      `# 2. Nginx Perimeter Firewall (nginx.conf / site-enabled):`,
      `location ${targetPath} {`,
      `    deny ${ip}; # The Watch Automated Threat Block`,
      `    limit_req zone=auth_limit burst=5 nodelay;`,
      `}`,
      ``,
      `# 3. Linux Kernel IP Block (iptables / UFW):`,
      `iptables -I INPUT -s ${ip} -p tcp --dport 443 -j DROP`,
      `ufw insert 1 deny from ${ip} to any port 443 proto tcp`,
    ].join('\n');
  }
}

export const heuristicEngine = new HeuristicEngine();
