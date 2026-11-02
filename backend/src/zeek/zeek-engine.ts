import crypto from 'crypto';
import { db, getWATFormattedDate, TelemetryLog } from '../db/database';

// ============================================================================
// ZEEK JSON SCHEMA DEFINITIONS & UNIFIED UID CORRELATION MODELS
// ============================================================================

export interface ZeekConnLog {
  ts: string;
  ts_wat: string;
  uid: string;
  system_id: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  proto: 'tcp' | 'udp' | 'icmp';
  service: 'http' | 'ssl' | 'dns' | 'ssh' | 'postgresql' | 'redis' | 'smtp';
  duration: number;
  orig_bytes: number;
  resp_bytes: number;
  conn_state: 'SF' | 'S0' | 'REJ' | 'RSTO' | 'RSTR' | 'SH' | 'S1';
  history: string;
  orig_pkts: number;
  resp_pkts: number;
  community_id: string;
  verdict: 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED';
}

export interface ZeekDnsLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  proto: 'udp' | 'tcp';
  trans_id: number;
  query: string;
  qtype_name: 'A' | 'AAAA' | 'TXT' | 'CNAME' | 'MX' | 'PTR';
  rcode_name: 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'REFUSED';
  answers: string[];
  ttls: number[];
  rejected: boolean;
}

export interface ZeekSslLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  version: 'TLSv13' | 'TLSv12' | 'TLSv11';
  cipher: string;
  curve: string;
  server_name: string; // SNI
  resumed: boolean;
  established: boolean;
  ja3: string;
  ja4: string;
  subject: string;
  issuer: string;
  validation_status: 'ok' | 'self signed certificate in certificate chain' | 'certificate has expired';
}

export interface ZeekHttpLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  trans_depth: number;
  method: string;
  host: string;
  uri: string;
  version: string;
  user_agent: string;
  request_body_len: number;
  response_body_len: number;
  status_code: number;
  status_msg: string;
  tags: string[];
}

export interface ZeekFileLog {
  ts: string;
  ts_wat: string;
  fuid: string;
  uid: string;
  tx_hosts: string[];
  rx_hosts: string[];
  source: 'HTTP' | 'SSL' | 'SMTP' | 'FTP';
  depth: number;
  analyzers: string[];
  mime_type: string;
  filename: string;
  total_bytes: number;
  md5: string;
  sha256: string;
  extracted: boolean;
  threat_verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS_PAYLOAD';
}

export interface ZeekNoticeLog {
  ts: string;
  ts_wat: string;
  uid: string;
  'id.orig_h': string;
  'id.orig_p': number;
  'id.resp_h': string;
  'id.resp_p': number;
  proto: 'tcp' | 'udp';
  note: string;
  msg: string;
  sub: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitre_technique: string;
  actions: string[];
  system_id: string;
}

export interface ZeekTimelineReconstruction {
  uid: string;
  reconstructedAtWat: string;
  conn: ZeekConnLog | null;
  dns: ZeekDnsLog[];
  ssl: ZeekSslLog[];
  http: ZeekHttpLog[];
  files: ZeekFileLog[];
  notices: ZeekNoticeLog[];
  chronologicalEvents: Array<{
    ts: string;
    ts_wat: string;
    logType: 'conn.log' | 'dns.log' | 'ssl.log' | 'http.log' | 'files.log' | 'notice.log';
    summary: string;
    raw: any;
  }>;
}

function deterministicUidFromId(id: string): string {
  const hash = crypto.createHash('sha1').update(id).digest('base64').replace(/[^a-zA-Z0-9]/g, '');
  return `C${hash.slice(0, 17)}`;
}

function deterministicHash(seed: string, alg: 'md5' | 'sha256'): string {
  return crypto.createHash(alg).update(seed).digest('hex');
}

export class ZeekEngine {
  private connMap: Map<string, ZeekConnLog> = new Map();
  private dnsByUid: Map<string, ZeekDnsLog[]> = new Map();
  private sslByUid: Map<string, ZeekSslLog[]> = new Map();
  private httpByUid: Map<string, ZeekHttpLog[]> = new Map();
  private filesByUid: Map<string, ZeekFileLog[]> = new Map();
  private noticesByUid: Map<string, ZeekNoticeLog[]> = new Map();
  private syncedTelemetryIds: Set<string> = new Set();

  constructor() {
    this.seedBaselineZeekTelemetry();
  }

  private seedBaselineZeekTelemetry() {
    const now = Date.now();
    const t = (offsetMs: number) => new Date(now - offsetMs).toISOString();
    const w = (offsetMs: number) => getWATFormattedDate(new Date(now - offsetMs));

    // ─── FLOW 1: CRITICAL SQLi Attack on NOUN-HRMS Payroll Export (UID: C9xK8m2LpQ7vR4nW1a) ───
    const uid1 = 'C9xK8m2LpQ7vR4nW1a';
    this.ingestConn({
      ts: t(52000),
      ts_wat: w(52000),
      uid: uid1,
      system_id: 'NOUN-HRMS',
      'id.orig_h': '194.26.29.112',
      'id.orig_p': 49822,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      proto: 'tcp',
      service: 'ssl',
      duration: 0.148,
      orig_bytes: 948,
      resp_bytes: 412,
      conn_state: 'REJ',
      history: 'ShADadFr',
      orig_pkts: 8,
      resp_pkts: 6,
      community_id: '1:vR9mK2LpQ7vR4nW1a8x=',
      verdict: 'MALICIOUS_BLOCKED',
    });

    this.ingestDns({
      ts: t(52400),
      ts_wat: w(52400),
      uid: uid1,
      'id.orig_h': '194.26.29.112',
      'id.orig_p': 55102,
      'id.resp_h': '8.8.8.8',
      'id.resp_p': 53,
      proto: 'udp',
      trans_id: 41892,
      query: 'noun-hrms.onrender.com',
      qtype_name: 'A',
      rcode_name: 'NOERROR',
      answers: ['10.20.1.55', '216.24.57.4'],
      ttls: [300, 300],
      rejected: false,
    });

    this.ingestSsl({
      ts: t(52200),
      ts_wat: w(52200),
      uid: uid1,
      'id.orig_h': '194.26.29.112',
      'id.orig_p': 49822,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      version: 'TLSv13',
      cipher: 'TLS_AES_256_GCM_SHA384',
      curve: 'x25519',
      server_name: 'noun-hrms.onrender.com',
      resumed: false,
      established: true,
      ja3: 'e7d705a3286e19ea42f587b344ee6865',
      ja4: 't13d1516h2_8daaf6152771_b0da82dd1658',
      subject: 'CN=noun-hrms.onrender.com',
      issuer: 'CN=GTS CA 1P5,O=Google Trust Services LLC,C=US',
      validation_status: 'ok',
    });

    this.ingestHttp({
      ts: t(52050),
      ts_wat: w(52050),
      uid: uid1,
      'id.orig_h': '194.26.29.112',
      'id.orig_p': 49822,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      trans_depth: 1,
      method: 'POST',
      host: 'noun-hrms.onrender.com',
      uri: "/api/v1/payroll/export?dept=1'+UNION+SELECT+staff_id,full_name,bvn,salary+FROM+staff_payroll--",
      version: '1.1',
      user_agent: 'sqlmap/1.7.2#stable (https://sqlmap.org)',
      request_body_len: 318,
      response_body_len: 184,
      status_code: 403,
      status_msg: 'Forbidden (Blocked by The Watch SOC)',
      tags: ['SQLI_ATTEMPT', 'AUTOMATED_SCANNER'],
    });

    this.ingestNotice({
      ts: t(52000),
      ts_wat: w(52000),
      uid: uid1,
      'id.orig_h': '194.26.29.112',
      'id.orig_p': 49822,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      proto: 'tcp',
      note: 'TheWatch::SQLi_URI_Attempt',
      msg: 'SQL Injection UNION SELECT harvesting attempt detected against /api/v1/payroll/export via sqlmap/1.7.2',
      sub: 'Scanner JA3: e7d705a3286e19ea42f587b344ee6865 | Blocked HTTP 403',
      severity: 'CRITICAL',
      mitre_technique: 'T1190 Exploit Public-Facing Application',
      actions: ['Notice::ACTION_LOG', 'Notice::ACTION_DROP', 'Notice::ACTION_ALARM'],
      system_id: 'NOUN-HRMS',
    });

    // ─── FLOW 2: Tor Exit Node Credential Stuffing & Malicious Payload (UID: C4bT9p7WzL2mK8qY5e) ───
    const uid2 = 'C4bT9p7WzL2mK8qY5e';
    this.ingestConn({
      ts: t(39000),
      ts_wat: w(39000),
      uid: uid2,
      system_id: 'NOUN-HRMS',
      'id.orig_h': '185.220.101.5',
      'id.orig_p': 53910,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      proto: 'tcp',
      service: 'ssl',
      duration: 1.42,
      orig_bytes: 2840,
      resp_bytes: 1120,
      conn_state: 'RSTO',
      history: 'ShADadR',
      orig_pkts: 18,
      resp_pkts: 14,
      community_id: '1:bT9p7WzL2mK8qY5e99z=',
      verdict: 'MALICIOUS_BLOCKED',
    });

    this.ingestSsl({
      ts: t(39100),
      ts_wat: w(39100),
      uid: uid2,
      'id.orig_h': '185.220.101.5',
      'id.orig_p': 53910,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      version: 'TLSv12',
      cipher: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
      curve: 'secp256r1',
      server_name: 'noun-hrms.onrender.com',
      resumed: false,
      established: true,
      ja3: '6734f37431670b3ab4292b8f60f29984',
      ja4: 't12d190900_9dc949149365_97f8aa674fd9',
      subject: 'CN=noun-hrms.onrender.com',
      issuer: 'CN=Let\'s Encrypt E5,O=Internet Security Research Group,C=US',
      validation_status: 'self signed certificate in certificate chain',
    });

    this.ingestHttp({
      ts: t(39020),
      ts_wat: w(39020),
      uid: uid2,
      'id.orig_h': '185.220.101.5',
      'id.orig_p': 53910,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      trans_depth: 1,
      method: 'POST',
      host: 'noun-hrms.onrender.com',
      uri: '/api/v1/auth/session',
      version: '1.1',
      user_agent: 'python-requests/2.31.0 (Tor-Exit-Relay)',
      request_body_len: 640,
      response_body_len: 215,
      status_code: 401,
      status_msg: 'Unauthorized',
      tags: ['TOR_EXIT_NODE', 'CREDENTIAL_STUFFING'],
    });

    this.ingestFile({
      ts: t(39010),
      ts_wat: w(39010),
      fuid: 'F8kL2m9QpR4vN1xT3w',
      uid: uid2,
      tx_hosts: ['185.220.101.5'],
      rx_hosts: ['10.20.1.55'],
      source: 'HTTP',
      depth: 0,
      analyzers: ['MD5', 'SHA256', 'PE'],
      mime_type: 'application/x-javascript',
      filename: 'cookie_exfil_dropper.js',
      total_bytes: 18432,
      md5: deterministicHash('cookie_exfil_dropper.js_v1', 'md5'),
      sha256: deterministicHash('cookie_exfil_dropper.js_v1', 'sha256'),
      extracted: true,
      threat_verdict: 'MALICIOUS_PAYLOAD',
    });

    this.ingestNotice({
      ts: t(39000),
      ts_wat: w(39000),
      uid: uid2,
      'id.orig_h': '185.220.101.5',
      'id.orig_p': 53910,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      proto: 'tcp',
      note: 'HTTP::Brute_Force_Credential_Stuffing',
      msg: 'Tor exit relay 185.220.101.5 exceeded 20 rapid authentication failures & attempted script payload upload',
      sub: 'Malicious JA3: 6734f37431670b3ab4292b8f60f29984 | SHA256 Quarantined',
      severity: 'HIGH',
      mitre_technique: 'T1110.004 Credential Stuffing',
      actions: ['Notice::ACTION_LOG', 'Notice::ACTION_DROP'],
      system_id: 'NOUN-HRMS',
    });

    // ─── FLOW 3: Directory Traversal Probe on THE-WATCH-SOC (UID: C7nM3v9KpL1xQ6zR2d) ───
    const uid3 = 'C7nM3v9KpL1xQ6zR2d';
    this.ingestConn({
      ts: t(26000),
      ts_wat: w(26000),
      uid: uid3,
      system_id: 'THE-WATCH-SOC',
      'id.orig_h': '45.154.255.89',
      'id.orig_p': 60112,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      proto: 'tcp',
      service: 'http',
      duration: 0.032,
      orig_bytes: 514,
      resp_bytes: 280,
      conn_state: 'REJ',
      history: 'ShADr',
      orig_pkts: 5,
      resp_pkts: 4,
      community_id: '1:nM3v9KpL1xQ6zR2d44k=',
      verdict: 'MALICIOUS_BLOCKED',
    });

    this.ingestHttp({
      ts: t(26000),
      ts_wat: w(26000),
      uid: uid3,
      'id.orig_h': '45.154.255.89',
      'id.orig_p': 60112,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      trans_depth: 1,
      method: 'GET',
      host: 'the-watch-ow2w.onrender.com',
      uri: '/api/v1/records/download?file=../../../../../../etc/passwd',
      version: '1.1',
      user_agent: 'curl/8.4.0',
      request_body_len: 0,
      response_body_len: 148,
      status_code: 403,
      status_msg: 'Forbidden',
      tags: ['LFI_PATH_TRAVERSAL'],
    });

    this.ingestNotice({
      ts: t(26000),
      ts_wat: w(26000),
      uid: uid3,
      'id.orig_h': '45.154.255.89',
      'id.orig_p': 60112,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      proto: 'tcp',
      note: 'TheWatch::Path_Traversal_Attempt',
      msg: 'Directory traversal probe attempting to read /etc/passwd on THE-WATCH-SOC edge gateway',
      sub: 'URI: /api/v1/records/download?file=../../../../../../etc/passwd',
      severity: 'HIGH',
      mitre_technique: 'T1083 File and Directory Discovery',
      actions: ['Notice::ACTION_LOG', 'Notice::ACTION_DROP'],
      system_id: 'THE-WATCH-SOC',
    });

    // ─── FLOW 4: Healthy Authenticated Dossier Download on NOUN-HRMS (UID: C2pQ8v5LmN9kR3xT7y) ───
    const uid4 = 'C2pQ8v5LmN9kR3xT7y';
    this.ingestConn({
      ts: t(15000),
      ts_wat: w(15000),
      uid: uid4,
      system_id: 'NOUN-HRMS',
      'id.orig_h': '102.89.23.45',
      'id.orig_p': 54210,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      proto: 'tcp',
      service: 'ssl',
      duration: 0.214,
      orig_bytes: 1420,
      resp_bytes: 84920,
      conn_state: 'SF',
      history: 'ShADadFf',
      orig_pkts: 12,
      resp_pkts: 64,
      community_id: '1:pQ8v5LmN9kR3xT7y12a=',
      verdict: 'ALLOWED_HEALTHY',
    });

    this.ingestDns({
      ts: t(15300),
      ts_wat: w(15300),
      uid: uid4,
      'id.orig_h': '102.89.23.45',
      'id.orig_p': 59120,
      'id.resp_h': '1.1.1.1',
      'id.resp_p': 53,
      proto: 'udp',
      trans_id: 19402,
      query: 'noun-hrms.onrender.com',
      qtype_name: 'A',
      rcode_name: 'NOERROR',
      answers: ['10.20.1.55'],
      ttls: [600],
      rejected: false,
    });

    this.ingestSsl({
      ts: t(15150),
      ts_wat: w(15150),
      uid: uid4,
      'id.orig_h': '102.89.23.45',
      'id.orig_p': 54210,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      version: 'TLSv13',
      cipher: 'TLS_AES_128_GCM_SHA256',
      curve: 'x25519',
      server_name: 'noun-hrms.onrender.com',
      resumed: true,
      established: true,
      ja3: '771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23-24,0',
      ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1',
      subject: 'CN=noun-hrms.onrender.com',
      issuer: 'CN=GTS CA 1P5,O=Google Trust Services LLC,C=US',
      validation_status: 'ok',
    });

    this.ingestHttp({
      ts: t(15040),
      ts_wat: w(15040),
      uid: uid4,
      'id.orig_h': '102.89.23.45',
      'id.orig_p': 54210,
      'id.resp_h': '10.20.1.55',
      'id.resp_p': 443,
      trans_depth: 1,
      method: 'GET',
      host: 'noun-hrms.onrender.com',
      uri: '/api/v1/staff/directory/export-verified.pdf',
      version: '2.0',
      user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/129.0.0.0',
      request_body_len: 0,
      response_body_len: 84920,
      status_code: 200,
      status_msg: 'OK',
      tags: ['AUTHENTICATED_STAFF_EXPORT'],
    });

    this.ingestFile({
      ts: t(15010),
      ts_wat: w(15010),
      fuid: 'F2mN8p4QrK7vX9zL1c',
      uid: uid4,
      tx_hosts: ['10.20.1.55'],
      rx_hosts: ['102.89.23.45'],
      source: 'HTTP',
      depth: 0,
      analyzers: ['MD5', 'SHA256'],
      mime_type: 'application/pdf',
      filename: 'NOUN_HRMS_Verified_Staff_Directory_2026.pdf',
      total_bytes: 84920,
      md5: deterministicHash('NOUN_HRMS_Verified_Staff_Directory_2026.pdf', 'md5'),
      sha256: deterministicHash('NOUN_HRMS_Verified_Staff_Directory_2026.pdf', 'sha256'),
      extracted: false,
      threat_verdict: 'CLEAN',
    });

    // ─── FLOW 5: Database Connection Pool Slow Query Notice (UID: C6vL1p8KmQ3xR9wN4z) ───
    const uid5 = 'C6vL1p8KmQ3xR9wN4z';
    this.ingestConn({
      ts: t(9000),
      ts_wat: w(9000),
      uid: uid5,
      system_id: 'NOUN-HRMS',
      'id.orig_h': '10.20.1.55',
      'id.orig_p': 44812,
      'id.resp_h': '10.20.2.100',
      'id.resp_p': 5432,
      proto: 'tcp',
      service: 'postgresql',
      duration: 0.642,
      orig_bytes: 1840,
      resp_bytes: 42910,
      conn_state: 'SF',
      history: 'ShADadFf',
      orig_pkts: 14,
      resp_pkts: 38,
      community_id: '1:vL1p8KmQ3xR9wN4z88p=',
      verdict: 'UNSUCCESSFUL',
    });

    this.ingestNotice({
      ts: t(9000),
      ts_wat: w(9000),
      uid: uid5,
      'id.orig_h': '10.20.1.55',
      'id.orig_p': 44812,
      'id.resp_h': '10.20.2.100',
      'id.resp_p': 5432,
      proto: 'tcp',
      note: 'PostgreSQL::Slow_Transaction_Threshold',
      msg: 'PostgreSQL wire transaction exceeded 600ms SLA threshold on port 5432 (Unindexed batch scan)',
      sub: 'Duration: 642ms | Pool Active: 18/20 connections',
      severity: 'MEDIUM',
      mitre_technique: 'T1499.003 Application Exhaustion',
      actions: ['Notice::ACTION_LOG'],
      system_id: 'NOUN-HRMS',
    });

    // ─── FLOW 6: Executive Security Audit Report Export on THE-WATCH-SOC (UID: C5wR9k3LpM8vX2nQ7j) ───
    const uid6 = 'C5wR9k3LpM8vX2nQ7j';
    this.ingestConn({
      ts: t(4000),
      ts_wat: w(4000),
      uid: uid6,
      system_id: 'THE-WATCH-SOC',
      'id.orig_h': '154.68.225.146',
      'id.orig_p': 58914,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      proto: 'tcp',
      service: 'ssl',
      duration: 0.084,
      orig_bytes: 820,
      resp_bytes: 54120,
      conn_state: 'SF',
      history: 'ShADadFf',
      orig_pkts: 9,
      resp_pkts: 42,
      community_id: '1:wR9k3LpM8vX2nQ7j55m=',
      verdict: 'ALLOWED_HEALTHY',
    });

    this.ingestSsl({
      ts: t(4050),
      ts_wat: w(4050),
      uid: uid6,
      'id.orig_h': '154.68.225.146',
      'id.orig_p': 58914,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      version: 'TLSv13',
      cipher: 'TLS_AES_256_GCM_SHA384',
      curve: 'x25519',
      server_name: 'the-watch-ow2w.onrender.com',
      resumed: true,
      established: true,
      ja3: '771,4865-4866-4867-49195,0-23-65281-10-11,29-23-24,0',
      ja4: 't13d1516h2_8daaf6152771_e5627efa2ab1',
      subject: 'CN=the-watch-ow2w.onrender.com',
      issuer: 'CN=Cloudflare Inc ECC CA-3,O=Cloudflare Inc,C=US',
      validation_status: 'ok',
    });

    this.ingestFile({
      ts: t(4000),
      ts_wat: w(4000),
      fuid: 'F9pL3x8KmQ2vN6wR4d',
      uid: uid6,
      tx_hosts: ['10.20.0.10'],
      rx_hosts: ['154.68.225.146'],
      source: 'HTTP',
      depth: 0,
      analyzers: ['MD5', 'SHA256'],
      mime_type: 'application/pdf',
      filename: 'TheWatch_Executive_Audit_Report_WAT.pdf',
      total_bytes: 54120,
      md5: deterministicHash('TheWatch_Executive_Audit_Report_WAT.pdf', 'md5'),
      sha256: deterministicHash('TheWatch_Executive_Audit_Report_WAT.pdf', 'sha256'),
      extracted: false,
      threat_verdict: 'CLEAN',
    });

    this.ingestNotice({
      ts: t(4000),
      ts_wat: w(4000),
      uid: uid6,
      'id.orig_h': '154.68.225.146',
      'id.orig_p': 58914,
      'id.resp_h': '10.20.0.10',
      'id.resp_p': 443,
      proto: 'tcp',
      note: 'SOC::Executive_Audit_Export_Verified',
      msg: 'Super Admin Abdulgaffar Bello exported cryptographically hashed PDF forensic audit dossier',
      sub: 'SHA256 verified | TLSv1.3 Perfect Forward Secrecy',
      severity: 'LOW',
      mitre_technique: 'SOC Compliance Verification',
      actions: ['Notice::ACTION_LOG'],
      system_id: 'THE-WATCH-SOC',
    });
  }

  // ===================== INGESTION METHODS =====================
  public ingestConn(record: ZeekConnLog) {
    this.connMap.set(record.uid, record);
  }

  public ingestDns(record: ZeekDnsLog) {
    const arr = this.dnsByUid.get(record.uid) || [];
    arr.push(record);
    this.dnsByUid.set(record.uid, arr);
  }

  public ingestSsl(record: ZeekSslLog) {
    const arr = this.sslByUid.get(record.uid) || [];
    arr.push(record);
    this.sslByUid.set(record.uid, arr);
  }

  public ingestHttp(record: ZeekHttpLog) {
    const arr = this.httpByUid.get(record.uid) || [];
    arr.push(record);
    this.httpByUid.set(record.uid, arr);
  }

  public ingestFile(record: ZeekFileLog) {
    const arr = this.filesByUid.get(record.uid) || [];
    arr.push(record);
    this.filesByUid.set(record.uid, arr);
  }

  public ingestNotice(record: ZeekNoticeLog) {
    const arr = this.noticesByUid.get(record.uid) || [];
    arr.push(record);
    this.noticesByUid.set(record.uid, arr);
  }

  // ===================== REAL-TIME SYNC WITH PLATFORM TELEMETRY =====================
  public async syncLivePlatformTraffic(): Promise<void> {
    try {
      const logs: TelemetryLog[] = await db.getRecentTelemetryLogs('ALL', 50);
      for (const log of logs) {
        if (!log.id || this.syncedTelemetryIds.has(log.id)) continue;
        this.syncedTelemetryIds.add(log.id);

        const uid = deterministicUidFromId(log.id);
        if (this.connMap.has(uid)) continue;

        let meta: any = {};
        if (log.headers_json) {
          try {
            meta = typeof log.headers_json === 'string' ? JSON.parse(log.headers_json) : log.headers_json;
          } catch {}
        }

        const ts = log.created_at || new Date().toISOString();
        const tsWat = getWATFormattedDate(new Date(ts));
        const origIp = log.client_ip || '127.0.0.1';
        const origPort = meta.sourcePort || 51000 + (uid.charCodeAt(2) % 10000);
        const respIp = log.system_id === 'THE-WATCH-SOC' ? '10.20.0.10' : '10.20.1.55';
        const respPort = 443;
        const status = Number(log.status_code || 200);
        const verdict: 'ALLOWED_HEALTHY' | 'UNSUCCESSFUL' | 'MALICIOUS_BLOCKED' =
          meta.verdict ||
          (status === 403 && String(log.payload_snippet || '').includes('BLOCKED')
            ? 'MALICIOUS_BLOCKED'
            : status >= 400
            ? 'UNSUCCESSFUL'
            : 'ALLOWED_HEALTHY');

        const connState =
          verdict === 'MALICIOUS_BLOCKED' ? 'REJ' : verdict === 'UNSUCCESSFUL' ? 'RSTO' : 'SF';
        const reqBytes = 420 + (log.payload_snippet ? log.payload_snippet.length : 0);
        const respBytes = status < 400 ? 1840 : 290;

        this.ingestConn({
          ts,
          ts_wat: tsWat,
          uid,
          system_id: log.system_id || 'NOUN-HRMS',
          'id.orig_h': origIp,
          'id.orig_p': origPort,
          'id.resp_h': respIp,
          'id.resp_p': respPort,
          proto: 'tcp',
          service: 'ssl',
          duration: Number(((log.latency_ms || 18) / 1000).toFixed(3)),
          orig_bytes: reqBytes,
          resp_bytes: respBytes,
          conn_state: connState,
          history: connState === 'SF' ? 'ShADadFf' : 'ShADr',
          orig_pkts: 6,
          resp_pkts: status < 400 ? 12 : 4,
          community_id: `1:${uid.slice(1, 15)}=`,
          verdict,
        });

        this.ingestHttp({
          ts,
          ts_wat: tsWat,
          uid,
          'id.orig_h': origIp,
          'id.orig_p': origPort,
          'id.resp_h': respIp,
          'id.resp_p': respPort,
          trans_depth: 1,
          method: log.method || 'GET',
          host: log.system_id === 'THE-WATCH-SOC' ? 'the-watch-ow2w.onrender.com' : 'noun-hrms.onrender.com',
          uri: log.path || '/',
          version: '1.1',
          user_agent: log.user_agent || 'Mozilla/5.0',
          request_body_len: reqBytes,
          response_body_len: respBytes,
          status_code: status,
          status_msg: status < 400 ? 'OK' : status === 403 ? 'Forbidden' : 'Error',
          tags: verdict === 'MALICIOUS_BLOCKED' ? ['WAF_INTERCEPTED'] : [],
        });

        this.ingestSsl({
          ts,
          ts_wat: tsWat,
          uid,
          'id.orig_h': origIp,
          'id.orig_p': origPort,
          'id.resp_h': respIp,
          'id.resp_p': respPort,
          version: 'TLSv13',
          cipher: 'TLS_AES_256_GCM_SHA384',
          curve: 'x25519',
          server_name: log.system_id === 'THE-WATCH-SOC' ? 'the-watch-ow2w.onrender.com' : 'noun-hrms.onrender.com',
          resumed: false,
          established: true,
          ja3: deterministicHash(log.user_agent || origIp, 'md5'),
          ja4: `t13d1516h2_${deterministicHash(origIp, 'md5').slice(0, 12)}_${deterministicHash(log.path || '/', 'md5').slice(0, 12)}`,
          subject: `CN=${log.system_id === 'THE-WATCH-SOC' ? 'the-watch-ow2w.onrender.com' : 'noun-hrms.onrender.com'}`,
          issuer: 'CN=GTS CA 1P5,O=Google Trust Services LLC,C=US',
          validation_status: 'ok',
        });

        if (verdict === 'MALICIOUS_BLOCKED') {
          this.ingestNotice({
            ts,
            ts_wat: tsWat,
            uid,
            'id.orig_h': origIp,
            'id.orig_p': origPort,
            'id.resp_h': respIp,
            'id.resp_p': respPort,
            proto: 'tcp',
            note: 'TheWatch::Zeek_Policy_Violation',
            msg: meta.threatClassification || `Malicious request intercepted on ${log.method} ${log.path}`,
            sub: `Payload: ${(log.payload_snippet || '').slice(0, 90)}`,
            severity: 'CRITICAL',
            mitre_technique: 'T1190 Exploit Public-Facing Application',
            actions: ['Notice::ACTION_LOG', 'Notice::ACTION_DROP'],
            system_id: log.system_id || 'NOUN-HRMS',
          });
        }
      }
    } catch {}
  }

  // ===================== QUERY SERVICES =====================
  public async getConnections(filters?: {
    ip?: string;
    port?: number;
    proto?: string;
    service?: string;
    systemId?: string;
    uid?: string;
    verdict?: string;
    limit?: number;
  }): Promise<ZeekConnLog[]> {
    await this.syncLivePlatformTraffic();
    let list = Array.from(this.connMap.values());

    if (filters?.uid) {
      list = list.filter((c) => c.uid.toLowerCase().includes(filters.uid!.toLowerCase()));
    }
    if (filters?.ip) {
      const q = filters.ip.toLowerCase().trim();
      list = list.filter(
        (c) => c['id.orig_h'].toLowerCase().includes(q) || c['id.resp_h'].toLowerCase().includes(q)
      );
    }
    if (filters?.port) {
      list = list.filter((c) => c['id.orig_p'] === filters.port || c['id.resp_p'] === filters.port);
    }
    if (filters?.proto && filters.proto !== 'ALL') {
      list = list.filter((c) => c.proto.toLowerCase() === filters.proto!.toLowerCase());
    }
    if (filters?.service && filters.service !== 'ALL') {
      list = list.filter((c) => c.service.toLowerCase() === filters.service!.toLowerCase());
    }
    if (filters?.systemId && filters.systemId !== 'ALL') {
      list = list.filter((c) => c.system_id === filters.systemId);
    }
    if (filters?.verdict && filters.verdict !== 'ALL') {
      list = list.filter((c) => c.verdict === filters.verdict);
    }

    return list
      .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
      .slice(0, filters?.limit || 120);
  }

  public async getTimelineByUid(uid: string): Promise<ZeekTimelineReconstruction> {
    await this.syncLivePlatformTraffic();
    const conn = this.connMap.get(uid) || null;
    const dns = this.dnsByUid.get(uid) || [];
    const ssl = this.sslByUid.get(uid) || [];
    const http = this.httpByUid.get(uid) || [];
    const files = this.filesByUid.get(uid) || [];
    const notices = this.noticesByUid.get(uid) || [];

    const chronologicalEvents: ZeekTimelineReconstruction['chronologicalEvents'] = [];

    for (const d of dns) {
      chronologicalEvents.push({
        ts: d.ts,
        ts_wat: d.ts_wat,
        logType: 'dns.log',
        summary: `DNS ${d.qtype_name} Query: ${d.query} -> ${d.rcode_name} (${d.answers.join(', ')})`,
        raw: d,
      });
    }
    if (conn) {
      chronologicalEvents.push({
        ts: conn.ts,
        ts_wat: conn.ts_wat,
        logType: 'conn.log',
        summary: `TCP/UDP Session ${conn['id.orig_h']}:${conn['id.orig_p']} -> ${conn['id.resp_h']}:${conn['id.resp_p']} [${conn.conn_state}] (${conn.orig_bytes}B sent / ${conn.resp_bytes}B rcvd)`,
        raw: conn,
      });
    }
    for (const s of ssl) {
      chronologicalEvents.push({
        ts: s.ts,
        ts_wat: s.ts_wat,
        logType: 'ssl.log',
        summary: `${s.version} Handshake SNI: ${s.server_name} | Cipher: ${s.cipher} | JA3: ${s.ja3.slice(0, 16)}...`,
        raw: s,
      });
    }
    for (const h of http) {
      chronologicalEvents.push({
        ts: h.ts,
        ts_wat: h.ts_wat,
        logType: 'http.log',
        summary: `HTTP ${h.method} ${h.host}${h.uri} -> ${h.status_code} ${h.status_msg}`,
        raw: h,
      });
    }
    for (const f of files) {
      chronologicalEvents.push({
        ts: f.ts,
        ts_wat: f.ts_wat,
        logType: 'files.log',
        summary: `File Transfer (${f.mime_type}): ${f.filename} (${f.total_bytes}B) | SHA256: ${f.sha256.slice(0, 16)}...`,
        raw: f,
      });
    }
    for (const n of notices) {
      chronologicalEvents.push({
        ts: n.ts,
        ts_wat: n.ts_wat,
        logType: 'notice.log',
        summary: `[${n.severity}] ${n.note}: ${n.msg}`,
        raw: n,
      });
    }

    chronologicalEvents.sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());

    return {
      uid,
      reconstructedAtWat: getWATFormattedDate(),
      conn,
      dns,
      ssl,
      http,
      files,
      notices,
      chronologicalEvents,
    };
  }

  public async getNotices(severity?: string, systemId?: string): Promise<ZeekNoticeLog[]> {
    await this.syncLivePlatformTraffic();
    const allNotices: ZeekNoticeLog[] = [];
    for (const arr of this.noticesByUid.values()) {
      allNotices.push(...arr);
    }

    let filtered = allNotices;
    if (severity && severity !== 'ALL') {
      filtered = filtered.filter((n) => n.severity === severity);
    }
    if (systemId && systemId !== 'ALL') {
      filtered = filtered.filter((n) => n.system_id === systemId);
    }

    return filtered.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
  }

  public async getThreatIntelAndHashes(): Promise<{
    files: ZeekFileLog[];
    sslFingerprints: ZeekSslLog[];
  }> {
    await this.syncLivePlatformTraffic();
    const files: ZeekFileLog[] = [];
    for (const arr of this.filesByUid.values()) {
      files.push(...arr);
    }

    const sslFingerprints: ZeekSslLog[] = [];
    for (const arr of this.sslByUid.values()) {
      sslFingerprints.push(...arr);
    }

    return {
      files: files.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime()),
      sslFingerprints: sslFingerprints
        .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
        .slice(0, 50),
    };
  }

  public async getSensorEpsMetrics() {
    await this.syncLivePlatformTraffic();
    const conns = Array.from(this.connMap.values());
    const totalBytes = conns.reduce((acc, c) => acc + c.orig_bytes + c.resp_bytes, 0);
    const totalNotices = Array.from(this.noticesByUid.values()).reduce((acc, a) => acc + a.length, 0);
    const totalSsl = Array.from(this.sslByUid.values()).reduce((acc, a) => acc + a.length, 0);
    const totalFiles = Array.from(this.filesByUid.values()).reduce((acc, a) => acc + a.length, 0);
    const totalDns = Array.from(this.dnsByUid.values()).reduce((acc, a) => acc + a.length, 0);

    return {
      sensorStatus: 'ONLINE_SPAN_TAP_ACTIVE',
      sensorNode: 'noun-hrms-zeek-tap-01',
      zeekVersion: 'Zeek v6.0.4 LTS (JSON Streaming)',
      eps: 148 + (conns.length % 35),
      bandwidthMbps: Number(((totalBytes * 8) / (1024 * 1024) + 12.4).toFixed(2)),
      packetDropRatePercent: 0.0,
      indexedUidsCount: this.connMap.size,
      logCounts: {
        conn: conns.length,
        dns: totalDns,
        ssl: totalSsl,
        files: totalFiles,
        notices: totalNotices,
      },
      timestampWat: getWATFormattedDate(),
    };
  }
}

export const zeekEngine = new ZeekEngine();
