import dotenv from 'dotenv';
dotenv.config();

export interface TenantConfig {
  systemId: string;
  name: string;
  apiKey: string;
  apiSecret: string;
  description: string;
  primaryContact: string;
  enabled: boolean;
}

export interface SyntheticProbeConfig {
  id: string;
  systemId: string;
  name: string;
  targetUrl: string;
  method: 'GET' | 'POST' | 'HEAD';
  expectedStatus: number;
  intervalSeconds: number;
  timeoutMs: number;
  checkSsl: boolean;
  enabled: boolean;
}

export const CONFIG = {
  PORT: parseInt(process.env.PORT || '4000', 10),
  UDP_PORT: parseInt(process.env.UDP_PORT || '9876', 10),
  HOST: process.env.HOST || '0.0.0.0',
  ENV: process.env.NODE_ENV || 'development',
  DATABASE_URL: process.env.DATABASE_URL || '',
  REDIS_URL: process.env.REDIS_URL || '',
  HMAC_SECRET: process.env.HMAC_SECRET || 'the-watch-enterprise-hmac-master-key-2026',
  ALERT_EMAIL_RECIPIENTS: [
    'admin@institution.edu.ng',
    'it-security-director@institution.edu.ng'
  ],
  SLACK_WEBHOOK_URL: process.env.SLACK_WEBHOOK_URL || '',
  DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || '',
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || '',
  TIMEZONE: 'Africa/Lagos', // West Africa Time (WAT / UTC+1)
};

export const REGISTERED_TENANTS: Record<string, TenantConfig> = {
  'NOUN-HRMS': {
    systemId: 'NOUN-HRMS',
    name: 'National Open University HRMS Platform',
    apiKey: 'tel_sec_noun_hrms_98234',
    apiSecret: 'sec_sig_noun_8849204',
    description: 'Flagship University Human Resources & Payroll System',
    primaryContact: 'hrms-admin@noun.edu.ng',
    enabled: true,
  },
  'Clinic-EHR': {
    systemId: 'Clinic-EHR',
    name: 'University Clinic Electronic Health Records',
    apiKey: 'tel_sec_clinic_ehr_51283',
    apiSecret: 'sec_sig_clinic_441092',
    description: 'Campus Medical & Health Records System',
    primaryContact: 'clinic-sec@noun.edu.ng',
    enabled: true,
  },
  'Security-Dispatch': {
    systemId: 'Security-Dispatch',
    name: 'Campus Incident & Security Dispatch Unit',
    apiKey: 'tel_sec_sec_disp_77391',
    apiSecret: 'sec_sig_disp_119028',
    description: 'Physical & Digital Campus Security Dispatch System',
    primaryContact: 'dispatch-ops@noun.edu.ng',
    enabled: true,
  },
};

export const DEFAULT_PROBES: SyntheticProbeConfig[] = [
  {
    id: 'probe-noun-health',
    systemId: 'NOUN-HRMS',
    name: 'HRMS Core Health Probe',
    targetUrl: 'http://localhost:4000/api/mock/noun/health',
    method: 'GET',
    expectedStatus: 200,
    intervalSeconds: 30,
    timeoutMs: 5000,
    checkSsl: true,
    enabled: true,
  },
  {
    id: 'probe-noun-auth-session',
    systemId: 'NOUN-HRMS',
    name: 'Staff Auth Session Validator',
    targetUrl: 'http://localhost:4000/api/mock/noun/auth/session',
    method: 'GET',
    expectedStatus: 200,
    intervalSeconds: 30,
    timeoutMs: 5000,
    checkSsl: true,
    enabled: true,
  },
  {
    id: 'probe-noun-payroll-status',
    systemId: 'NOUN-HRMS',
    name: 'Payroll Batch Controller Status',
    targetUrl: 'http://localhost:4000/api/mock/noun/payroll/status',
    method: 'GET',
    expectedStatus: 200,
    intervalSeconds: 45,
    timeoutMs: 8000,
    checkSsl: true,
    enabled: true,
  },
  {
    id: 'probe-clinic-ehr-api',
    systemId: 'Clinic-EHR',
    name: 'EHR Medical Records Ingest API',
    targetUrl: 'http://localhost:4000/api/mock/clinic/health',
    method: 'GET',
    expectedStatus: 200,
    intervalSeconds: 60,
    timeoutMs: 5000,
    checkSsl: true,
    enabled: true,
  },
  {
    id: 'probe-security-dispatch-ws',
    systemId: 'Security-Dispatch',
    name: 'Security Dispatch Relay Link',
    targetUrl: 'http://localhost:4000/api/mock/dispatch/health',
    method: 'GET',
    expectedStatus: 200,
    intervalSeconds: 60,
    timeoutMs: 5000,
    checkSsl: true,
    enabled: true,
  },
];
