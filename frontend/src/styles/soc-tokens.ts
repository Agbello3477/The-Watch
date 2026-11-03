/**
 * ============================================================================
 * THE WATCH — Enterprise SOC Design System & Semantic Threat Hierarchy Tokens
 * ============================================================================
 * Visual Mass Allocation:
 * - 80% Neutral & Structural Surfaces (#0B0F19, #161B26, #1F2937, #2D3748)
 * - 15% Typographic Hierarchy (#F8FAFC, #E2E8F0, #94A3B8, #64748B)
 * - 5%  Semantic Threat & Status Accents (#EF4444, #F97316, #EAB308, #3B82F6, #10B981)
 * ============================================================================
 */

export const SOC_TOKENS = {
  neutral: {
    rootBg: '#0B0F19',       // Deep Charcoal Navy (Never #000000)
    surface: '#161B26',      // Card panels, table wrappers, modular widgets
    elevated: '#1F2937',     // Modals, dropdowns, tooltips, active rows
    border: '#2D3748',       // Table gridlines, card borders, dividers
    focusStroke: '#4B5563',  // Focus / active stroke
  },
  typography: {
    primary: '#F8FAFC',      // Primary metrics & values (Off-white, never harsh #FFFFFF)
    heading: '#E2E8F0',      // Section headings
    secondary: '#94A3B8',    // Column labels & descriptions
    muted: '#64748B',        // Metadata, timestamps (WAT), SHA256/JA3 hashes
  },
  semantic: {
    critical: '#EF4444',     // P1 / Critical: Active compromises, critical CVEs, confirmed attacks
    high: '#F97316',         // P2 / High: Privilege escalations, suspicious lateral movements
    medium: '#EAB308',       // P3 / Medium: Policy anomalies, threshold spikes, brute-force attempts
    low: '#3B82F6',          // P4 / Low / Info: System health heartbeats, informational logs
    resolved: '#10B981',     // Resolved / Normal: Mitigated incidents, healthy sensor connections
  },
} as const;

export type SocSeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'RESOLVED' | 'P1' | 'P2' | 'P3' | 'P4';

/**
 * Returns the standardized Tailwind classes for any threat severity or status badge:
 * - 10% alpha background fill
 * - 1px 30% alpha matching border
 * - Solid semantic text color (WCAG AA compliant on #0B0F19 / #161B26)
 */
export function getSocSeverityBadgeClass(severity: string): string {
  const norm = (severity || '').toUpperCase().trim();
  switch (norm) {
    case 'CRITICAL':
    case 'P1':
    case 'DOWN':
    case 'MALICIOUS_BLOCKED':
    case 'BLOCKED':
      return 'bg-red-500/10 text-red-400 border border-red-500/30';
    case 'HIGH':
    case 'P2':
      return 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
    case 'MEDIUM':
    case 'P3':
    case 'DEGRADED':
    case 'UNSUCCESSFUL':
    case 'ACKNOWLEDGED':
    case 'INVESTIGATING':
    case 'TRIAGE':
      return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
    case 'LOW':
    case 'P4':
    case 'INFO':
      return 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
    case 'RESOLVED':
    case 'CLOSED':
    case 'CONTAINED':
    case 'UP':
    case 'HEALTHY':
    case 'NORMAL':
    case 'ALLOWED_HEALTHY':
      return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    default:
      return 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
  }
}

export const SOC_CLASSES = {
  canvas: 'bg-[#0B0F19] text-[#F8FAFC]',
  card: 'bg-[#161B26] border border-[#2D3748] rounded-xl',
  elevated: 'bg-[#1F2937] border border-[#2D3748] rounded-xl',
  tableHeader: 'bg-[#0B0F19] text-[#94A3B8] border-b border-[#2D3748] text-xs uppercase tracking-wider font-mono',
  tableRow: 'border-b border-[#2D3748] odd:bg-[#161B26] even:bg-[#0B0F19]/45 hover:bg-[#1F2937]/70 transition-colors',
  buttonDefault: 'bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition cursor-pointer',
  buttonPrimary: 'bg-blue-600 hover:bg-blue-500 text-slate-100 border border-blue-500/40 transition cursor-pointer',
  inputField: 'bg-[#0B0F19] border border-[#2D3748] text-[#F8FAFC] placeholder-[#64748B] focus:outline-none focus:border-[#4B5563] focus:ring-1 focus:ring-[#4B5563]',
} as const;
