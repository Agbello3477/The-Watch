import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  Info,
  CheckCircle2,
  ShieldAlert,
} from 'lucide-react';

export type SocSeverityLevel =
  | 'CRITICAL'
  | 'P1'
  | 'HIGH'
  | 'P2'
  | 'MEDIUM'
  | 'P3'
  | 'WARNING'
  | 'LOW'
  | 'INFO'
  | 'RESOLVED'
  | 'NORMAL'
  | 'HEALTHY'
  | 'DEGRADED'
  | 'DOWN'
  | string;

interface SocSeverityBadgeProps {
  severity: SocSeverityLevel;
  label?: string;
  size?: 'xs' | 'sm' | 'md';
  pulse?: boolean;
  className?: string;
}

/**
 * Enterprise SOC Severity & Status Badge
 * Follows strict 5% semantic visual mass & protanopia/deuteranopia accessibility rules:
 * - Semi-transparent alpha container (10% opacity)
 * - Subtle 1px matching border (30% opacity)
 * - Solid semantic text
 * - Redundant geometric iconography + explicit uppercase text label
 */
export const SocSeverityBadge: React.FC<SocSeverityBadgeProps> = ({
  severity,
  label,
  size = 'xs',
  pulse = false,
  className = '',
}) => {
  const normalized = String(severity || 'INFO').toUpperCase();

  let badgeStyle = 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
  let IconComponent = Info;
  let defaultLabel = normalized;

  if (
    normalized === 'CRITICAL' ||
    normalized === 'P1' ||
    normalized === 'DOWN' ||
    normalized === 'BLOCKED' ||
    normalized === 'MALICIOUS'
  ) {
    badgeStyle = 'bg-red-500/10 text-red-400 border border-red-500/30';
    IconComponent = AlertOctagon;
  } else if (
    normalized === 'HIGH' ||
    normalized === 'P2' ||
    normalized === 'EXPLOIT'
  ) {
    badgeStyle = 'bg-orange-500/10 text-orange-400 border border-orange-500/30';
    IconComponent = ShieldAlert;
  } else if (
    normalized === 'MEDIUM' ||
    normalized === 'P3' ||
    normalized === 'WARNING' ||
    normalized === 'DEGRADED' ||
    normalized === 'UNSUCCESSFUL' ||
    normalized === 'SUSPICIOUS'
  ) {
    badgeStyle = 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30';
    IconComponent = AlertTriangle;
  } else if (
    normalized === 'RESOLVED' ||
    normalized === 'NORMAL' ||
    normalized === 'HEALTHY' ||
    normalized === 'ONLINE' ||
    normalized === 'ALLOWED' ||
    normalized === 'SAFE'
  ) {
    badgeStyle = 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    IconComponent = CheckCircle2;
  } else {
    badgeStyle = 'bg-blue-500/10 text-blue-400 border border-blue-500/30';
    IconComponent = Info;
  }

  const sizeClasses =
    size === 'md'
      ? 'px-2.5 py-1 text-xs gap-1.5'
      : size === 'sm'
      ? 'px-2 py-0.5 text-[11px] gap-1.5'
      : 'px-2 py-0.5 text-[10px] gap-1';

  const iconSize = size === 'md' ? 'w-3.5 h-3.5' : 'w-3 h-3';

  return (
    <span
      className={`inline-flex items-center font-mono font-bold uppercase tracking-wider rounded ${badgeStyle} ${sizeClasses} ${className}`}
    >
      <IconComponent
        className={`${iconSize} shrink-0 ${pulse ? 'animate-pulse' : ''}`}
        aria-hidden="true"
      />
      <span>{label || defaultLabel}</span>
    </span>
  );
};
