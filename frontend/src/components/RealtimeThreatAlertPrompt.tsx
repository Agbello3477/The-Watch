import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert,
  Flame,
  Volume2,
  VolumeX,
  X,
  Zap,
  CheckCircle2,
  ExternalLink,
  Radio,
  Clock,
  Globe,
  Database,
  Lock,
  Crosshair,
  Ban,
  Download,
  FileText,
  FileSpreadsheet,
  BellRing,
  MapPin,
  Server,
  Activity,
} from 'lucide-react';
import { api } from '../services/api';

export interface LiveThreatAlert {
  id: string;
  systemId: string;
  incidentType: string;
  threatClassification: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  offendingIp: string;
  geoCountry?: string;
  geoRegion?: string;
  geoCity?: string;
  geoLat?: number;
  geoLng?: number;
  asn?: string;
  isp?: string;
  isProxyOrVpn?: boolean;
  targetEndpoint: string;
  httpMethod: string;
  capturedPayload: string;
  status: 'UNRESOLVED' | 'ACKNOWLEDGED' | 'RESOLVED';
  mitigationBlueprint?: string;
  remediationSummary?: string;
  timestampWat: string;
  timestampIso: string;
}

interface IpTraceResult {
  ip: string;
  tracedAtWat: string;
  isBlocked: boolean;
  profile: {
    ip: string;
    reverseDns: string;
    country: string;
    countryCode: string;
    region: string;
    city: string;
    postalCode: string;
    latitude: number;
    longitude: number;
    asn: string;
    isp: string;
    organization: string;
    isProxyOrVpn: boolean;
    isTorExitNode: boolean;
    threatRiskScore: number;
  };
  whois: {
    registry: string;
    cidr: string;
    netname: string;
    isp: string;
    organization: string;
    asn: string;
    abuseContact: string;
  };
  hops: Array<{
    hop: number;
    ip: string;
    hostname: string;
    location: string;
    asn: string;
    rttMs: number;
  }>;
  attackSummary: {
    totalIncidentsFromIp: number;
    totalAuditEventsFromIp: number;
  };
}

interface RealtimeThreatAlertPromptProps {
  onViewWarRoom?: (alert: LiveThreatAlert) => void;
  onAlertNeutralized?: (alertId: string) => void;
}

// Persistent shared Web Audio Context for maximum loudness wake-up alarm
let sharedAudioCtx: AudioContext | null = null;

function getOrInitAudioContext(): AudioContext | null {
  try {
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return null;
    if (!sharedAudioCtx || sharedAudioCtx.state === 'closed') {
      sharedAudioCtx = new AudioContextClass();
    }
    if (sharedAudioCtx.state === 'suspended') {
      sharedAudioCtx.resume().catch(() => {});
    }
    return sharedAudioCtx;
  } catch {
    return null;
  }
}

/**
 * High-Decibel Wake-Up Intrusion Klaxon Siren
 * Uses multi-oscillator sawtooth + square wave + dynamics compressor at maximum gain (0.95)
 * Designed to wake up a sleeping SOC operator immediately upon any intrusion attempt.
 */
export function playWakeUpKlaxonCycle() {
  try {
    const ctx = getOrInitAudioContext();
    if (!ctx) return;

    const now = ctx.currentTime;

    // Dynamics Compressor to maximize perceived loudness without distortion
    const compressor = ctx.createDynamicsCompressor();
    compressor.threshold.setValueAtTime(-14, now);
    compressor.knee.setValueAtTime(0, now);
    compressor.ratio.setValueAtTime(20, now);
    compressor.attack.setValueAtTime(0.001, now);
    compressor.release.setValueAtTime(0.05, now);

    const masterGain = ctx.createGain();
    masterGain.gain.setValueAtTime(0.95, now);
    compressor.connect(masterGain);
    masterGain.connect(ctx.destination);

    // Oscillator 1: Piercing Emergency Air-Raid / Intrusion Klaxon Sweep (Sawtooth)
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sawtooth';
    osc1.frequency.setValueAtTime(740, now);
    osc1.frequency.linearRampToValueAtTime(1680, now + 0.45);
    osc1.frequency.linearRampToValueAtTime(740, now + 0.75);
    osc1.frequency.linearRampToValueAtTime(1820, now + 1.15);
    osc1.frequency.linearRampToValueAtTime(880, now + 1.35);

    gain1.gain.setValueAtTime(0.85, now);
    gain1.gain.setValueAtTime(0.85, now + 1.25);
    gain1.gain.exponentialRampToValueAtTime(0.01, now + 1.38);

    osc1.connect(gain1);
    gain1.connect(compressor);

    // Oscillator 2: Rapid High-Frequency Tactical Strobe Beep (Square wave)
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'square';
    osc2.frequency.setValueAtTime(1480, now);
    osc2.frequency.setValueAtTime(988, now + 0.2);
    osc2.frequency.setValueAtTime(1760, now + 0.4);
    osc2.frequency.setValueAtTime(988, now + 0.6);
    osc2.frequency.setValueAtTime(1760, now + 0.8);
    osc2.frequency.setValueAtTime(1975, now + 1.0);

    gain2.gain.setValueAtTime(0.65, now);
    gain2.gain.setValueAtTime(0.65, now + 1.25);
    gain2.gain.exponentialRampToValueAtTime(0.01, now + 1.38);

    osc2.connect(gain2);
    gain2.connect(compressor);

    // Oscillator 3: Deep Low-Mid Horn Resonance (Triangle wave)
    const osc3 = ctx.createOscillator();
    const gain3 = ctx.createGain();
    osc3.type = 'triangle';
    osc3.frequency.setValueAtTime(440, now);
    osc3.frequency.linearRampToValueAtTime(880, now + 0.45);
    osc3.frequency.linearRampToValueAtTime(440, now + 0.75);
    osc3.frequency.linearRampToValueAtTime(932, now + 1.15);

    gain3.gain.setValueAtTime(0.75, now);
    gain3.gain.exponentialRampToValueAtTime(0.01, now + 1.38);

    osc3.connect(gain3);
    gain3.connect(compressor);

    osc1.start(now);
    osc2.start(now);
    osc3.start(now);

    osc1.stop(now + 1.4);
    osc2.stop(now + 1.4);
    osc3.stop(now + 1.4);
  } catch (err) {
    console.debug('[WakeUpSiren] Audio playback error:', err);
  }
}

/**
 * Spoken Voice Intrusion Announcement via Web Speech Synthesis
 */
function speakIntrusionVoiceAlert(alert: LiveThreatAlert) {
  try {
    if (!('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const origin = [alert.geoCity, alert.geoCountry].filter(Boolean).join(', ') || 'Unknown Location';
    const text = `Emergency Security Alert! Intrusion attempt detected on ${alert.systemId}. Attack type: ${alert.threatClassification}. Originating from ${origin}, IP address ${alert.offendingIp}. Immediate action required!`;
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.volume = 1.0;
    utterance.rate = 1.02;
    utterance.pitch = 1.05;
    window.speechSynthesis.speak(utterance);
  } catch {
    // Ignore speech synthesis errors on unsupported browsers
  }
}

function stopVoiceAlert() {
  try {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  } catch {}
}

export const RealtimeThreatAlertPrompt: React.FC<RealtimeThreatAlertPromptProps> = ({
  onViewWarRoom,
  onAlertNeutralized,
}) => {
  const [alerts, setAlerts] = useState<LiveThreatAlert[]>([]);
  const [isMuted, setIsMuted] = useState<boolean>(() => {
    return localStorage.getItem('the_watch_alert_sound_muted') === 'true';
  });
  const [isSirenRinging, setIsSirenRinging] = useState<boolean>(false);
  const [neutralizingIds, setNeutralizingIds] = useState<Set<string>>(new Set());
  const [neutralizedSuccessIds, setNeutralizedSuccessIds] = useState<Set<string>>(new Set());
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [isConnected, setIsConnected] = useState<boolean>(false);

  // IP Trace state per alert ID
  const [tracingAlertId, setTracingAlertId] = useState<string | null>(null);
  const [traceResults, setTraceResults] = useState<Record<string, IpTraceResult>>({});

  const seenIdsRef = useRef<Set<string>>(new Set());
  const lastTimestampRef = useRef<string>(new Date(Date.now() - 30000).toISOString());
  const sirenLoopRef = useRef<any>(null);
  const voiceLoopRef = useRef<any>(null);

  // Unlock Web Audio Context on first user interaction anywhere on the page
  useEffect(() => {
    const unlockAudio = () => {
      getOrInitAudioContext();
    };
    window.addEventListener('click', unlockAudio, { once: true, passive: true });
    window.addEventListener('keydown', unlockAudio, { once: true, passive: true });
    return () => {
      window.removeEventListener('click', unlockAudio);
      window.removeEventListener('keydown', unlockAudio);
    };
  }, []);

  // Manage Continuous Wake-Up Siren Loop whenever there is an active un-silenced alert
  useEffect(() => {
    if (sirenLoopRef.current) {
      clearInterval(sirenLoopRef.current);
      sirenLoopRef.current = null;
    }
    if (voiceLoopRef.current) {
      clearInterval(voiceLoopRef.current);
      voiceLoopRef.current = null;
    }

    if (isSirenRinging && !isMuted && alerts.length > 0) {
      // Play immediately
      playWakeUpKlaxonCycle();
      speakIntrusionVoiceAlert(alerts[0]);

      // Repeat piercing klaxon every 1.45 seconds continuously so the user wakes up!
      sirenLoopRef.current = setInterval(() => {
        playWakeUpKlaxonCycle();
      }, 1450);

      // Repeat spoken voice warning every 14 seconds
      voiceLoopRef.current = setInterval(() => {
        if (alerts[0]) {
          speakIntrusionVoiceAlert(alerts[0]);
        }
      }, 14000);
    } else {
      stopVoiceAlert();
    }

    return () => {
      if (sirenLoopRef.current) clearInterval(sirenLoopRef.current);
      if (voiceLoopRef.current) clearInterval(voiceLoopRef.current);
    };
  }, [isSirenRinging, isMuted, alerts]);

  const handleSilenceSiren = () => {
    setIsSirenRinging(false);
    stopVoiceAlert();
  };

  const handleToggleMute = () => {
    setIsMuted((prev) => {
      const next = !prev;
      localStorage.setItem('the_watch_alert_sound_muted', String(next));
      if (next) {
        stopVoiceAlert();
      }
      return next;
    });
  };

  const handleTestWakeUpSiren = () => {
    setIsMuted(false);
    localStorage.setItem('the_watch_alert_sound_muted', 'false');
    playWakeUpKlaxonCycle();

    const demoAlert: LiveThreatAlert = {
      id: `inc-wakeup-test-${Date.now()}`,
      systemId: 'NOUN-HRMS',
      incidentType: 'SQL_INJECTION',
      threatClassification: 'SQLi UNION-Based Payroll & Staff Dossier Exfiltration Attempt',
      severity: 'CRITICAL',
      offendingIp: '194.26.29.112',
      geoCountry: 'Russia',
      geoRegion: 'Moscow Oblast',
      geoCity: 'Moscow',
      geoLat: 55.7558,
      geoLng: 37.6173,
      asn: 'AS48693',
      isp: 'FastVDS Bulletproof Hosting Network',
      isProxyOrVpn: true,
      targetEndpoint: '/api/v1/payroll/export',
      httpMethod: 'POST',
      capturedPayload: `dept_id=1' UNION ALL SELECT staff_id, full_name, bvn, bank_account, net_pay FROM noun_staff_payroll WHERE '1'='1' --`,
      status: 'UNRESOLVED',
      mitigationBlueprint: 'iptables -I INPUT -s 194.26.29.112 -j DROP',
      remediationSummary: 'Critical SQL Injection attempt intercepted targeting NOUN HRMS payroll export endpoint.',
      timestampWat: new Date().toLocaleString('en-GB', {
        timeZone: 'Africa/Lagos',
        dateStyle: 'full',
        timeStyle: 'long',
      }),
      timestampIso: new Date().toISOString(),
    };

    setAlerts((prev) => [demoAlert, ...prev.slice(0, 2)]);
    setIsSirenRinging(true);
  };

  const pushAlert = useCallback((alert: LiveThreatAlert) => {
    if (seenIdsRef.current.has(alert.id)) return;
    seenIdsRef.current.add(alert.id);

    setAlerts((prev) => {
      const updated = [alert, ...prev.filter((a) => a.id !== alert.id)];
      return updated.slice(0, 3);
    });
    setIsSirenRinging(true);
  }, []);

  // SSE Stream with Fallback Fast Polling
  useEffect(() => {
    const rawApiUrl = (import.meta as any).env?.VITE_API_URL || '';
    const API_BASE = rawApiUrl ? `${rawApiUrl.replace(/\/$/, '')}/api/v1` : '/api/v1';

    let eventSource: EventSource | null = null;
    let pollInterval: any = null;

    const connectSSE = () => {
      try {
        eventSource = new EventSource(`${API_BASE}/threats/stream`);

        eventSource.onopen = () => {
          setIsConnected(true);
        };

        eventSource.addEventListener('threat-alert', (event: MessageEvent) => {
          try {
            const data: LiveThreatAlert = JSON.parse(event.data);
            if (data && data.status !== 'RESOLVED') {
              pushAlert(data);
              lastTimestampRef.current = data.timestampIso || new Date().toISOString();
            }
          } catch (e) {
            console.error('[SSE] Failed to parse threat-alert data:', e);
          }
        });

        eventSource.addEventListener('history', (event: MessageEvent) => {
          try {
            const history: LiveThreatAlert[] = JSON.parse(event.data);
            if (Array.isArray(history)) {
              history.forEach((h) => {
                if (h.status !== 'RESOLVED') {
                  seenIdsRef.current.add(h.id);
                }
              });
            }
          } catch (e) {
            console.error('[SSE] Failed to parse history:', e);
          }
        });

        eventSource.onerror = () => {
          setIsConnected(false);
        };
      } catch (err) {
        console.warn('[SSE] EventSource init failed, relying on HTTP polling:', err);
      }
    };

    const pollLiveAlerts = async () => {
      try {
        const res = await fetch(
          `${API_BASE}/threats/live-alerts?since=${encodeURIComponent(lastTimestampRef.current)}`
        );
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.alerts)) {
            data.alerts.forEach((alert: LiveThreatAlert) => {
              if (alert.status !== 'RESOLVED') {
                pushAlert(alert);
                lastTimestampRef.current = alert.timestampIso || new Date().toISOString();
              }
            });
          }
        }
      } catch {
        // Silent catch on offline/dev network switch
      }
    };

    connectSSE();
    pollInterval = setInterval(pollLiveAlerts, 3500);

    return () => {
      if (eventSource) eventSource.close();
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [pushAlert]);

  const handleDismiss = (id: string) => {
    setAlerts((prev) => {
      const remaining = prev.filter((a) => a.id !== id);
      if (remaining.length === 0) {
        setIsSirenRinging(false);
        stopVoiceAlert();
      }
      return remaining;
    });
  };

  const handleTraceIp = async (alert: LiveThreatAlert) => {
    setTracingAlertId(alert.id);
    try {
      const res = await api.traceIp(alert.offendingIp);
      if (res && res.ip) {
        setTraceResults((prev) => ({ ...prev, [alert.id]: res }));
        if (res.isBlocked) {
          setBlockedIps((prev) => new Set(prev).add(alert.offendingIp));
        }
      }
    } catch (err) {
      console.error('[IntrusionAlert] Failed to trace IP:', err);
    } finally {
      setTracingAlertId(null);
    }
  };

  const handleBlockAndNeutralize = async (alert: LiveThreatAlert) => {
    setNeutralizingIds((prev) => new Set(prev).add(alert.id));
    setIsSirenRinging(false);
    stopVoiceAlert();

    try {
      // 1. Block IP on active SOC Firewall for 720 hours (30 days)
      await api.blockIp({
        ip: alert.offendingIp,
        reason: `Intrusion Blocked: ${alert.threatClassification} on ${alert.systemId} (${alert.targetEndpoint})`,
        threatClassification: alert.threatClassification,
        systemId: alert.systemId,
        durationHours: 720,
      });

      // 2. Resolve incident if it's a real DB incident
      if (!alert.id.startsWith('inc-wakeup-test-')) {
        await api.updateIncidentStatus(alert.id, 'RESOLVED');
      }

      setBlockedIps((prev) => new Set(prev).add(alert.offendingIp));
      setNeutralizedSuccessIds((prev) => new Set(prev).add(alert.id));
      onAlertNeutralized?.(alert.id);
    } catch (err) {
      console.error('[RealtimeThreatPrompt] Threat neutralization failed:', err);
    } finally {
      setNeutralizingIds((prev) => {
        const next = new Set(prev);
        next.delete(alert.id);
        return next;
      });
    }
  };

  const handleDownloadIncidentPdf = (alert: LiveThreatAlert) => {
    const incidentIdParam = alert.id.startsWith('inc-wakeup-test-') ? undefined : alert.id;
    const url = api.getPdfReportUrl(alert.systemId, incidentIdParam);
    window.open(url, '_blank');
  };

  const handleDownloadAuditCsv = (alert: LiveThreatAlert) => {
    const url = api.getCsvReportUrl(alert.systemId);
    window.open(url, '_blank');
  };

  return (
    <>
      {/* Persistent Bottom-Right Wake-Up Siren Status & Test Bar */}
      <div className="fixed bottom-4 right-4 z-40 flex items-center gap-2 bg-slate-950/95 border border-rose-500/50 rounded-full px-3.5 py-1.5 shadow-xl shadow-rose-950/50 backdrop-blur-md">
        <span className="relative flex h-2.5 w-2.5">
          <span
            className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
              isConnected ? 'bg-emerald-400' : 'bg-amber-400'
            }`}
          />
          <span
            className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
              isConnected ? 'bg-emerald-500' : 'bg-amber-500'
            }`}
          />
        </span>
        <span className="text-[11px] font-mono font-bold text-slate-200 hidden sm:inline">
          24/7 INTRUSION GUARD
        </span>
        <button
          onClick={handleToggleMute}
          className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold flex items-center gap-1 transition cursor-pointer ${
            isMuted
              ? 'bg-rose-950 text-rose-300 border border-rose-700'
              : 'bg-emerald-950 text-emerald-300 border border-emerald-700'
          }`}
          title={isMuted ? 'Click to enable loud wake-up siren' : 'Loud wake-up siren is ARMED'}
        >
          {isMuted ? <VolumeX className="w-3 h-3" /> : <Volume2 className="w-3 h-3" />}
          <span>{isMuted ? 'SIREN MUTED' : 'SIREN ARMED'}</span>
        </button>
        <button
          onClick={handleTestWakeUpSiren}
          className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white shadow-md shadow-rose-600/30 flex items-center gap-1 transition cursor-pointer"
          title="Trigger a test intrusion alert with the loud wake-up klaxon siren"
        >
          <BellRing className="w-3 h-3 animate-bounce" />
          <span>TEST WAKE-UP ALARM</span>
        </button>
      </div>

      {/* Emergency Intrusion & Hack Attempt Command Modal */}
      {alerts.length > 0 && (
        <div
          aria-live="assertive"
          className={`fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 overflow-y-auto backdrop-blur-md transition-colors duration-300 ${
            isSirenRinging && !isMuted
              ? 'bg-rose-950/75 animate-pulse'
              : 'bg-slate-950/85'
          }`}
        >
          <div className="w-full max-w-3xl space-y-4 my-auto max-h-[94vh] overflow-y-auto pr-1">
            {alerts.map((alert) => {
              const isCritical = alert.severity === 'CRITICAL';
              const isNeutralizing = neutralizingIds.has(alert.id);
              const isNeutralized = neutralizedSuccessIds.has(alert.id);
              const isIpBlocked = blockedIps.has(alert.offendingIp) || isNeutralized;
              const traceData = traceResults[alert.id];
              const isTracing = tracingAlertId === alert.id;

              const fullOriginLocation = [
                alert.geoCity || 'Unknown City',
                alert.geoRegion,
                alert.geoCountry || 'Unknown Country',
              ]
                .filter(Boolean)
                .join(', ');

              return (
                <div
                  key={alert.id}
                  className={`rounded-2xl border-2 shadow-2xl overflow-hidden transition-all ${
                    isNeutralized
                      ? 'bg-slate-950 border-emerald-500 shadow-emerald-950/80'
                      : isCritical
                      ? 'bg-slate-950 border-rose-500 shadow-rose-950/90'
                      : 'bg-slate-950 border-amber-500 shadow-amber-950/80'
                  }`}
                >
                  {/* Top Red-Alert Siren Banner */}
                  <div
                    className={`px-4 py-3 flex flex-wrap items-center justify-between gap-2 border-b ${
                      isNeutralized
                        ? 'bg-emerald-950/90 border-emerald-500/50 text-emerald-200'
                        : isCritical
                        ? 'bg-gradient-to-r from-rose-950 via-red-900 to-rose-950 border-rose-500/60 text-white'
                        : 'bg-amber-950/90 border-amber-500/50 text-amber-100'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-xl bg-rose-500/20 border border-rose-400/50">
                        <ShieldAlert className="w-6 h-6 text-rose-300 animate-bounce" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs sm:text-sm font-black tracking-wider font-mono uppercase">
                            {isNeutralized
                              ? '✓ INTRUSION BLOCKED & IP QUARANTINED'
                              : '🚨 EMERGENCY INTRUSION / HACK ATTEMPT DETECTED!'}
                          </span>
                          <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-black/50 border border-white/20">
                            TARGET: {alert.systemId}
                          </span>
                          <span
                            className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                              isCritical
                                ? 'bg-rose-500 text-slate-950'
                                : 'bg-amber-400 text-slate-950'
                            }`}
                          >
                            {alert.severity} SEVERITY
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-rose-200/90 mt-0.5">
                          Active 24/7 Threat Sentinel — National Open University of Nigeria (NOUN)
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {isSirenRinging && !isMuted && (
                        <button
                          onClick={handleSilenceSiren}
                          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-400 hover:bg-amber-300 text-slate-950 font-mono font-extrabold text-xs shadow-lg cursor-pointer animate-bounce"
                        >
                          <VolumeX className="w-4 h-4" />
                          <span>SILENCE SIREN</span>
                        </button>
                      )}
                      <button
                        onClick={handleToggleMute}
                        title={isMuted ? 'Unmute Siren' : 'Mute Siren'}
                        className="p-1.5 rounded-lg bg-black/40 hover:bg-black/70 text-slate-200 border border-white/15 cursor-pointer"
                      >
                        {isMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
                      </button>
                      <button
                        onClick={() => handleDismiss(alert.id)}
                        title="Close Alert Window"
                        className="p-1.5 rounded-lg bg-black/40 hover:bg-black/70 text-slate-200 border border-white/15 cursor-pointer"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Main Intrusion Forensic Body */}
                  <div className="p-4 sm:p-5 space-y-4">
                    {/* 1. Attack Type & Classification */}
                    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <div className="text-[10px] font-mono uppercase text-rose-400 font-bold tracking-wider">
                          TYPE OF ATTACK / INTRUSION VECTOR
                        </div>
                        <div className="text-base sm:text-lg font-extrabold text-white flex items-center gap-2 mt-0.5">
                          <Flame className="w-5 h-5 text-rose-500 shrink-0" />
                          <span>{alert.threatClassification}</span>
                        </div>
                        <div className="text-xs font-mono text-cyan-400 mt-0.5">
                          Classification Code: <span className="font-bold">{alert.incidentType}</span> • Target Endpoint:{' '}
                          <span className="text-amber-300 font-bold">
                            {alert.httpMethod} {alert.targetEndpoint}
                          </span>
                        </div>
                      </div>

                      <div className="sm:text-right font-mono">
                        <div className="text-[10px] uppercase text-slate-400">FIREWALL STATUS</div>
                        {isIpBlocked ? (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-700 text-xs font-bold mt-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> IP BLOCKED (403 DROP)
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-950 text-rose-300 border border-rose-700 text-xs font-bold mt-1 animate-pulse">
                            <ShieldAlert className="w-3.5 h-3.5" /> ACTIVE INTRUSION ATTEMPT
                          </span>
                        )}
                      </div>
                    </div>

                    {/* 2. Key Forensics Grid: IP Address, Origin Location, Precise Date & Time, ISP/ASN */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                      {/* Offending IP Address */}
                      <div className="bg-slate-900/80 border border-rose-500/40 rounded-xl p-3">
                        <div className="flex items-center justify-between text-[10px] text-rose-400 font-bold uppercase">
                          <span className="flex items-center gap-1">
                            <Lock className="w-3.5 h-3.5" /> ATTACKER IP ADDRESS
                          </span>
                          {alert.isProxyOrVpn && (
                            <span className="px-1.5 py-0.2 bg-rose-950 text-rose-300 border border-rose-700 rounded text-[9px]">
                              TOR / VPN PROXY
                            </span>
                          )}
                        </div>
                        <div className="text-lg font-black text-amber-300 tracking-wide mt-1">
                          {alert.offendingIp}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                          ISP/ASN: {alert.asn || 'AS48693'} • {alert.isp || 'External Network'}
                        </div>
                      </div>

                      {/* Where the Attack is Originating */}
                      <div className="bg-slate-900/80 border border-cyan-500/40 rounded-xl p-3">
                        <div className="text-[10px] text-cyan-400 font-bold uppercase flex items-center gap-1">
                          <MapPin className="w-3.5 h-3.5" /> ATTACK ORIGIN LOCATION
                        </div>
                        <div className="text-sm sm:text-base font-bold text-white mt-1 truncate">
                          {fullOriginLocation}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          Coordinates: {alert.geoLat ?? 9.0765}° N, {alert.geoLng ?? 7.3986}° E
                        </div>
                      </div>

                      {/* Precise Date & Time of Attack (WAT) */}
                      <div className="bg-slate-900/80 border border-emerald-500/40 rounded-xl p-3">
                        <div className="text-[10px] text-emerald-400 font-bold uppercase flex items-center gap-1">
                          <Clock className="w-3.5 h-3.5" /> PRECISE DATE & TIME OF ATTACK (WAT)
                        </div>
                        <div className="text-xs sm:text-sm font-bold text-emerald-200 mt-1">
                          {alert.timestampWat}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-0.5">
                          ISO Timestamp: {alert.timestampIso}
                        </div>
                      </div>

                      {/* Target System & Vector */}
                      <div className="bg-slate-900/80 border border-purple-500/40 rounded-xl p-3">
                        <div className="text-[10px] text-purple-400 font-bold uppercase flex items-center gap-1">
                          <Database className="w-3.5 h-3.5" /> TARGETED SYSTEM & ENDPOINT
                        </div>
                        <div className="text-xs sm:text-sm font-bold text-purple-200 mt-1 truncate">
                          {alert.systemId} → {alert.httpMethod} {alert.targetEndpoint}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-0.5 truncate">
                          Incident ID: {alert.id}
                        </div>
                      </div>
                    </div>

                    {/* 3. The Attempt: Captured Malicious Payload / Signature */}
                    <div className="bg-black/80 border border-rose-900/80 rounded-xl p-3.5 font-mono">
                      <div className="flex items-center justify-between text-[10px] text-rose-400 font-bold uppercase mb-1.5">
                        <span>THE ATTEMPT (CAPTURED HACKER PAYLOAD / EXPLOIT SIGNATURE)</span>
                        <span className="text-slate-500">RAW PACKET INSPECTION</span>
                      </div>
                      <pre className="text-xs text-rose-200 whitespace-pre-wrap break-all bg-rose-950/30 p-2.5 rounded-lg border border-rose-900/50 max-h-28 overflow-y-auto">
                        {alert.capturedPayload || `${alert.httpMethod} ${alert.targetEndpoint}`}
                      </pre>
                    </div>

                    {/* 4. Live IP Trace Drawer (Expanded when user clicks "Trace IP") */}
                    {traceData && (
                      <div className="bg-slate-900/95 border border-cyan-500/60 rounded-xl p-4 space-y-3 font-mono animate-fadeIn">
                        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                          <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs">
                            <Crosshair className="w-4 h-4 animate-spin" />
                            <span>DEEP IP FORENSIC TRACE & MULTI-HOP ROUTE: {traceData.ip}</span>
                          </div>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                            Risk Score: {traceData.profile.threatRiskScore}/100
                          </span>
                        </div>

                        {/* Whois & Registry Metadata */}
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                          <div>
                            <span className="text-slate-500 block text-[10px]">REVERSE DNS</span>
                            <span className="text-slate-200 font-bold break-all">{traceData.profile.reverseDns}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">CIDR SUBNET & REGISTRY</span>
                            <span className="text-cyan-300 font-bold">{traceData.whois.cidr}</span>
                            <span className="text-slate-400 block text-[10px] truncate">{traceData.whois.registry}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block text-[10px]">ISP / ABUSE CONTACT</span>
                            <span className="text-amber-300 font-bold">{traceData.whois.abuseContact}</span>
                            <span className="text-slate-400 block text-[10px]">
                              Prior Attacks: {traceData.attackSummary.totalIncidentsFromIp}
                            </span>
                          </div>
                        </div>

                        {/* Hop-by-Hop Network Path */}
                        <div className="space-y-1">
                          <div className="text-[10px] text-slate-400 uppercase font-bold">
                            Hop-by-Hop Packet Path (NOUN SOC Gateway → Attacker Host):
                          </div>
                          <div className="overflow-x-auto">
                            <table className="w-full text-left text-[11px]">
                              <thead className="text-slate-400 border-b border-slate-800">
                                <tr>
                                  <th className="py-1 pr-2">Hop</th>
                                  <th className="py-1 pr-2">Router IP</th>
                                  <th className="py-1 pr-2">Hostname</th>
                                  <th className="py-1 pr-2">Geographical Node</th>
                                  <th className="py-1 text-right">RTT</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-800/60">
                                {traceData.hops.map((h) => (
                                  <tr key={h.hop} className={h.hop === traceData.hops.length ? 'text-rose-300 font-bold' : 'text-slate-300'}>
                                    <td className="py-1 pr-2">#{h.hop}</td>
                                    <td className="py-1 pr-2 text-amber-300">{h.ip}</td>
                                    <td className="py-1 pr-2 truncate max-w-[160px]">{h.hostname}</td>
                                    <td className="py-1 pr-2">{h.location}</td>
                                    <td className="py-1 text-right text-cyan-400">{h.rttMs} ms</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 5. Tactical Command Buttons: TRACE IP, BLOCK IP, DOWNLOAD PDF/CSV REPORT */}
                    <div className="pt-1 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                      {/* Trace IP Button */}
                      <button
                        onClick={() => handleTraceIp(alert)}
                        disabled={isTracing}
                        className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-600/25 transition cursor-pointer"
                      >
                        <Crosshair className={`w-4 h-4 ${isTracing ? 'animate-spin' : ''}`} />
                        <span>{isTracing ? 'TRACING IP...' : 'TRACE IP ORIGIN'}</span>
                      </button>

                      {/* Block IP & Neutralize Button */}
                      <button
                        onClick={() => handleBlockAndNeutralize(alert)}
                        disabled={isNeutralizing || isIpBlocked}
                        className={`flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono font-bold transition shadow-lg cursor-pointer ${
                          isIpBlocked
                            ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700 cursor-default'
                            : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
                        }`}
                      >
                        {isIpBlocked ? (
                          <>
                            <CheckCircle2 className="w-4 h-4" />
                            <span>IP BLOCKED & QUARANTINED</span>
                          </>
                        ) : (
                          <>
                            <Ban className={`w-4 h-4 ${isNeutralizing ? 'animate-spin' : ''}`} />
                            <span>{isNeutralizing ? 'BLOCKING IP...' : 'BLOCK IP & NEUTRALIZE'}</span>
                          </>
                        )}
                      </button>

                      {/* Download Forensic PDF Report */}
                      <button
                        onClick={() => handleDownloadIncidentPdf(alert)}
                        className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono font-bold bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/25 transition cursor-pointer"
                      >
                        <FileText className="w-4 h-4" />
                        <span>DOWNLOAD REPORT (PDF)</span>
                      </button>

                      {/* Download Audit CSV */}
                      <button
                        onClick={() => handleDownloadAuditCsv(alert)}
                        className="flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-xl text-xs font-mono font-bold bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700 transition cursor-pointer"
                      >
                        <Download className="w-4 h-4" />
                        <span>EXPORT AUDIT (CSV)</span>
                      </button>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="px-4 py-2 bg-black/60 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-400 font-mono">
                    <span className="flex items-center gap-1.5 text-emerald-400">
                      <Radio className="w-3 h-3 animate-pulse" />
                      <span>The Watch Active Intrusion Defense Shield • Powered by MaSha Tech Innovations</span>
                    </span>
                    {onViewWarRoom && (
                      <button
                        onClick={() => {
                          handleSilenceSiren();
                          onViewWarRoom(alert);
                          handleDismiss(alert.id);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1 cursor-pointer"
                      >
                        <span>Open Full SOC War Room</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </>
  );
};
