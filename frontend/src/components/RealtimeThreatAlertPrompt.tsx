import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert,
  Flame,
  Volume2,
  VolumeX,
  X,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Radio,
  Clock,
  Globe,
  Database,
  Lock,
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
  geoCity?: string;
  asn?: string;
  targetEndpoint: string;
  httpMethod: string;
  capturedPayload: string;
  status: 'UNRESOLVED' | 'ACKNOWLEDGED' | 'RESOLVED';
  mitigationBlueprint?: string;
  timestampWat: string;
  timestampIso: string;
}

interface RealtimeThreatAlertPromptProps {
  onViewWarRoom?: (alert: LiveThreatAlert) => void;
  onAlertNeutralized?: (alertId: string) => void;
}

// Tactical Web Audio chime synthesizer - Zero external mp3/wav files required
function playTacticalChime(severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') {
  try {
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();

    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }

    const now = ctx.currentTime;
    const masterGain = ctx.createGain();
    masterGain.gain.setValueAtTime(0.2, now);
    masterGain.connect(ctx.destination);

    if (severity === 'CRITICAL') {
      // 3-tone urgent klaxon
      const osc1 = ctx.createOscillator();
      const osc2 = ctx.createOscillator();
      osc1.type = 'sawtooth';
      osc2.type = 'sine';

      osc1.frequency.setValueAtTime(880, now);
      osc1.frequency.setValueAtTime(1174.66, now + 0.12);
      osc1.frequency.setValueAtTime(1760, now + 0.24);

      osc2.frequency.setValueAtTime(440, now);
      osc2.frequency.setValueAtTime(587.33, now + 0.12);
      osc2.frequency.setValueAtTime(880, now + 0.24);

      const gain = ctx.createGain();
      gain.gain.setValueAtTime(0.3, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.55);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(masterGain);

      osc1.start(now);
      osc2.start(now);
      osc1.stop(now + 0.56);
      osc2.stop(now + 0.56);
    } else {
      // High/Medium tactical sonar ping
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(987.77, now); // B5
      osc.frequency.exponentialRampToValueAtTime(1318.51, now + 0.18); // E6

      const gain = ctx.createGain();
      gain.gain.setValueAtTime(0.25, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);

      osc.connect(gain);
      gain.connect(masterGain);

      osc.start(now);
      osc.stop(now + 0.42);
    }
  } catch (err) {
    // Non-blocking if audio blocked by autoplay policies
    console.debug('[RealtimeThreatPrompt] Audio playback deferred:', err);
  }
}

export const RealtimeThreatAlertPrompt: React.FC<RealtimeThreatAlertPromptProps> = ({
  onViewWarRoom,
  onAlertNeutralized,
}) => {
  const [alerts, setAlerts] = useState<LiveThreatAlert[]>([]);
  const [isMuted, setIsMuted] = useState<boolean>(() => {
    return localStorage.getItem('the_watch_alert_sound_muted') === 'true';
  });
  const [neutralizingIds, setNeutralizingIds] = useState<Set<string>>(new Set());
  const [neutralizedSuccessIds, setNeutralizedSuccessIds] = useState<Set<string>>(new Set());
  const [isConnected, setIsConnected] = useState<boolean>(false);

  const seenIdsRef = useRef<Set<string>>(new Set());
  const lastTimestampRef = useRef<string>(new Date(Date.now() - 30000).toISOString());

  const handleToggleMute = () => {
    setIsMuted((prev) => {
      const next = !prev;
      localStorage.setItem('the_watch_alert_sound_muted', String(next));
      return next;
    });
  };

  const pushAlert = useCallback(
    (alert: LiveThreatAlert) => {
      if (seenIdsRef.current.has(alert.id)) return;
      seenIdsRef.current.add(alert.id);

      // Play audio chime if unmuted
      if (!isMuted) {
        playTacticalChime(alert.severity);
      }

      setAlerts((prev) => {
        // Keep up to 3 active alert cards simultaneously
        const updated = [alert, ...prev.filter((a) => a.id !== alert.id)];
        return updated.slice(0, 3);
      });
    },
    [isMuted]
  );

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
          // If SSE encounters an error, it will auto-retry. Fallback poll handles traffic.
        };
      } catch (err) {
        console.warn('[SSE] EventSource init failed, relying on HTTP polling:', err);
      }
    };

    const pollLiveAlerts = async () => {
      try {
        const res = await fetch(`${API_BASE}/threats/live-alerts?since=${encodeURIComponent(lastTimestampRef.current)}`);
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
      } catch (err) {
        // Silent catch on offline/dev network switch
      }
    };

    connectSSE();
    pollInterval = setInterval(pollLiveAlerts, 4000);

    return () => {
      if (eventSource) {
        eventSource.close();
      }
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pushAlert]);

  const handleDismiss = (id: string) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  };

  const handleNeutralize = async (alert: LiveThreatAlert) => {
    setNeutralizingIds((prev) => new Set(prev).add(alert.id));
    try {
      // 1. Resolve incident via the hardened status endpoint (which quarantines IP & applies mitigation)
      await api.updateIncidentStatus(alert.id, 'RESOLVED');

      // 2. Mark state as neutralized
      setNeutralizedSuccessIds((prev) => new Set(prev).add(alert.id));
      onAlertNeutralized?.(alert.id);

      // 3. Remove prompt smoothly after 1.5s
      setTimeout(() => {
        handleDismiss(alert.id);
        setNeutralizedSuccessIds((prev) => {
          const next = new Set(prev);
          next.delete(alert.id);
          return next;
        });
      }, 1600);
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

  if (alerts.length === 0) {
    return null;
  }

  return (
    <div
      aria-live="assertive"
      className="fixed top-20 right-3 sm:right-6 z-50 flex flex-col gap-3 max-w-sm sm:max-w-md w-full pointer-events-none"
    >
      {alerts.map((alert) => {
        const isCritical = alert.severity === 'CRITICAL';
        const isNeutralizing = neutralizingIds.has(alert.id);
        const isNeutralized = neutralizedSuccessIds.has(alert.id);

        return (
          <div
            key={alert.id}
            className={`pointer-events-auto transform transition-all duration-300 ease-out shadow-2xl rounded-xl border backdrop-blur-md overflow-hidden ${
              isNeutralized
                ? 'bg-emerald-950/95 border-emerald-500/80 text-emerald-100 scale-95 opacity-90'
                : isCritical
                ? 'bg-slate-950/95 border-rose-500/80 text-slate-100 shadow-rose-950/60 animate-bounce-subtle'
                : 'bg-slate-950/95 border-amber-500/80 text-slate-100 shadow-amber-950/50'
            }`}
          >
            {/* Top Tactical Status Bar */}
            <div
              className={`px-3.5 py-1.5 flex items-center justify-between text-[11px] font-mono tracking-wider font-bold border-b ${
                isNeutralized
                  ? 'bg-emerald-900/60 border-emerald-500/40 text-emerald-300'
                  : isCritical
                  ? 'bg-rose-900/60 border-rose-500/40 text-rose-300'
                  : 'bg-amber-900/60 border-amber-500/40 text-amber-300'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="relative flex h-2.5 w-2.5">
                  <span
                    className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                      isNeutralized ? 'bg-emerald-400' : isCritical ? 'bg-rose-400' : 'bg-amber-400'
                    }`}
                  />
                  <span
                    className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                      isNeutralized ? 'bg-emerald-500' : isCritical ? 'bg-rose-500' : 'bg-amber-500'
                    }`}
                  />
                </span>
                <span>
                  {isNeutralized
                    ? 'THREAT NEUTRALIZED'
                    : isCritical
                    ? 'REAL-TIME P1 CRITICAL THREAT'
                    : 'REAL-TIME HIGH THREAT'}
                </span>
                <span className="text-slate-400 font-normal">[{alert.systemId}]</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleToggleMute}
                  title={isMuted ? 'Unmute tactical alert siren' : 'Mute tactical alert siren'}
                  className="text-slate-400 hover:text-slate-100 transition p-0.5 rounded"
                >
                  {isMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => handleDismiss(alert.id)}
                  title="Dismiss alert banner"
                  className="text-slate-400 hover:text-slate-100 transition p-0.5 rounded"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Main Prompt Body */}
            <div className="p-3.5 space-y-2.5">
              {isNeutralized ? (
                <div className="py-2 flex items-center gap-3">
                  <CheckCircle2 className="w-7 h-7 text-emerald-400 flex-shrink-0 animate-pulse" />
                  <div>
                    <div className="text-sm font-bold text-emerald-300">Active Threat Successfully Neutralized</div>
                    <div className="text-xs text-emerald-200/80 font-mono mt-0.5">
                      IP {alert.offendingIp} quarantined on Ingest Edge Firewall (403 Drop). Incident resolved.
                    </div>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-sm font-bold text-white flex items-center gap-1.5">
                        <Flame className={`w-4 h-4 ${isCritical ? 'text-rose-400 animate-pulse' : 'text-amber-400'}`} />
                        <span>{alert.threatClassification}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5 line-clamp-1">
                        Endpoint: <span className="font-mono text-cyan-400">{alert.httpMethod} {alert.targetEndpoint}</span>
                      </div>
                    </div>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${
                        isCritical
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </div>

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-900/80 p-2 rounded-lg border border-slate-800">
                    <div className="flex items-center gap-1.5 text-slate-300 truncate">
                      <Lock className="w-3 h-3 text-rose-400 flex-shrink-0" />
                      <span className="text-slate-400">Attacker:</span>
                      <span className="text-amber-300 font-bold truncate">{alert.offendingIp}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-300 truncate">
                      <Globe className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                      <span className="text-slate-400">Geo:</span>
                      <span className="truncate">{alert.geoCity || alert.geoCountry || 'Abuja, NG'}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-300 truncate">
                      <Clock className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                      <span className="text-slate-400">WAT:</span>
                      <span className="truncate">{alert.timestampWat.split(',')[1] || alert.timestampWat}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-300 truncate">
                      <Database className="w-3 h-3 text-purple-400 flex-shrink-0" />
                      <span className="text-slate-400">Vector:</span>
                      <span className="truncate">{alert.incidentType}</span>
                    </div>
                  </div>

                  {/* Captured snippet if available */}
                  {alert.capturedPayload && (
                    <div className="bg-black/60 px-2 py-1.5 rounded border border-slate-800/80 text-[10.5px] font-mono text-slate-300 line-clamp-2 break-all">
                      <span className="text-rose-400 font-semibold select-none">SIG: </span>
                      {alert.capturedPayload}
                    </div>
                  )}

                  {/* Tactical Action Buttons */}
                  <div className="pt-1 flex items-center justify-between gap-2">
                    <button
                      onClick={() => handleNeutralize(alert)}
                      disabled={isNeutralizing}
                      className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold font-mono transition shadow-lg ${
                        isCritical
                          ? 'bg-rose-500 hover:bg-rose-400 text-slate-950 shadow-rose-500/20 active:scale-95'
                          : 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-amber-500/20 active:scale-95'
                      } ${isNeutralizing ? 'opacity-70 cursor-wait' : ''}`}
                    >
                      <Zap className={`w-3.5 h-3.5 ${isNeutralizing ? 'animate-spin' : ''}`} />
                      <span>{isNeutralizing ? 'NEUTRALIZING...' : '1-CLICK NEUTRALIZE'}</span>
                    </button>

                    {onViewWarRoom && (
                      <button
                        onClick={() => {
                          onViewWarRoom(alert);
                          handleDismiss(alert.id);
                        }}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-mono font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                      >
                        <span>War Room</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Sub-footer watermark */}
            <div className="px-3.5 py-1 bg-black/40 border-t border-slate-800/60 flex items-center justify-between text-[9.5px] text-slate-500 font-mono">
              <span className="flex items-center gap-1 text-emerald-400">
                <Radio className="w-2.5 h-2.5 animate-pulse" />
                <span>The Watch Live Telemetry Shield</span>
              </span>
              <span>MaSha Tech Innovations</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};
