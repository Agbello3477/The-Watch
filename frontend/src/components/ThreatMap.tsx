import React, { useState } from 'react';
import { Globe, MapPin, ShieldAlert, Crosshair, Radio, Info } from 'lucide-react';
import { ThreatMapNode } from '../types/dashboard';

interface ThreatMapProps {
  nodes: ThreatMapNode[];
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ nodes }) => {
  const [activeNode, setActiveNode] = useState<ThreatMapNode | null>(null);

  // Convert Latitude / Longitude to SVG (x, y) coordinates for Equirectangular Projection
  // SVG viewBox: 0 0 960 480 (Width: 960, Height: 480, Center: 480, 240)
  const latLngToXY = (lat: number, lng: number) => {
    const x = ((lng + 180) * (960 / 360));
    const y = (((-1 * lat) + 90) * (480 / 180));
    return { x: Math.max(20, Math.min(940, x)), y: Math.max(20, Math.min(460, y)) };
  };

  const getSeverityGlow = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'fill-red-500 text-red-500 shadow-red-500';
      case 'HIGH':
        return 'fill-orange-500 text-orange-500 shadow-orange-500';
      case 'MEDIUM':
        return 'fill-yellow-400 text-yellow-400 shadow-yellow-400';
      default:
        return 'fill-cyan-400 text-cyan-400 shadow-cyan-400';
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-sm">
      
      {/* Map Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white tracking-wide">GLOBAL THREAT INTELLIGENCE & GEOLOCATION RADAR</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time origin IP geolocation, Autonomous System (ASN) resolution, and Proxy/Tor exit node detection
          </p>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span> Critical Threat
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span> High Threat
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span> Clean Node
          </span>
        </div>
      </div>

      {/* Interactive Map Canvas */}
      <div className="relative w-full aspect-[2/1] bg-slate-950 rounded-lg border border-slate-800/80 overflow-hidden flex items-center justify-center">
        
        {/* Radar Background Grid & Lines */}
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:20px_20px] opacity-40"></div>
        <div className="absolute inset-0 border border-cyan-500/10 rounded-lg pointer-events-none"></div>

        {/* Global Continental Outlines (SVG) */}
        <svg viewBox="0 0 960 480" className="w-full h-full select-none">
          <defs>
            <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Equator & Prime Meridian Grid */}
          <line x1="0" y1="240" x2="960" y2="240" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />
          <line x1="480" y1="0" x2="480" y2="480" stroke="#1e293b" strokeWidth="1" strokeDasharray="4 4" />

          {/* Simplified World Continents Silhouettes */}
          {/* North America */}
          <path
            d="M150 90 Q 220 70, 310 90 T 360 180 T 260 220 T 180 180 Z"
            fill="#1e293b"
            opacity="0.6"
          />
          {/* South America */}
          <path
            d="M270 240 Q 340 250, 320 340 T 280 430 T 250 330 Z"
            fill="#1e293b"
            opacity="0.6"
          />
          {/* Europe */}
          <path
            d="M460 80 Q 530 80, 550 140 T 480 170 T 450 120 Z"
            fill="#1e293b"
            opacity="0.6"
          />
          {/* Africa & Nigeria Hub Highlight */}
          <path
            d="M450 170 Q 550 170, 560 260 T 520 380 T 460 300 T 430 220 Z"
            fill="#1e293b"
            opacity="0.75"
            stroke="#0284c7"
            strokeWidth="0.75"
          />
          {/* Asia */}
          <path
            d="M560 90 Q 750 80, 800 170 T 720 280 T 580 200 Z"
            fill="#1e293b"
            opacity="0.6"
          />
          {/* Australia */}
          <path
            d="M740 310 Q 840 310, 830 380 T 740 370 Z"
            fill="#1e293b"
            opacity="0.6"
          />

          {/* Nigeria Institutional Center Radar Ring */}
          {(() => {
            const pos = latLngToXY(9.0765, 7.3986); // Abuja NOUN HQ
            return (
              <g transform={`translate(${pos.x}, ${pos.y})`}>
                <circle r="18" fill="none" stroke="#38bdf8" strokeWidth="1" strokeDasharray="3 3" className="animate-spin" />
                <circle r="6" fill="#0284c7" opacity="0.8" />
                <text x="10" y="4" fill="#38bdf8" fontSize="9" fontWeight="bold" fontFamily="monospace">NOUN HQ (WAT)</text>
              </g>
            );
          })()}

          {/* Render Threat Incident Coordinates */}
          {nodes.map((node) => {
            const { x, y } = latLngToXY(node.latitude, node.longitude);
            const isCritical = node.severity === 'CRITICAL';
            const isSelected = activeNode?.id === node.id;

            return (
              <g
                key={node.id}
                transform={`translate(${x}, ${y})`}
                className="cursor-pointer transition-transform hover:scale-125"
                onClick={() => setActiveNode(node)}
              >
                {/* Pulsing Radar Ring */}
                <circle
                  r={isCritical ? 14 : 10}
                  className={`animate-ping opacity-75 ${
                    isCritical ? 'fill-red-500' : 'fill-orange-400'
                  }`}
                />
                
                {/* Core Pin Marker */}
                <circle
                  r={isSelected ? 6 : 4.5}
                  className={isCritical ? 'fill-red-500 stroke-white' : 'fill-orange-400 stroke-slate-900'}
                  strokeWidth="1.5"
                />

                {/* City Tag Label */}
                <text
                  x="8"
                  y="3"
                  fill="#f1f5f9"
                  fontSize="8"
                  fontFamily="sans-serif"
                  fontWeight="600"
                  className="pointer-events-none drop-shadow"
                >
                  {node.city || node.country}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Threat Node Forensics Modal / Overlay */}
        {activeNode && (
          <div className="absolute bottom-4 left-4 right-4 md:right-auto md:w-96 bg-slate-900/95 border border-slate-700 rounded-xl p-4 shadow-2xl backdrop-blur-md animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className={`w-4 h-4 ${activeNode.severity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'}`} />
                <span className="text-xs font-bold uppercase tracking-wider text-slate-200">
                  {activeNode.threatClassification}
                </span>
              </div>
              <button
                onClick={() => setActiveNode(null)}
                className="text-slate-400 hover:text-white text-xs font-bold px-1.5 py-0.5 rounded bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="mt-3 space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Offending IP:</span>
                <span className="font-mono font-bold text-slate-100">{activeNode.offendingIp}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Resolved Location:</span>
                <span className="text-slate-200">{activeNode.city}, {activeNode.region}, {activeNode.country}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Autonomous System (ASN):</span>
                <span className="text-cyan-400 font-mono">{activeNode.asn} ({activeNode.isp})</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Proxy / Tor Exit Node:</span>
                <span className={`font-bold ${activeNode.isProxyOrVpn ? 'text-red-400' : 'text-emerald-400'}`}>
                  {activeNode.isProxyOrVpn ? 'YES (Detected)' : 'NO (Direct IP)'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Endpoint:</span>
                <span className="font-mono text-amber-400">{activeNode.httpMethod} {activeNode.targetEndpoint}</span>
              </div>
              <div className="flex justify-between pt-1 border-t border-slate-800 text-[11px] text-slate-500">
                <span>Timestamp (WAT):</span>
                <span>{activeNode.timestampWat}</span>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
};
