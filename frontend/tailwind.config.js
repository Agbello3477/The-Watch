/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        // SOC Neutral & Typographic Token Mapping (80% Structural + 15% Typographic)
        slate: {
          50: '#F8FAFC',
          100: '#F8FAFC', // Primary Text / Metrics / Headings
          200: '#E2E8F0', // Primary Text (Soft Off-White)
          300: '#CBD5E1',
          400: '#94A3B8', // Secondary / Column Labels / Descriptions
          500: '#64748B', // Muted / Metadata / Timestamps / Hashes
          600: '#4B5563', // Focus / Active Stroke
          700: '#2D3748', // Structural Borders & Separators
          800: '#1F2937', // Elevated Surface (Modals / Menus / Tooltips)
          900: '#161B26', // Surface / Card / Container
          950: '#0B0F19', // Root Background (Deep Charcoal Navy)
        },
        // Explicit SOC Design System Tokens
        soc: {
          root: '#0B0F19',
          surface: '#161B26',
          elevated: '#1F2937',
          border: '#2D3748',
          focus: '#4B5563',
          text: {
            primary: '#F8FAFC',
            secondary: '#94A3B8',
            muted: '#64748B',
          },
          threat: {
            critical: '#EF4444', // P1 - Active compromises, critical CVEs, confirmed attacks
            high: '#F97316',     // P2 - Privilege escalations, suspicious lateral movements
            medium: '#EAB308',   // P3 - Policy anomalies, threshold spikes, brute-force attempts
            low: '#3B82F6',      // Info - System health heartbeats, informational logs
            resolved: '#10B981', // Normal - Mitigated incidents, healthy sensor connections
          },
        },
        brand: {
          dark: '#0B0F19',
          card: '#161B26',
          elevated: '#1F2937',
          border: '#2D3748',
          accent: '#3B82F6',
          danger: '#EF4444',
          warning: '#EAB308',
          high: '#F97316',
          success: '#10B981',
        },
      },
      animation: {
        'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
