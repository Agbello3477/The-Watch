import React, { useState } from 'react';
import { 
  X, 
  ShieldCheck, 
  Lock, 
  Mail, 
  Eye, 
  EyeOff, 
  AlertTriangle, 
  KeyRound, 
  CheckCircle2, 
  Sparkles,
  Clock,
  ShieldAlert
} from 'lucide-react';
import { api } from '../services/api';
import { AuthSessionUser } from '../types/dashboard';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: AuthSessionUser) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({
  isOpen,
  onClose,
  onLoginSuccess,
}) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleFillSuperAdmin = () => {
    setEmail('abdulgaffarbello3477@gmail.com');
    setPassword('Agbello@3477');
    setErrorMessage(null);
    setErrorCode(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMessage('Please provide both email and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setErrorCode(null);

    try {
      const response = await api.login({ email, password });
      if (response.success && response.user) {
        onLoginSuccess(response.user);
        onClose();
      } else {
        setErrorMessage(response.error || 'Authentication failed. Please verify your credentials.');
        setErrorCode(response.code || null);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected network error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
      <div 
        className="relative w-full max-w-md bg-slate-900 border border-cyan-800/60 rounded-2xl shadow-2xl shadow-cyan-950/80 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Accent Header */}
        <div className="relative px-6 pt-6 pb-4 bg-gradient-to-b from-slate-800/80 to-slate-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 p-[1.5px]">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <h3 className="font-bold text-slate-100 text-base">Security Command Portal</h3>
              <p className="text-[11px] text-slate-400 font-mono">SOC Multi-Factor Authentication</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick-Fill Super Admin Banner */}
        <div className="mx-6 mt-4 p-3 rounded-xl bg-cyan-950/40 border border-cyan-800/50 flex items-center justify-between">
          <div className="space-y-0.5">
            <div className="text-xs font-semibold text-cyan-300 flex items-center space-x-1.5">
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
              <span>Super Admin Demo Preset</span>
            </div>
            <div className="text-[10px] text-slate-400 font-mono">abdulgaffarbello3477@gmail.com</div>
          </div>
          <button
            type="button"
            onClick={handleFillSuperAdmin}
            className="px-2.5 py-1 text-[11px] font-bold rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition"
          >
            Fill Super Admin
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {errorMessage && (
            <div className={`p-3 rounded-xl text-xs flex items-start space-x-2 border ${
              errorCode === 'ACCOUNT_LOCKED' 
                ? 'bg-rose-950/70 border-rose-800 text-rose-300' 
                : 'bg-amber-950/70 border-amber-800 text-amber-300'
            }`}>
              {errorCode === 'ACCOUNT_LOCKED' ? (
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
              )}
              <div className="flex-1">
                <span className="font-semibold block">{errorMessage}</span>
                {errorCode === 'ACCOUNT_LOCKED' && (
                  <span className="text-[10px] opacity-80 mt-1 block font-mono">
                    Security Policy: Lockout automatically releases in 15 minutes.
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Email field */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              Institutional Email Address
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Mail className="w-4 h-4" />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@institution.edu.ng"
                className="w-full pl-9 pr-3 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition"
              />
            </div>
          </div>

          {/* Password field */}
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-slate-300">
              Security Password / Key
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-10 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono transition"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-300 transition"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Security Features Info Box */}
          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-[10px] text-slate-400 space-y-1 font-mono">
            <div className="flex items-center space-x-1 text-slate-300 font-semibold">
              <KeyRound className="w-3 h-3 text-cyan-400" />
              <span>Enterprise Security Protocol</span>
            </div>
            <div>• PBKDF2 100,000 Iterations (SHA-512)</div>
            <div>• Automatic 15-Minute Lockout after 5 Failures</div>
            <div>• Real-time West Africa Time (WAT) Audit Trail</div>
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/25 transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isLoading ? (
              <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Verify & Sign In</span>
              </>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="px-6 py-3 bg-slate-950 border-t border-slate-800 text-center text-[10px] text-slate-500 font-mono">
          Powered by: MaSha Tech Innovations
        </div>
      </div>
    </div>
  );
};
