import React, { useState, useEffect } from 'react';
import { 
  Users, 
  UserPlus, 
  ShieldAlert, 
  ShieldCheck, 
  UserX, 
  CheckCircle2, 
  Clock, 
  RefreshCw, 
  KeyRound, 
  Trash2, 
  Lock, 
  Mail, 
  User as UserIcon, 
  AlertTriangle,
  History,
  Activity,
  Eye
} from 'lucide-react';
import { api } from '../services/api';
import { User, UserAuditLog, AuthSessionUser } from '../types/dashboard';

interface UserManagementProps {
  currentUser: AuthSessionUser;
}

export const UserManagement: React.FC<UserManagementProps> = ({ currentUser }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [auditLogs, setAuditLogs] = useState<UserAuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeSubTab, setActiveSubTab] = useState<'users' | 'audit'>('users');
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  
  // Create User Form State
  const [newEmail, setNewEmail] = useState('');
  const [newFullName, setNewFullName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR'>('SOC_ANALYST');
  const [newAllowedSystems, setNewAllowedSystems] = useState('ALL');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Status Action Feedback
  const [actionFeedback, setActionFeedback] = useState<{ id: string; message: string; type: 'success' | 'error' } | null>(null);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [usersRes, auditRes] = await Promise.all([
        api.getUsers(),
        api.getUserAuditLogs(100),
      ]);
      if (usersRes.users) setUsers(usersRes.users);
      if (auditRes.logs) setAuditLogs(auditRes.logs);
    } catch (err) {
      console.error('Failed to load user management data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleToggleStatus = async (user: User) => {
    const nextStatus = user.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE';
    if (user.id === currentUser.id && nextStatus === 'SUSPENDED') {
      alert('You cannot suspend your own Super Admin account.');
      return;
    }

    try {
      const res = await api.updateUserStatus(user.id, nextStatus);
      if (res.success) {
        setActionFeedback({
          id: user.id,
          message: `User ${user.email} is now ${nextStatus}`,
          type: 'success',
        });
        await fetchData();
      }
    } catch (err: any) {
      setActionFeedback({
        id: user.id,
        message: err.message || 'Failed to update status',
        type: 'error',
      });
    }
  };

  const handleDeleteUser = async (user: User) => {
    if (user.id === currentUser.id) {
      alert('You cannot delete your own Super Admin account.');
      return;
    }
    if (!window.confirm(`Are you sure you want to permanently delete user ${user.email}? This will be recorded in the security audit trail.`)) {
      return;
    }

    try {
      const res = await api.deleteUser(user.id);
      if (res.success) {
        await fetchData();
      }
    } catch (err) {
      console.error('Failed to delete user:', err);
    }
  };

  const handleCreateUserSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);
    setIsSubmitting(true);

    try {
      const res = await api.createUser({
        email: newEmail,
        fullName: newFullName,
        password: newPassword,
        role: newRole,
        allowedSystems: newAllowedSystems,
      });

      if (res.success) {
        setFormSuccess(`User ${newEmail} created successfully.`);
        setNewEmail('');
        setNewFullName('');
        setNewPassword('');
        setNewRole('SOC_ANALYST');
        setNewAllowedSystems('ALL');
        await fetchData();
        setTimeout(() => {
          setIsCreateModalOpen(false);
          setFormSuccess(null);
        }, 1200);
      } else {
        setFormError(res.message || 'Failed to create user account.');
      }
    } catch (err: any) {
      setFormError(err.message || 'An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const activeCount = users.filter((u) => u.status === 'ACTIVE').length;
  const suspendedCount = users.filter((u) => u.status === 'SUSPENDED').length;
  const superAdminCount = users.filter((u) => u.role === 'SUPER_ADMIN').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-950 border border-indigo-700/50 flex items-center justify-center text-indigo-400">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center space-x-2">
                <span>Super Admin Command & Access Control</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  SUPER_ADMIN
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Institutional User Management, Role Authorization, and Live Security Audit Trail (WAT Timezone)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchData}
            className="p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition"
            title="Refresh Users & Audit Logs"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 shadow-lg shadow-indigo-500/20 transition cursor-pointer"
          >
            <UserPlus className="w-4 h-4 text-slate-950" />
            <span>Create New User</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400 font-mono">Total Directory Users</div>
          <div className="text-2xl font-black text-slate-100 font-mono mt-1">{users.length}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400 font-mono">Active Accounts</div>
          <div className="text-2xl font-black text-emerald-400 font-mono mt-1">{activeCount}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400 font-mono">Suspended Accounts</div>
          <div className="text-2xl font-black text-rose-400 font-mono mt-1">{suspendedCount}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4">
          <div className="text-xs text-slate-400 font-mono">Super Admins</div>
          <div className="text-2xl font-black text-indigo-400 font-mono mt-1">{superAdminCount}</div>
        </div>
      </div>

      {/* Sub-Tabs: Users Directory vs Audit Trail */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('users')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center space-x-2 ${
            activeSubTab === 'users'
              ? 'bg-indigo-950 text-indigo-300 border border-indigo-800 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>User Directory ({users.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('audit')}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition flex items-center space-x-2 ${
            activeSubTab === 'audit'
              ? 'bg-indigo-950 text-indigo-300 border border-indigo-800 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          <span>Security Audit Trail ({auditLogs.length})</span>
        </button>
      </div>

      {/* SubTab 1: Users Directory */}
      {activeSubTab === 'users' && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[11px] uppercase text-slate-400">
                <tr>
                  <th className="px-6 py-4">User</th>
                  <th className="px-6 py-4">Role</th>
                  <th className="px-6 py-4">System Scope</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Last Login</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {users.map((user) => {
                  const isSelf = user.id === currentUser.id;
                  return (
                    <tr key={user.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-6 py-4">
                        <div className="font-sans font-bold text-slate-100">{user.full_name}</div>
                        <div className="text-[11px] text-slate-400">{user.email}</div>
                        {isSelf && (
                          <span className="inline-block mt-1 text-[9px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                            Current Session
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 rounded text-[10px] font-bold border ${
                          user.role === 'SUPER_ADMIN'
                            ? 'bg-indigo-950 text-indigo-300 border-indigo-700/60'
                            : user.role === 'SOC_ANALYST'
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-700/60'
                            : user.role === 'SECURITY_OPERATOR'
                            ? 'bg-amber-950 text-amber-300 border-amber-700/60'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="text-slate-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 text-[11px]">
                          {user.allowed_systems}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold ${
                          user.status === 'ACTIVE'
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                            : 'bg-rose-950/80 text-rose-400 border border-rose-800/60'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${user.status === 'ACTIVE' ? 'bg-emerald-400' : 'bg-rose-400'}`} />
                          <span>{user.status}</span>
                        </span>
                      </td>
                      <td className="px-6 py-4 text-[11px]">
                        <div>{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never logged in'}</div>
                        {user.last_login_ip && (
                          <div className="text-[10px] text-slate-500 font-mono mt-0.5">IP: {user.last_login_ip}</div>
                        )}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => handleToggleStatus(user)}
                            disabled={isSelf}
                            className={`px-2.5 py-1 rounded-lg text-[10px] font-bold transition border cursor-pointer ${
                              user.status === 'ACTIVE'
                                ? 'bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border-rose-800/50'
                                : 'bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 border-emerald-800/50'
                            } ${isSelf ? 'opacity-40 cursor-not-allowed' : ''}`}
                            title={isSelf ? 'Cannot suspend your own account' : `Set to ${user.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE'}`}
                          >
                            {user.status === 'ACTIVE' ? 'Suspend' : 'Activate'}
                          </button>

                          <button
                            onClick={() => handleDeleteUser(user)}
                            disabled={isSelf}
                            className={`p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/50 border border-transparent hover:border-rose-900/50 transition ${
                              isSelf ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'
                            }`}
                            title={isSelf ? 'Cannot delete your own account' : 'Delete user'}
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SubTab 2: Live Security Audit Trail */}
      {activeSubTab === 'audit' && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl space-y-3 p-4">
          <div className="flex items-center justify-between px-2 pt-1 pb-2 border-b border-slate-800">
            <div className="text-xs font-mono text-slate-300 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>IMMUTABLE USER SECURITY AUDIT LOG (WAT / UTC+1)</span>
            </div>
            <span className="text-[10px] font-mono text-slate-500">Auto-streaming live events</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-[11px] uppercase text-slate-400">
                <tr>
                  <th className="px-4 py-3">Timestamp (WAT)</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">User Target</th>
                  <th className="px-4 py-3">Client IP</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Event Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 text-[11px] text-cyan-400 whitespace-nowrap">
                      {log.created_at_wat || 'WAT'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        log.action === 'LOGIN_SUCCESS'
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          : log.action === 'LOGIN_FAILED'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : log.action === 'ACCOUNT_CREATED'
                          ? 'bg-indigo-950 text-indigo-300 border-indigo-800'
                          : log.action === 'ACCOUNT_SUSPENDED'
                          ? 'bg-amber-950 text-amber-300 border-amber-800'
                          : 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-200 font-semibold">{log.email}</td>
                    <td className="px-4 py-3 text-slate-400">{log.ip_address}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        log.status === 'SUCCESS'
                          ? 'text-emerald-400 bg-emerald-950/60 border border-emerald-800/50'
                          : log.status === 'FAILED'
                          ? 'text-rose-400 bg-rose-950/60 border border-rose-800/50'
                          : 'text-amber-400 bg-amber-950/60 border border-amber-800/50'
                      }`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300 text-[11px]">{log.details || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: Create New User */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-lg bg-slate-900 border border-indigo-800/60 rounded-2xl shadow-2xl shadow-indigo-950/80 overflow-hidden">
            <div className="px-6 py-4 bg-slate-800/80 border-b border-slate-700/80 flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <UserPlus className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-slate-100 text-sm">Provision New SOC User</h3>
              </div>
              <button
                onClick={() => setIsCreateModalOpen(false)}
                className="text-slate-400 hover:text-slate-100 transition"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateUserSubmit} className="p-6 space-y-4">
              {formError && (
                <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs flex items-center space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              {formSuccess && (
                <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{formSuccess}</span>
                </div>
              )}

              {/* Full Name */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Staff Full Name</label>
                <div className="relative">
                  <UserIcon className="w-4 h-4 text-slate-500 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="text"
                    required
                    value={newFullName}
                    onChange={(e) => setNewFullName(e.target.value)}
                    placeholder="e.g. Dr. Samuel Okafor"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Email */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Institutional Email</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="s.okafor@noun.edu.ng"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Password */}
              <div className="space-y-1">
                <label className="text-xs font-medium text-slate-300">Initial Password (min. 8 characters)</label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Role */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">SOC Role</label>
                  <select
                    value={newRole}
                    onChange={(e: any) => setNewRole(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="SOC_ANALYST">SOC Analyst</option>
                    <option value="SECURITY_OPERATOR">Security Operator</option>
                    <option value="AUDITOR">Compliance Auditor</option>
                    <option value="SUPER_ADMIN">Super Admin</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-medium text-slate-300">Monitored Systems Scope</label>
                  <select
                    value={newAllowedSystems}
                    onChange={(e) => setNewAllowedSystems(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-indigo-500 font-mono"
                  >
                    <option value="ALL">ALL Systems (Universal)</option>
                    <option value="NOUN-HRMS">NOUN-HRMS Only</option>
                    <option value="Clinic-EHR">Clinic-EHR Only</option>
                    <option value="Security-Dispatch">Security-Dispatch Only</option>
                  </select>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-2 flex items-center justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-2 transition shadow-lg shadow-indigo-500/25 disabled:opacity-50 cursor-pointer"
                >
                  {isSubmitting ? (
                    <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <>
                      <KeyRound className="w-4 h-4" />
                      <span>Provision User</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
