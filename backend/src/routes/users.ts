import { Router, Response } from 'express';
import { authenticateUser, requireSuperAdmin, AuthenticatedUserRequest } from '../middleware/user-auth';
import { db, User, hashPassword, getWATFormattedDate } from '../db/database';

export const usersRouter = Router();

// Protect all user management routes with Super Admin authorization
usersRouter.use(authenticateUser);
usersRouter.use(requireSuperAdmin);

/**
 * List all users (Super Admin only)
 */
usersRouter.get('/', async (req: AuthenticatedUserRequest, res: Response) => {
  const users = await db.getAllUsers();
  res.json({
    totalUsers: users.length,
    users,
  });
});

/**
 * Create a new user account (Super Admin only)
 */
usersRouter.post('/', async (req: AuthenticatedUserRequest, res: Response) => {
  const { email, password, fullName, role, allowedSystems } = req.body;
  const adminUser = req.user!;
  const clientIp = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  // Validate inputs
  if (!email || !password || !fullName) {
    res.status(400).json({
      error: 'MISSING_FIELDS',
      message: 'Email, password, and full name are required.',
    });
    return;
  }

  const cleanEmail = email.toLowerCase().trim();

  // Basic email syntax check
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    res.status(400).json({
      error: 'INVALID_EMAIL_FORMAT',
      message: 'Please provide a valid email address.',
    });
    return;
  }

  // Password complexity check
  if (password.length < 8) {
    res.status(400).json({
      error: 'WEAK_PASSWORD',
      message: 'Password must be at least 8 characters in length.',
    });
    return;
  }

  // Check if user already exists
  const existing = await db.getUserByEmail(cleanEmail);
  if (existing) {
    res.status(409).json({
      error: 'USER_ALREADY_EXISTS',
      message: `An account with email ${cleanEmail} already exists.`,
    });
    return;
  }

  // Validate Role
  const validRoles = ['SUPER_ADMIN', 'SOC_ANALYST', 'SECURITY_OPERATOR', 'AUDITOR'];
  const userRole = validRoles.includes(role) ? role : 'SOC_ANALYST';

  // Hash password with PBKDF2
  const { hash, salt } = hashPassword(password);

  const newUser: User = {
    id: `usr-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    email: cleanEmail,
    password_hash: hash,
    salt,
    full_name: fullName.trim(),
    role: userRole,
    status: 'ACTIVE',
    allowed_systems: allowedSystems || 'ALL',
    failed_login_attempts: 0,
    created_by: adminUser.email,
    created_at: new Date().toISOString(),
  };

  await db.saveUser(newUser);

  // Record Audit Log
  await db.saveUserAuditLog({
    id: `ual-create-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    user_id: newUser.id,
    email: newUser.email,
    action: 'ACCOUNT_CREATED',
    ip_address: clientIp,
    user_agent: req.headers['user-agent'],
    status: 'SUCCESS',
    details: `Account created by Super Admin (${adminUser.email}) with role ${newUser.role}`,
    created_at_wat: getWATFormattedDate(),
  });

  const { password_hash, salt: userSalt, ...safeUser } = newUser;

  res.status(201).json({
    success: true,
    message: `User ${newUser.email} created successfully.`,
    user: safeUser,
  });
});

/**
 * Toggle user status: ACTIVE or SUSPENDED (Super Admin only)
 */
usersRouter.patch('/:id/status', async (req: AuthenticatedUserRequest, res: Response) => {
  const { id } = req.params;
  const { status } = req.body;
  const adminUser = req.user!;
  const clientIp = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  if (status !== 'ACTIVE' && status !== 'SUSPENDED') {
    res.status(400).json({ error: 'INVALID_STATUS', message: 'Status must be ACTIVE or SUSPENDED.' });
    return;
  }

  // Prevent Super Admin from suspending self
  if (id === adminUser.id && status === 'SUSPENDED') {
    res.status(400).json({ error: 'CANNOT_SUSPEND_SELF', message: 'You cannot suspend your own Super Admin account.' });
    return;
  }

  const updated = await db.updateUserStatus(id, status);
  if (!updated) {
    res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User account not found.' });
    return;
  }

  // Record Audit Log
  const action = status === 'SUSPENDED' ? 'ACCOUNT_SUSPENDED' : 'ACCOUNT_ACTIVATED';
  await db.saveUserAuditLog({
    id: `ual-stat-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    user_id: updated.id,
    email: updated.email,
    action,
    ip_address: clientIp,
    user_agent: req.headers['user-agent'],
    status: 'SUCCESS',
    details: `Account status updated to ${status} by Super Admin (${adminUser.email})`,
    created_at_wat: getWATFormattedDate(),
  });

  res.json({
    success: true,
    message: `User status changed to ${status}.`,
    user: {
      id: updated.id,
      email: updated.email,
      fullName: updated.full_name,
      role: updated.role,
      status: updated.status,
    },
  });
});

/**
 * Delete user account (Super Admin only)
 */
usersRouter.delete('/:id', async (req: AuthenticatedUserRequest, res: Response) => {
  const { id } = req.params;
  const adminUser = req.user!;
  const clientIp = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  if (id === adminUser.id) {
    res.status(400).json({ error: 'CANNOT_DELETE_SELF', message: 'You cannot delete your own Super Admin account.' });
    return;
  }

  const user = await db.getUserById(id);
  if (!user) {
    res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User account not found.' });
    return;
  }

  const deleted = await db.deleteUser(id);
  if (!deleted) {
    res.status(500).json({ error: 'DELETE_FAILED', message: 'Failed to delete user.' });
    return;
  }

  // Record Audit Log
  await db.saveUserAuditLog({
    id: `ual-del-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    user_id: user.id,
    email: user.email,
    action: 'ACCOUNT_DELETED',
    ip_address: clientIp,
    user_agent: req.headers['user-agent'],
    status: 'SUCCESS',
    details: `User ${user.email} (${user.role}) permanently deleted by Super Admin (${adminUser.email})`,
    created_at_wat: getWATFormattedDate(),
  });

  res.json({
    success: true,
    message: `User ${user.email} deleted successfully.`,
  });
});

/**
 * Fetch real-time user security audit log stream (Super Admin only)
 */
usersRouter.get('/audit', async (req: AuthenticatedUserRequest, res: Response) => {
  const limit = req.query.limit ? parseInt(String(req.query.limit), 10) : 100;
  const logs = await db.getUserAuditLogs(limit);
  res.json({
    totalLogs: logs.length,
    logs,
  });
});
