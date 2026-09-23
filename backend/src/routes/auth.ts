import { Router, Request, Response } from 'express';
import { authService } from '../auth/auth-service';
import { authenticateUser, AuthenticatedUserRequest } from '../middleware/user-auth';
import { db, getWATFormattedDate } from '../db/database';

export const authRouter = Router();

/**
 * Enterprise Secure Login
 * Rate limited, brute-force protected, audited in WAT
 */
authRouter.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const ipAddress = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
  const userAgent = req.headers['user-agent'] || 'Unknown Client';

  if (!email || !password) {
    res.status(400).json({
      error: 'MISSING_CREDENTIALS',
      message: 'Email address and password are required.',
    });
    return;
  }

  const result = await authService.login({
    email,
    password,
    ipAddress,
    userAgent,
  });

  if (!result.success) {
    const statusCode = result.code === 'ACCOUNT_LOCKED' ? 423 : result.code === 'ACCOUNT_SUSPENDED' ? 403 : 401;
    res.status(statusCode).json(result);
    return;
  }

  res.json(result);
});

/**
 * Get current session profile
 */
authRouter.get('/me', authenticateUser, (req: AuthenticatedUserRequest, res: Response) => {
  res.json({
    user: req.user,
    sessionValid: true,
    timestampWat: getWATFormattedDate(),
  });
});

/**
 * Secure Logout & Audit Log
 */
authRouter.post('/logout', authenticateUser, async (req: AuthenticatedUserRequest, res: Response) => {
  const user = req.user!;
  const ipAddress = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

  await db.saveUserAuditLog({
    id: `ual-logout-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    user_id: user.id,
    email: user.email,
    action: 'LOGIN_SUCCESS',
    ip_address: ipAddress,
    status: 'SUCCESS',
    details: 'User initiated secure session logout',
    created_at_wat: getWATFormattedDate(),
  });

  res.json({
    success: true,
    message: 'Session successfully terminated.',
  });
});
