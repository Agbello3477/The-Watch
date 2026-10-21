import { Router, Request, Response } from 'express';
import { authService } from '../auth/auth-service';
import { authenticateUser, AuthenticatedUserRequest } from '../middleware/user-auth';
import { db, UserAuditLog, getWATFormattedDate } from '../db/database';
import { geoIPService } from '../threat/geoip-service';
import { realtimeAlertHub } from '../alerts/realtime-alert-hub';
import { socEngine } from '../soc/soc-engine';

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

  // Whitelist & unban authenticated SOC Operator IP so resolving self-tested alerts never locks out the operator
  socEngine.whitelistOperatorIp(ipAddress);

  res.json(result);
});

/**
 * Get current session profile
 */
authRouter.get('/me', authenticateUser, (req: AuthenticatedUserRequest, res: Response) => {
  const ipAddress = (req.headers['x-forwarded-for'] as string || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
  socEngine.whitelistOperatorIp(ipAddress);
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
  const geo = await geoIPService.resolve(ipAddress);
  const location = `${geo.city}, ${geo.country}${geo.asn ? ` (${geo.asn})` : ''}`;

  const auditLog: UserAuditLog = {
    id: `ual-logout-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
    user_id: user.id,
    email: user.email,
    full_name: user.fullName || user.email,
    role: user.role,
    action: 'LOGOUT',
    ip_address: ipAddress,
    location,
    geo_city: geo.city,
    geo_country: geo.country,
    user_agent: req.headers['user-agent'],
    status: 'SUCCESS',
    details: `User signed out of session from ${location}`,
    created_at_wat: getWATFormattedDate(),
  };

  await db.saveUserAuditLog(auditLog);
  realtimeAlertHub.broadcastAuditLog(auditLog);

  res.json({
    success: true,
    message: 'Session successfully terminated.',
  });
});
