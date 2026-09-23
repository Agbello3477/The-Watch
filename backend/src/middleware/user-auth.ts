import { Request, Response, NextFunction } from 'express';
import { authService, AuthSessionUser } from '../auth/auth-service';
import { db } from '../db/database';

export interface AuthenticatedUserRequest extends Request {
  user?: AuthSessionUser;
}

/**
 * Validates JWT bearer token and sets req.user
 */
export async function authenticateUser(req: AuthenticatedUserRequest, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'UNAUTHORIZED_SESSION',
      message: 'Access denied: Authentication token required.',
    });
    return;
  }

  const token = authHeader.substring(7).trim();
  const payload = authService.verifyToken(token);

  if (!payload) {
    res.status(401).json({
      error: 'INVALID_OR_EXPIRED_TOKEN',
      message: 'Your session has expired or is invalid. Please sign in again.',
    });
    return;
  }

  // Look up user to verify active status
  const user = await db.getUserById(payload.sub);
  if (!user || user.status === 'SUSPENDED') {
    res.status(403).json({
      error: 'ACCOUNT_INACTIVE',
      message: 'User account is not found or has been suspended.',
    });
    return;
  }

  req.user = {
    id: user.id,
    email: user.email,
    fullName: user.full_name,
    role: user.role,
    status: user.status,
    allowedSystems: user.allowed_systems || 'ALL',
    lastLoginAt: user.last_login_at || undefined,
    lastLoginIp: user.last_login_ip || undefined,
  };

  next();
}

/**
 * Ensures authenticated user has SUPER_ADMIN role
 */
export function requireSuperAdmin(req: AuthenticatedUserRequest, res: Response, next: NextFunction): void {
  if (!req.user || req.user.role !== 'SUPER_ADMIN') {
    res.status(403).json({
      error: 'FORBIDDEN_SUPER_ADMIN_ONLY',
      message: 'Access denied: This action requires Super Administrator privileges.',
    });
    return;
  }
  next();
}
