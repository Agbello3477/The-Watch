import crypto from 'crypto';
import { db, User, hashPassword, getWATFormattedDate } from '../db/database';
import { CONFIG } from '../config';
import { geoIPService } from '../threat/geoip-service';
import { ddosDetector } from '../threat/ddos-detector';

export interface AuthSessionUser {
  id: string;
  email: string;
  fullName: string;
  role: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
  status: 'ACTIVE' | 'SUSPENDED';
  allowedSystems: string;
  lastLoginAt?: string;
  lastLoginIp?: string;
}

export interface LoginResult {
  success: boolean;
  token?: string;
  user?: AuthSessionUser;
  error?: string;
  code?: 'INVALID_CREDENTIALS' | 'ACCOUNT_LOCKED' | 'ACCOUNT_SUSPENDED' | 'RATE_LIMITED';
  lockedUntil?: string;
}

export class AuthService {
  private readonly MAX_FAILED_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

  /**
   * Timing-safe verification of plaintext password against stored PBKDF2 hash & salt
   */
  public verifyPassword(password: string, hash: string, salt: string): boolean {
    try {
      const calculatedHash = crypto
        .pbkdf2Sync(password, salt, 100000, 64, 'sha512')
        .toString('hex');
      
      const storedBuf = Buffer.from(hash, 'hex');
      const calcBuf = Buffer.from(calculatedHash, 'hex');

      if (storedBuf.length !== calcBuf.length) return false;
      return crypto.timingSafeEqual(storedBuf, calcBuf);
    } catch {
      return false;
    }
  }

  /**
   * Authenticates user, enforces lockout & rate-limiting, and logs security audit trail
   */
  public async login(data: {
    email: string;
    password: string;
    ipAddress: string;
    userAgent?: string;
  }): Promise<LoginResult> {
    const { email, password, ipAddress, userAgent } = data;
    const cleanEmail = (email || '').toLowerCase().trim();

    // 1. Resolve GeoIP for location-aware audit logging
    const geo = await geoIPService.resolve(ipAddress);
    const locationStr = `${geo.city}, ${geo.country} (${geo.asn})`;

    // 2. Fetch user
    const user = await db.getUserByEmail(cleanEmail);

    if (!user) {
      // Record failed attempt audit log
      await db.saveUserAuditLog({
        id: `ual-fail-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        email: cleanEmail,
        action: 'LOGIN_FAILED',
        ip_address: ipAddress,
        user_agent: userAgent,
        status: 'FAILED',
        details: `Login attempt for non-existent user from ${locationStr}`,
        created_at_wat: getWATFormattedDate(),
      });

      // Track 401 failure against DDoS & Credential stuffing detector
      await ddosDetector.trackAndInspect({
        clientIp: ipAddress,
        path: '/api/v1/auth/login',
        statusCode: 401,
      });

      return {
        success: false,
        error: 'Invalid email address or password.',
        code: 'INVALID_CREDENTIALS',
      };
    }

    // 3. Check Account Suspension
    if (user.status === 'SUSPENDED') {
      await db.saveUserAuditLog({
        id: `ual-susp-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        user_id: user.id,
        email: user.email,
        action: 'LOGIN_FAILED',
        ip_address: ipAddress,
        user_agent: userAgent,
        status: 'BLOCKED',
        details: `Suspended account access denied from ${locationStr}`,
        created_at_wat: getWATFormattedDate(),
      });

      return {
        success: false,
        error: 'Your account has been suspended by the Security Administrator. Please contact IT Security.',
        code: 'ACCOUNT_SUSPENDED',
      };
    }

    // 4. Check Account Lockout
    if (user.locked_until) {
      const lockExpiry = new Date(user.locked_until).getTime();
      if (Date.now() < lockExpiry) {
        const minutesLeft = Math.ceil((lockExpiry - Date.now()) / 60000);

        await db.saveUserAuditLog({
          id: `ual-lock-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
          user_id: user.id,
          email: user.email,
          action: 'LOGIN_FAILED',
          ip_address: ipAddress,
          user_agent: userAgent,
          status: 'BLOCKED',
          details: `Login blocked: account locked for ${minutesLeft} more minutes from ${locationStr}`,
          created_at_wat: getWATFormattedDate(),
        });

        return {
          success: false,
          error: `Account is temporarily locked due to excessive failed attempts. Please try again in ${minutesLeft} minutes.`,
          code: 'ACCOUNT_LOCKED',
          lockedUntil: user.locked_until,
        };
      }
    }

    // 5. Verify Password
    const isValid = this.verifyPassword(password, user.password_hash, user.salt);

    if (!isValid) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil: string | undefined = undefined;

      if (newAttempts >= this.MAX_FAILED_ATTEMPTS) {
        lockUntil = new Date(Date.now() + this.LOCKOUT_DURATION_MS).toISOString();
      }

      await db.incrementFailedLoginAttempts(cleanEmail, lockUntil);

      await db.saveUserAuditLog({
        id: `ual-badpass-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        user_id: user.id,
        email: user.email,
        action: 'LOGIN_FAILED',
        ip_address: ipAddress,
        user_agent: userAgent,
        status: 'FAILED',
        details: lockUntil
          ? `Account locked: exceeded ${this.MAX_FAILED_ATTEMPTS} failed attempts from ${locationStr}`
          : `Failed password attempt (${newAttempts}/${this.MAX_FAILED_ATTEMPTS}) from ${locationStr}`,
        created_at_wat: getWATFormattedDate(),
      });

      // Track credential stuffing trigger
      await ddosDetector.trackAndInspect({
        clientIp: ipAddress,
        path: '/api/v1/auth/login',
        statusCode: 401,
      });

      if (lockUntil) {
        return {
          success: false,
          error: `Account has been locked for 15 minutes after ${this.MAX_FAILED_ATTEMPTS} failed attempts.`,
          code: 'ACCOUNT_LOCKED',
          lockedUntil: lockUntil,
        };
      }

      return {
        success: false,
        error: `Invalid email address or password. (${this.MAX_FAILED_ATTEMPTS - newAttempts} attempts remaining before lockout)`,
        code: 'INVALID_CREDENTIALS',
      };
    }

    // 6. Successful Login: Update metrics & issue token
    await db.updateUserLoginMetrics(user.id, ipAddress);

    const sessionUser: AuthSessionUser = {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      role: user.role,
      status: user.status,
      allowedSystems: user.allowed_systems || 'ALL',
      lastLoginAt: new Date().toISOString(),
      lastLoginIp: ipAddress,
    };

    const token = this.generateToken(sessionUser);

    await db.saveUserAuditLog({
      id: `ual-ok-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
      user_id: user.id,
      email: user.email,
      action: 'LOGIN_SUCCESS',
      ip_address: ipAddress,
      user_agent: userAgent,
      status: 'SUCCESS',
      details: `Successful authenticated session started from ${locationStr}`,
      created_at_wat: getWATFormattedDate(),
    });

    return {
      success: true,
      token,
      user: sessionUser,
    };
  }

  /**
   * Generates a cryptographically signed HMAC-SHA256 JWT token
   */
  public generateToken(user: AuthSessionUser, expiresInHours: number = 24): string {
    const header = {
      alg: 'HS256',
      typ: 'JWT',
    };

    const payload = {
      sub: user.id,
      email: user.email,
      name: user.fullName,
      role: user.role,
      allowedSystems: user.allowedSystems,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresInHours * 3600,
    };

    const base64Header = Buffer.from(JSON.stringify(header)).toString('base64url');
    const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', CONFIG.HMAC_SECRET)
      .update(`${base64Header}.${base64Payload}`)
      .digest('base64url');

    return `${base64Header}.${base64Payload}.${signature}`;
  }

  /**
   * Verifies and decodes HMAC-SHA256 JWT token
   */
  public verifyToken(token: string): any | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const [headerB64, payloadB64, signature] = parts;
      const expectedSig = crypto
        .createHmac('sha256', CONFIG.HMAC_SECRET)
        .update(`${headerB64}.${payloadB64}`)
        .digest('base64url');

      const sigBuf = Buffer.from(signature);
      const expBuf = Buffer.from(expectedSig);

      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        return null;
      }

      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return null; // Expired token
      }

      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Helper method to programmatically create and save a new user
   */
  public async createUser(data: {
    email: string;
    fullName: string;
    password: string;
    role?: 'SUPER_ADMIN' | 'SOC_ANALYST' | 'SECURITY_OPERATOR' | 'AUDITOR';
    allowedSystems?: string;
    organization?: string;
    createdBy?: string;
  }): Promise<User> {
    const cleanEmail = (data.email || '').toLowerCase().trim();
    const { hash, salt } = hashPassword(data.password);

    const newUser: User = {
      id: `usr-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      email: cleanEmail,
      password_hash: hash,
      salt,
      full_name: data.fullName.trim(),
      role: data.role || 'SOC_ANALYST',
      status: 'ACTIVE',
      allowed_systems: data.allowedSystems || 'ALL',
      failed_login_attempts: 0,
      created_by: data.createdBy || 'SUPER_ADMIN',
      created_at: new Date().toISOString(),
    };

    await db.saveUser(newUser);
    return newUser;
  }
}

export const authService = new AuthService();
