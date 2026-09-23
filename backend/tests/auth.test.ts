import { describe, it, expect, beforeAll } from 'vitest';
import { authService } from '../src/auth/auth-service';
import { db } from '../src/db/database';

describe('Authentication & Security Service Tests', () => {
  beforeAll(async () => {
    await db.initialize();
  });

  it('should authenticate super admin with seeded credentials', async () => {
    const result = await authService.login({
      email: 'abdulgaffarbello3477@gmail.com',
      password: 'Agbello@3477',
      ipAddress: '127.0.0.1',
      userAgent: 'Mozilla/5.0 TestRunner',
    });

    expect(result.success).toBe(true);
    expect(result.token).toBeDefined();
    expect(result.user).toBeDefined();
    expect(result.user?.email).toBe('abdulgaffarbello3477@gmail.com');
    expect(result.user?.role).toBe('SUPER_ADMIN');
    expect(result.user?.status).toBe('ACTIVE');
    expect((result.user as any).password_hash).toBeUndefined();
    expect((result.user as any).password_salt).toBeUndefined();
  });

  it('should reject incorrect password and increment failed attempts', async () => {
    const testEmail = `sec-test-${Date.now()}@masha-tech.com`;
    const user = await authService.createUser({
      email: testEmail,
      fullName: 'Security Test User',
      password: 'TestPassword123!',
      role: 'SECURITY_ANALYST',
      organization: 'MaSha Tech Innovations',
    });

    expect(user.id).toBeDefined();

    // Attempt 1 with wrong password
    const failResult = await authService.login({
      email: testEmail,
      password: 'WrongPass123!',
      ipAddress: '102.89.23.1',
      userAgent: 'Vitest',
    });

    expect(failResult.success).toBe(false);
    expect(failResult.code).toBe('INVALID_CREDENTIALS');

    const freshUser = await db.getUserByEmail(testEmail);
    expect(freshUser?.failed_login_attempts).toBe(1);
  });

  it('should lock out account after 5 consecutive failed login attempts for 15 minutes', async () => {
    const testEmail = `lockout-${Date.now()}@masha-tech.com`;
    await authService.createUser({
      email: testEmail,
      fullName: 'Lockout Target',
      password: 'CorrectPassword@123',
      role: 'AUDITOR',
      organization: 'MaSha Tech Innovations',
    });

    // Fail 5 times
    for (let i = 1; i <= 5; i++) {
      const attempt = await authService.login({
        email: testEmail,
        password: 'BadPassword!',
        ipAddress: '197.210.64.1',
        userAgent: 'Vitest',
      });

      expect(attempt.success).toBe(false);
      if (i === 5) {
        expect(attempt.code).toBe('ACCOUNT_LOCKED');
        expect(attempt.lockedUntil).toBeDefined();
      } else {
        expect(attempt.code).toBe('INVALID_CREDENTIALS');
      }
    }

    // 6th attempt with CORRECT password should still be blocked due to active lockout
    const lockedAttempt = await authService.login({
      email: testEmail,
      password: 'CorrectPassword@123',
      ipAddress: '197.210.64.1',
      userAgent: 'Vitest',
    });

    expect(lockedAttempt.success).toBe(false);
    expect(lockedAttempt.code).toBe('ACCOUNT_LOCKED');
    expect(lockedAttempt.error).toContain('Account is temporarily locked');
  });

  it('should verify valid JWT and reject invalid/tampered tokens', () => {
    const token = authService.generateToken({
      id: 'usr_test_123',
      email: 'analyst@masha-tech.com',
      fullName: 'SOC Analyst',
      role: 'SOC_ANALYST',
      status: 'ACTIVE',
      allowedSystems: 'ALL',
    });

    expect(token).toBeDefined();
    const payload = authService.verifyToken(token);
    expect(payload).not.toBeNull();
    expect(payload?.email).toBe('analyst@masha-tech.com');
    expect(payload?.role).toBe('SOC_ANALYST');

    // Tampered token
    const tamperedToken = token.slice(0, -5) + 'xxxxx';
    const tamperedPayload = authService.verifyToken(tamperedToken);
    expect(tamperedPayload).toBeNull();
  });
});
