import { describe, it, expect, beforeAll } from 'vitest';
import { db } from '../src/db/database';
import { authService } from '../src/auth/auth-service';

describe('Super Admin User Management & Audit Tests', () => {
  beforeAll(async () => {
    await db.initialize();
  });

  it('should list all registered users including seeded super admin', async () => {
    const users = await db.getAllUsers();
    expect(users.length).toBeGreaterThanOrEqual(1);
    const superAdmin = users.find((u) => u.email === 'abdulgaffarbello3477@gmail.com');
    expect(superAdmin).toBeDefined();
    expect(superAdmin?.role).toBe('SUPER_ADMIN');
    expect(superAdmin?.status).toBe('ACTIVE');
  });

  it('should allow creating a new user with secure password hash and retrieve it', async () => {
    const email = `analyst-${Date.now()}@masha-tech.com`;
    const createdUser = await authService.createUser({
      email,
      fullName: 'SOC Operator Alpha',
      password: 'StrongPassword123#',
      role: 'SOC_ANALYST',
      organization: 'MaSha Security Operations',
    });

    expect(createdUser.id).toBeDefined();
    expect(createdUser.email).toBe(email);
    expect(createdUser.role).toBe('SOC_ANALYST');

    const fetched = await db.getUserById(createdUser.id);
    expect(fetched).toBeDefined();
    expect(fetched?.full_name).toBe('SOC Operator Alpha');
  });

  it('should allow toggling user status between ACTIVE and SUSPENDED', async () => {
    const email = `suspend-test-${Date.now()}@masha-tech.com`;
    const user = await authService.createUser({
      email,
      fullName: 'Suspension Candidate',
      password: 'Password999!',
      role: 'AUDITOR',
    });

    // Suspend user
    const suspended = await db.updateUserStatus(user.id, 'SUSPENDED');
    expect(suspended?.status).toBe('SUSPENDED');

    // Attempting login when suspended should fail
    const loginAttempt = await authService.login({
      email,
      password: 'Password999!',
      ipAddress: '127.0.0.1',
      userAgent: 'Vitest',
    });
    expect(loginAttempt.success).toBe(false);
    expect(loginAttempt.code).toBe('ACCOUNT_SUSPENDED');

    // Reactivate user
    const reactivated = await db.updateUserStatus(user.id, 'ACTIVE');
    expect(reactivated?.status).toBe('ACTIVE');

    // Login succeeds after reactivation
    const loginResult = await authService.login({
      email,
      password: 'Password999!',
      ipAddress: '127.0.0.1',
      userAgent: 'Vitest',
    });
    expect(loginResult.success).toBe(true);
    expect(loginResult.token).toBeDefined();
  });

  it('should record and query audit logs with WAT timestamps and actor details', async () => {
    const logs = await db.getUserAuditLogs(20);
    expect(Array.isArray(logs)).toBe(true);
    expect(logs.length).toBeGreaterThan(0);

    const latest = logs[0];
    expect(latest.created_at_wat).toBeDefined();
    expect(latest.created_at_wat).toContain('WAT');
    expect(latest.action).toBeDefined();
    expect(latest.ip_address).toBeDefined();
  });

  it('should delete a user cleanly', async () => {
    const email = `delete-me-${Date.now()}@masha-tech.com`;
    const user = await authService.createUser({
      email,
      fullName: 'To Be Deleted',
      password: 'TempPassword123!',
      role: 'AUDITOR',
    });

    const deleted = await db.deleteUser(user.id);
    expect(deleted).toBe(true);

    const check = await db.getUserById(user.id);
    expect(check).toBeNull();
  });
});
