import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { db } from '../db/database';
import { REGISTERED_TENANTS } from '../config';

export interface AuthenticatedTenantRequest extends Request {
  tenant?: {
    systemId: string;
    name: string;
    apiKey: string;
  };
}

/**
 * Validates tenant API telemetry key and optional HMAC-SHA256 signature
 */
export async function authenticateTenant(req: AuthenticatedTenantRequest, res: Response, next: NextFunction): Promise<void> {
  const apiKey = (req.headers['x-telemetry-key'] as string) || (req.query.apiKey as string);
  const signature = req.headers['x-telemetry-signature'] as string;

  if (!apiKey) {
    res.status(401).json({
      error: 'UNAUTHORIZED_TELEMETRY_ACCESS',
      message: 'Missing required X-Telemetry-Key header.',
    });
    return;
  }

  // Look up tenant
  const tenant = await db.getTenantByApiKey(apiKey);
  if (!tenant) {
    res.status(403).json({
      error: 'INVALID_TELEMETRY_KEY',
      message: 'Provided telemetry key is unrecognized or deactivated.',
    });
    return;
  }

  // If cryptographic signature provided, verify HMAC-SHA256
  if (signature) {
    const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const expectedSig = crypto
      .createHmac('sha256', tenant.api_secret || tenant.apiSecret || '')
      .update(rawBody)
      .digest('hex');

    if (signature !== expectedSig) {
      res.status(403).json({
        error: 'INVALID_CRYPTOGRAPHIC_SIGNATURE',
        message: 'HMAC-SHA256 telemetry payload verification failed.',
      });
      return;
    }
  }

  req.tenant = {
    systemId: tenant.system_id || tenant.systemId,
    name: tenant.name,
    apiKey: tenant.api_key || tenant.apiKey,
  };

  next();
}
