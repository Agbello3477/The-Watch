import { describe, it, expect } from 'vitest';
import { GeoIPService } from '../src/threat/geoip-service';

describe('GeoIP & Threat Intelligence Pipeline', () => {
  const geo = new GeoIPService();

  it('should resolve Nigerian MTN IP with accurate city and ASN', async () => {
    const profile = await geo.resolve('197.210.64.12');

    expect(profile.country).toBe('Nigeria');
    expect(profile.countryCode).toBe('NG');
    expect(profile.city).toBe('Ikeja');
    expect(profile.region).toBe('Lagos');
    expect(profile.asn).toBe('AS29465');
    expect(profile.isp).toContain('MTN');
    expect(profile.latitude).toBeCloseTo(6.5965, 1);
    expect(profile.longitude).toBeCloseTo(3.3421, 1);
    expect(profile.isProxyOrVpn).toBe(false);
  });

  it('should resolve Nigerian MainOne / NOUN Abuja IP with accurate metadata', async () => {
    const profile = await geo.resolve('102.89.23.45');

    expect(profile.country).toBe('Nigeria');
    expect(profile.region).toContain('Abuja');
    expect(profile.asn).toBe('AS37075');
    expect(profile.isp).toContain('MainOne');
  });

  it('should identify Tor Exit Nodes and flag proxy/VPN risk', async () => {
    const profile = await geo.resolve('185.220.101.5');

    expect(profile.country).toBe('Germany');
    expect(profile.isTorExitNode).toBe(true);
    expect(profile.isProxyOrVpn).toBe(true);
    expect(profile.threatRiskScore).toBeGreaterThanOrEqual(90);
  });

  it('should handle local and private IP addresses cleanly', async () => {
    const profile = await geo.resolve('127.0.0.1');

    expect(profile.country).toBe('Nigeria');
    expect(profile.city).toContain('NOUN');
    expect(profile.isProxyOrVpn).toBe(false);
  });
});
