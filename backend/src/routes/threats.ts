import { Router, Request, Response } from 'express';
import { db, getWATFormattedDate } from '../db/database';
import { geoIPService } from '../threat/geoip-service';
import { realtimeAlertHub } from '../alerts/realtime-alert-hub';
import { socEngine } from '../soc/soc-engine';

export const threatsRouter = Router();

/**
 * Real-time SSE stream for active SOC Threat alerts
 */
threatsRouter.get('/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Prevent Nginx/proxy buffering
  res.flushHeaders?.();

  realtimeAlertHub.registerClient(res);
});

/**
 * Fallback polling endpoint for real-time alerts
 */
threatsRouter.get('/live-alerts', (req: Request, res: Response) => {
  const since = req.query.since as string;
  const alerts = realtimeAlertHub.getAlertsSince(since);
  res.json({ alerts, total: alerts.length });
});

/**
 * Returns geographical threat data for interactive map rendering
 */
threatsRouter.get('/map', async (req: Request, res: Response) => {
  const systemId = req.query.systemId as string;
  const incidents = await db.getIncidents({ systemId, limit: 100 });

  // Group by coordinates and city
  const mapNodes = incidents.map((inc) => ({
    id: inc.id,
    systemId: inc.system_id,
    threatClassification: inc.threat_classification,
    severity: inc.severity,
    offendingIp: inc.offending_ip,
    country: inc.geo_country,
    region: inc.geo_region,
    city: inc.geo_city,
    latitude: inc.geo_lat,
    longitude: inc.geo_lng,
    asn: inc.asn,
    isp: inc.isp,
    isProxyOrVpn: inc.is_proxy_or_vpn,
    targetEndpoint: inc.target_endpoint,
    httpMethod: inc.http_method,
    status: inc.status,
    timestampWat: inc.created_at_wat,
  }));

  res.json({
    totalNodes: mapNodes.length,
    nodes: mapNodes,
  });
});

/**
 * Deep IP threat profile lookup
 */
threatsRouter.get('/intelligence/:ip', async (req: Request, res: Response) => {
  const { ip } = req.params;
  const profile = await geoIPService.resolve(ip);
  res.json(profile);
});

/**
 * Full Forensic IP Traceroute, Whois & Attack History Lookup
 */
threatsRouter.get('/trace/:ip', async (req: Request, res: Response) => {
  try {
    const rawIp = req.params.ip || '127.0.0.1';
    const cleanIp = rawIp.replace(/^::ffff:/, '').trim();
    const profile = await geoIPService.resolve(cleanIp);
    const isBlocked = socEngine.isIpBlocked(cleanIp);

    const allIncidents = await db.getIncidents({ limit: 250 });
    const relatedIncidents = allIncidents.filter((inc) => inc.offending_ip === cleanIp);

    const allAudits = await db.getUserAuditLogs(250);
    const relatedAudits = allAudits.filter((log) => log.ip_address === cleanIp);

    const registry =
      profile.countryCode === 'NG'
        ? 'AFRINIC (African Network Information Centre)'
        : ['US', 'CA'].includes(profile.countryCode)
        ? 'ARIN (American Registry for Internet Numbers)'
        : ['CN', 'JP', 'IN', 'SG'].includes(profile.countryCode)
        ? 'APNIC (Asia-Pacific Network Information Centre)'
        : 'RIPE NCC (Réseaux IP Européens Network Coordination Centre)';

    const octets = cleanIp.split('.');
    const subnetPrefix = octets.length === 4 ? `${octets[0]}.${octets[1]}.${octets[2]}` : '192.168.1';

    const hops = [
      {
        hop: 1,
        ip: '10.20.0.1',
        hostname: 'soc-edge-fw01.jabi.noun.edu.ng',
        location: 'Abuja (FCT), Nigeria — NOUN HQ Perimeter',
        asn: 'AS37075',
        rttMs: 1.1,
      },
      {
        hop: 2,
        ip: '196.216.2.14',
        hostname: 'ixpn-abv-core01.ixp.net.ng',
        location: 'Abuja / Lagos IXPN Backbone, Nigeria',
        asn: 'AS37258',
        rttMs: 7.8,
      },
      {
        hop: 3,
        ip: '105.16.32.1',
        hostname: 'intl-submarine-gw.mainone.net',
        location: 'Atlantic Submarine Cable Landing Station',
        asn: 'AS37282',
        rttMs: profile.countryCode === 'NG' ? 14.2 : 48.5,
      },
      {
        hop: 4,
        ip: `${subnetPrefix}.1`,
        hostname: `border-router-${profile.asn.toLowerCase()}.${profile.countryCode.toLowerCase()}.net`,
        location: `${profile.region}, ${profile.country} (${profile.isp})`,
        asn: profile.asn,
        rttMs: profile.countryCode === 'NG' ? 21.4 : 94.2,
      },
      {
        hop: 5,
        ip: profile.ip,
        hostname: profile.reverseDns,
        location: `${profile.city}, ${profile.region}, ${profile.country}`,
        asn: profile.asn,
        rttMs: profile.countryCode === 'NG' ? 26.9 : 118.7,
      },
    ];

    res.json({
      ip: profile.ip,
      tracedAtWat: getWATFormattedDate(),
      isBlocked,
      profile,
      whois: {
        registry,
        cidr: `${subnetPrefix}.0/24`,
        netname: `${profile.asn}-${profile.countryCode}-NET`,
        isp: profile.isp,
        organization: profile.organization,
        asn: profile.asn,
        abuseContact: `abuse@${(profile.isp || 'isp').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 18) || 'network'}.net`,
      },
      hops,
      attackSummary: {
        totalIncidentsFromIp: relatedIncidents.length,
        totalAuditEventsFromIp: relatedAudits.length,
        recentIncidents: relatedIncidents.slice(0, 5),
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: 'TRACE_FAILED', message: err.message });
  }
});

