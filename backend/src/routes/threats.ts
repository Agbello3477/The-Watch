import { Router, Request, Response } from 'express';
import { db } from '../db/database';
import { geoIPService } from '../threat/geoip-service';

export const threatsRouter = Router();

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
