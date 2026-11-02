import { Router, Request, Response } from 'express';
import { zeekEngine } from '../zeek/zeek-engine';
import { getWATFormattedDate } from '../db/database';

export const zeekRouter = Router();

/**
 * GET /api/soc/zeek/connections
 * Filtered connection telemetry by time window, IP, port, protocol, service, systemId, or UID
 */
zeekRouter.get('/connections', async (req: Request, res: Response) => {
  const { ip, port, proto, service, systemId, uid, verdict, limit } = req.query;
  const connections = await zeekEngine.getConnections({
    ip: ip ? String(ip) : undefined,
    port: port ? parseInt(String(port), 10) : undefined,
    proto: proto ? String(proto) : undefined,
    service: service ? String(service) : undefined,
    systemId: systemId ? String(systemId) : undefined,
    uid: uid ? String(uid) : undefined,
    verdict: verdict ? String(verdict) : undefined,
    limit: limit ? parseInt(String(limit), 10) : 120,
  });

  res.json({
    connections,
    total: connections.length,
    fetchedAtWat: getWATFormattedDate(),
  });
});

/**
 * GET /api/soc/zeek/timeline/:uid
 * Full transaction trace reconstruction for any given Zeek UID across DNS, HTTP, SSL, Files, and Notices
 */
zeekRouter.get('/timeline/:uid', async (req: Request, res: Response) => {
  const { uid } = req.params;
  const timeline = await zeekEngine.getTimelineByUid(uid);
  res.json(timeline);
});

/**
 * GET /api/soc/zeek/notices
 * Feed of security-significant triggers from notice.log mapped to severity classes
 */
zeekRouter.get('/notices', async (req: Request, res: Response) => {
  const { severity, systemId } = req.query;
  const notices = await zeekEngine.getNotices(
    severity ? String(severity) : undefined,
    systemId ? String(systemId) : undefined
  );
  res.json({
    notices,
    total: notices.length,
    fetchedAtWat: getWATFormattedDate(),
  });
});

/**
 * GET /api/soc/zeek/metrics/eps
 * Event-per-second and bandwidth telemetry for real-time sensor health widgets
 */
zeekRouter.get('/metrics/eps', async (_req: Request, res: Response) => {
  const metrics = await zeekEngine.getSensorEpsMetrics();
  res.json(metrics);
});

/**
 * GET /api/soc/zeek/intel
 * Threat Intel & Hash Watch: files.log (MD5/SHA256 hashes) & ssl.log (JA3/JA4 + SNIs)
 */
zeekRouter.get('/intel', async (_req: Request, res: Response) => {
  const intel = await zeekEngine.getThreatIntelAndHashes();
  res.json(intel);
});

/**
 * POST /api/soc/zeek/ingest
 * Ingestion endpoint for Fluent Bit / Vector / Logstash shipping Zeek JSON logs
 */
zeekRouter.post('/ingest', (req: Request, res: Response) => {
  const payload = Array.isArray(req.body) ? req.body : [req.body];
  let ingested = 0;

  for (const record of payload) {
    if (!record || !record.uid) continue;
    const ts = record.ts || new Date().toISOString();
    const ts_wat = getWATFormattedDate(new Date(ts));

    if (record.conn_state || record.orig_bytes !== undefined) {
      zeekEngine.ingestConn({ ...record, ts, ts_wat, system_id: record.system_id || 'NOUN-HRMS', verdict: record.verdict || 'ALLOWED_HEALTHY' });
      ingested++;
    } else if (record.qtype_name || record.query) {
      zeekEngine.ingestDns({ ...record, ts, ts_wat });
      ingested++;
    } else if (record.ja3 || record.cipher || record.server_name) {
      zeekEngine.ingestSsl({ ...record, ts, ts_wat });
      ingested++;
    } else if (record.uri || record.method) {
      zeekEngine.ingestHttp({ ...record, ts, ts_wat });
      ingested++;
    } else if (record.fuid || record.sha256) {
      zeekEngine.ingestFile({ ...record, ts, ts_wat });
      ingested++;
    } else if (record.note || record.msg) {
      zeekEngine.ingestNotice({ ...record, ts, ts_wat, severity: record.severity || 'MEDIUM', system_id: record.system_id || 'NOUN-HRMS' });
      ingested++;
    }
  }

  res.status(202).json({ status: 'ACCEPTED', ingested });
});
