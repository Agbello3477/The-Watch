import { Router, Request, Response } from 'express';
import { db } from '../db/database';

export const overviewRouter = Router();

/**
 * Platform health score, reliability index & real-time metrics
 */
overviewRouter.get('/', async (req: Request, res: Response) => {
  const systemId = req.query.systemId as string;
  const overview = await db.getSystemHealthOverview(systemId);
  res.json(overview);
});
