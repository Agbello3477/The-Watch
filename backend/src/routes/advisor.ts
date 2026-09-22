import { Router, Request, Response } from 'express';
import { advisorService } from '../advisor/advisor-service';
import { db } from '../db/database';

export const advisorRouter = Router();

/**
 * Returns self-healing diagnostics and remediation blueprints
 */
advisorRouter.get('/recommendations', async (req: Request, res: Response) => {
  const systemId = req.query.systemId as string;
  const incidents = await db.getIncidents({ systemId, limit: 20 });
  const rules = advisorService.getAllRules();

  // Find active rules triggered by current unresolved incidents
  const activeDiagnoses = incidents
    .filter((inc) => inc.status === 'UNRESOLVED')
    .map((inc) => {
      const match = rules.find((r) => r.patternName === inc.threat_classification || inc.incident_type.includes(r.id));
      return {
        incidentId: inc.id,
        systemId: inc.system_id,
        threatClassification: inc.threat_classification,
        severity: inc.severity,
        targetEndpoint: inc.target_endpoint,
        createdAtWat: inc.created_at_wat,
        diagnosis: match || {
          id: `CUSTOM-${inc.id}`,
          patternName: inc.threat_classification,
          incidentSummary: inc.remediation_summary || 'Threat detected on endpoint.',
          suspectedRootCause: 'External anomalous payload or system degradation.',
          severity: inc.severity,
          mitigationBlueprint: inc.mitigation_blueprint,
          codePatch: inc.mitigation_blueprint,
          infrastructureFix: 'Apply WAF or application firewall filter.',
          recommendedAction: 'Review incident payload and deploy mitigation rule.',
        },
      };
    });

  res.json({
    activeDiagnosesCount: activeDiagnoses.length,
    activeDiagnoses,
    allCatalogRules: rules,
  });
});
