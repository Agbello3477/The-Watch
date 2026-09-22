import { Router, Request, Response } from 'express';
import { pdfReportGenerator, csvReportGenerator } from '../reports/pdf-generator';

export const reportsRouter = Router();

/**
 * Downloads Executive Forensic Security Audit PDF Report
 */
reportsRouter.get('/pdf', async (req: Request, res: Response) => {
  try {
    const systemId = req.query.systemId as string;
    const pdfBuffer = await pdfReportGenerator.generatePdf({
      systemId,
      reportTitle: systemId
        ? `FORENSIC SECURITY AUDIT: ${systemId.toUpperCase()}`
        : 'THE WATCH // INSTITUTIONAL SECURITY & OBSERVABILITY AUDIT',
    });

    const filename = `TheWatch_Forensic_Audit_${systemId || 'AllSystems'}_${Date.now()}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.end(pdfBuffer);
  } catch (err: any) {
    console.error('[Reports] PDF generation error:', err);
    res.status(500).json({ error: 'FAILED_TO_GENERATE_PDF', message: err.message });
  }
});

/**
 * Downloads Raw CSV Forensic Log
 */
reportsRouter.get('/csv', async (req: Request, res: Response) => {
  try {
    const systemId = req.query.systemId as string;
    const csvContent = await csvReportGenerator.generateCsv(systemId);
    const filename = `TheWatch_Audit_Logs_${systemId || 'AllSystems'}_${Date.now()}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csvContent);
  } catch (err: any) {
    console.error('[Reports] CSV generation error:', err);
    res.status(500).json({ error: 'FAILED_TO_GENERATE_CSV', message: err.message });
  }
});
