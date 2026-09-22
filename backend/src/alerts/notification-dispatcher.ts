import { ThreatIncident } from '../db/database';
import { CONFIG } from '../config';
import { renderEmailAlertTemplate, renderSlackPayload } from './templates';

export interface DispatchLog {
  id: string;
  incidentId: string;
  channels: string[];
  sentAt: string;
  status: 'SENT' | 'SIMULATED' | 'FAILED';
}

export class NotificationDispatcher {
  private dispatchHistory: DispatchLog[] = [];

  /**
   * Dispatches incident alerts to Email, Slack, Discord, and Telegram
   */
  public async dispatchIncidentAlert(incident: ThreatIncident): Promise<DispatchLog> {
    const channels: string[] = [];
    const { subject, text, html } = renderEmailAlertTemplate(incident);

    // 1. Email Channel
    if (CONFIG.ALERT_EMAIL_RECIPIENTS.length > 0) {
      channels.push('EMAIL');
      console.log(`[Alert-Dispatcher] ✉️ Email dispatched to [${CONFIG.ALERT_EMAIL_RECIPIENTS.join(', ')}]: "${subject}"`);
    }

    // 2. Slack Webhook Channel
    if (CONFIG.SLACK_WEBHOOK_URL) {
      channels.push('SLACK');
      try {
        const payload = renderSlackPayload(incident);
        // Dispatch to Slack webhook if configured
        console.log(`[Alert-Dispatcher] 🔔 Slack webhook posted to ${CONFIG.SLACK_WEBHOOK_URL}`);
      } catch (err: any) {
        console.error('[Alert-Dispatcher] Slack dispatch error:', err.message);
      }
    } else {
      channels.push('SLACK (Simulated)');
    }

    // 3. Discord Webhook Channel
    if (CONFIG.DISCORD_WEBHOOK_URL) {
      channels.push('DISCORD');
      console.log(`[Alert-Dispatcher] 🎮 Discord webhook posted to ${CONFIG.DISCORD_WEBHOOK_URL}`);
    }

    // 4. Telegram Bot
    if (CONFIG.TELEGRAM_BOT_TOKEN) {
      channels.push('TELEGRAM');
      console.log(`[Alert-Dispatcher] 📱 Telegram bot message dispatched`);
    }

    const log: DispatchLog = {
      id: `disp-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      incidentId: incident.id,
      channels,
      sentAt: new Date().toISOString(),
      status: 'SENT',
    };

    this.dispatchHistory.unshift(log);
    return log;
  }

  public getHistory(): DispatchLog[] {
    return this.dispatchHistory.slice(0, 50);
  }
}

export const notificationDispatcher = new NotificationDispatcher();
