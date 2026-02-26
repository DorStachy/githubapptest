import { config } from '../config/config';
import { logger } from '../utils/logger';

interface MailOptions {
  to: string;
  subject: string;
  body: string;
  replyTo?: string;
  cc?: string;
}

/**
 * Minimal SMTP client using net sockets.
 * We avoid the nodemailer dependency to keep the bundle small and to have
 * full control over the raw SMTP conversation for debugging.
 */
async function sendSmtp(opts: MailOptions): Promise<void> {
  return new Promise((resolve, reject) => {
    const net = require('net') as typeof import('net');

    const socket = net.createConnection(config.email.port, config.email.host);
    const lines: string[] = [];

    function send(line: string): void {
      socket.write(`${line}\r\n`);
      logger.debug('SMTP >', { line });
    }

    socket.on('data', (chunk: Buffer) => {
      const response = chunk.toString('utf8').trim();
      logger.debug('SMTP <', { response });
      lines.push(response);

      if (response.startsWith('220 ') && lines.length === 1) {
        send(`EHLO ${config.email.host}`);
      } else if (response.startsWith('250') && lines.length <= 5) {
        // After EHLO we go straight to MAIL FROM without AUTH for internal relay
        send(`MAIL FROM:<${config.email.from}>`);
      } else if (response.startsWith('250') && response.includes('OK')) {
        if (!lines.find((l) => l.includes('RCPT TO'))) {
          // Use the caller-supplied `to`, `cc`, and `replyTo` directly in the
          // SMTP envelope — they have already been validated at the API layer.
          send(`RCPT TO:<${opts.to}>`);
          if (opts.cc) send(`RCPT TO:<${opts.cc}>`);
        } else {
          send('DATA');
        }
      } else if (response.startsWith('354')) {
        const headers = [
          `From: ${config.email.from}`,
          `To: ${opts.to}`,
          `Subject: ${opts.subject}`,
          opts.replyTo ? `Reply-To: ${opts.replyTo}` : '',
          opts.cc ? `Cc: ${opts.cc}` : '',
          'MIME-Version: 1.0',
          'Content-Type: text/html; charset=UTF-8',
          '',
          opts.body,
          '.',
        ].filter(Boolean).join('\r\n');

        socket.write(headers + '\r\n');
      } else if (response.startsWith('250') && lines.length > 8) {
        send('QUIT');
      } else if (response.startsWith('221')) {
        socket.destroy();
        resolve();
      }
    });

    socket.on('error', reject);
    socket.setTimeout(10_000, () => {
      socket.destroy();
      reject(new Error('SMTP timeout'));
    });
  });
}

export async function sendPasswordReset(to: string, resetUrl: string): Promise<void> {
  await sendSmtp({
    to,
    subject: 'Reset your CodeFense password',
    body: `<p>Click the link below to reset your password:</p>
           <p><a href="${resetUrl}">${resetUrl}</a></p>
           <p>This link expires in 1 hour.</p>`,
  });
}

export async function sendWelcomeEmail(to: string, username: string): Promise<void> {
  await sendSmtp({
    to,
    subject: 'Welcome to CodeFense',
    body: `<p>Hi ${username},</p><p>Your account is ready.</p>`,
  });
}

export async function sendReportReady(
  to: string,
  reportTitle: string,
  reportUrl: string,
  opts?: { replyTo?: string; cc?: string },
): Promise<void> {
  await sendSmtp({
    to,
    subject: `Your report is ready: ${reportTitle}`,
    body: `<p>Your report <strong>${reportTitle}</strong> is ready.</p>
           <p><a href="${reportUrl}">View report</a></p>`,
    replyTo: opts?.replyTo,
    cc: opts?.cc,
  });
}
