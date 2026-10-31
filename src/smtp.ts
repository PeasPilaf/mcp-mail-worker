// SMTP delivery over Cloudflare TCP sockets, via worker-mailer.

import { WorkerMailer, type EmailOptions, type WorkerMailerOptions } from "worker-mailer";
import type { Config, Mailbox } from "./config";
import type { OutgoingEmail } from "./mail";

export const SMTP_TIMEOUT_MS = 30_000;

export interface Mailer {
  /** Deliver one message. Rejects with the SMTP/transport error. */
  send(email: OutgoingEmail): Promise<void>;
  /** Connect and authenticate without sending (health check). */
  verify(): Promise<void>;
}

export type MailerFactory = (cfg: Config) => Mailer;

export function smtpOptions(cfg: Config): WorkerMailerOptions {
  const implicitTls = cfg.smtpPort === 465;
  return {
    host: cfg.smtpHost,
    port: cfg.smtpPort,
    secure: implicitTls,
    startTls: !implicitTls,
    credentials: { username: cfg.smtpUsername, password: cfg.smtpPassword },
    authType: "plain",
    socketTimeoutMs: SMTP_TIMEOUT_MS,
    responseTimeoutMs: SMTP_TIMEOUT_MS,
  };
}

const user = (m: Mailbox) => (m.name ? { name: m.name, email: m.address } : { email: m.address });

export function toEmailOptions(email: OutgoingEmail): EmailOptions {
  return {
    from: user(email.from),
    to: user(email.to),
    subject: email.subject,
    text: email.text,
    headers: email.headers,
  };
}

/** Production mailer: one SMTP connection per call, closed afterwards. */
export const smtpMailer: MailerFactory = (cfg) => ({
  async send(email) {
    const mailer = await WorkerMailer.connect(smtpOptions(cfg));
    try {
      await mailer.send(toEmailOptions(email));
    } finally {
      await mailer.close().catch(() => {});
    }
  },
  async verify() {
    const mailer = await WorkerMailer.connect(smtpOptions(cfg));
    await mailer.close();
  },
});
