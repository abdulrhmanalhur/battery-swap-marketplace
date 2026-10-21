import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export class Denied extends Error {
  constructor(public readonly status: number, message: string) { super(message); }
}
export type Banner = Readonly<{ id: string; text: string; version: number; language: "ar" | "en"; enabled: boolean }>;
export type Requester = Readonly<{ client: string; subject: string; store: string; environment: string }>;
export type OwnerSession = Readonly<{ uid: string; sessionId: string; reauthenticatedAt: number; expiresAt: number }>;
export type Plan = Readonly<{
  id: string; command: "banner_text.edit_text.v1"; store: string; environment: string;
  client: string; subject: string; target: string; version: number; before: string;
  after: string; language: "ar" | "en"; enabled: boolean; issuedAt: number; expiresAt: number; digest: string;
}>;
export type Outcome = Readonly<{ state: "pending" | "reserved" | "committed" | "cancelled" | "blocked"; plan: Plan; reservation?: string; owner?: string; receiptWins?: boolean }>;
export interface Repository {
  readBanner(id: string): Promise<Banner | null>;
  save(plan: Plan): Promise<void>;
  get(id: string): Promise<Outcome | null>;
  reserve(plan: Plan, owner: string, now: number): Promise<string>;
  cancel(plan: Plan, owner: string, now: number): Promise<void>;
  ensureTargetAvailable(target: string, store: string, environment: string): Promise<void>;
  fence(plan: Plan, reservation: string, owner: string, now: number): Promise<"blocked" | "committed">;
  // Implementations MUST atomically CAS text+version, persist final audit receipt,
  // and transition this exact reservation to committed. No outside side effects.
  commit(plan: Plan, reservation: string, owner: string, now: number): Promise<void>;
}
export interface Authority {
  requester(request: Request): Promise<Requester>; // verified machine identity, never body fields
  owner(request: Request): Promise<OwnerSession>; // independent cookie auth; no MCP bearer acceptance
}
export function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join("|") !== [...keys].sort().join("|")) throw new Denied(400, "Unsupported request shape");
}
export function fingerprint(plan: Omit<Plan, "digest"> | Plan): string {
  // Explicit ordered tuple; include command, store/env and requester identity.
  return createHash("sha256").update(JSON.stringify([plan.id, plan.command, plan.store,
    plan.environment, plan.client, plan.subject, plan.target, plan.version, plan.before,
    plan.after, plan.language, plan.enabled, plan.issuedAt, plan.expiresAt])).digest("hex");
}
export class Csrf {
  constructor(private readonly secret: Buffer) {
    if (secret.length < 32) throw new Error("CSRF secret unconfigured");
  }
  issue(session: string, plan: Plan, purpose = "preview"): string {
    return createHmac("sha256", this.secret).update(JSON.stringify([purpose, session, plan.id, plan.digest, plan.expiresAt])).digest("hex");
  }
  verify(value: unknown, session: string, plan: Plan, purpose = "preview"): void {
    if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value) ||
        !timingSafeEqual(Buffer.from(value, "hex"), Buffer.from(this.issue(session, plan, purpose), "hex"))) throw new Denied(403, "Invalid CSRF proof");
  }
}
export class BannerEditService {
  constructor(readonly repository: Repository, readonly authority: Authority,
    readonly csrf: Csrf, readonly config: Readonly<{ ownerUid: string; origin: string; store: string; environment: string }>,
    readonly clock: () => number = Date.now, readonly invalidateSiteContent?: () => Promise<void>) {
    if (!config.ownerUid || !config.store || !config.environment || new URL(config.origin).origin !== config.origin)
      throw new Error("Independent owner/store/origin configuration required");
  }
  private now(): number {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0) throw new Denied(503, "Clock unavailable");
    return now;
  }
  private requesterIdentity(p: Requester): void {
    if (!p.client || !p.subject || p.store !== this.config.store || p.environment !== this.config.environment)
      throw new Denied(403, "Requester namespace denied");
  }
  private async owner(request: Request): Promise<OwnerSession> {
    // Do not let machine bearer authorization reach a browser approval boundary.
    if (request.headers.has("authorization")) throw new Denied(403, "Browser owner session required");
    const session = await this.authority.owner(request);
    const now = this.now();
    if (session.uid !== this.config.ownerUid || !session.sessionId ||
        !Number.isSafeInteger(session.expiresAt) || !Number.isSafeInteger(session.reauthenticatedAt) ||
        now >= session.expiresAt || session.reauthenticatedAt > now || now - session.reauthenticatedAt > 180_000)
      throw new Denied(403, "Fresh independent owner authentication required");
    return session;
  }
  private async pending(id: string): Promise<Outcome> {
    if (!/^[a-f0-9-]{36}$/.test(id)) throw new Denied(404, "Preview not found");
    const outcome = await this.repository.get(id);
    if (!outcome || outcome.plan.digest !== fingerprint(outcome.plan)) throw new Denied(404, "Preview not found");
    const p = outcome.plan;
    if (p.store !== this.config.store || p.environment !== this.config.environment || p.command !== "banner_text.edit_text.v1")
      throw new Denied(403, "Preview namespace denied");
    if (outcome.state !== "pending") throw new Denied(409, "Preview used; check outcome before further action");
    if (this.now() < p.issuedAt || this.now() >= p.expiresAt) throw new Denied(409, "Preview expired or clock invalid");
    return outcome;
  }
  async propose(request: Request, body: unknown): Promise<Plan> {
    const principal = await this.authority.requester(request);
    this.requesterIdentity(principal);
    exact(body, ["id", "expectedVersion", "text"]);
    if (typeof body.id !== "string" || !/^[a-f\d]{24}$/i.test(body.id) ||
        !Number.isSafeInteger(body.expectedVersion) || (body.expectedVersion as number) < 0 ||
        typeof body.text !== "string" || [...body.text].length > 200) throw new Denied(400, "Invalid existing-banner edit");
    const after = body.text.normalize("NFC").trim();
    if (!after || [...after].length > 200 || /[\p{Cc}\p{Cf}]/u.test(after)) throw new Denied(400, "Invalid plain banner text");
    await this.repository.ensureTargetAvailable(body.id.toLowerCase(), this.config.store, this.config.environment);
    const banner = await this.repository.readBanner(body.id.toLowerCase());
    if (!banner || banner.version !== body.expectedVersion || !Number.isSafeInteger(banner.version)) throw new Denied(409, "Missing or stale banner");
    if (banner.text === after) throw new Denied(400, "No text change");
    const now = this.now();
    const raw = { id: randomUUID(), command: "banner_text.edit_text.v1" as const,
      store: this.config.store, environment: this.config.environment, client: principal.client,
      subject: principal.subject, target: banner.id, version: banner.version, before: banner.text,
      after, language: banner.language, enabled: banner.enabled, issuedAt: now, expiresAt: now + 300_000 };
    const plan = Object.freeze({ ...raw, digest: fingerprint(raw) });
    await this.repository.save(plan);
    return plan;
  }
  async review(request: Request, id: string) {
    const session = await this.owner(request);
    const { plan } = await this.pending(id);
    return { plan, csrf: this.csrf.issue(session.sessionId, plan) };
  }
  async approve(request: Request, id: string, body: unknown) {
    if (request.headers.get("origin") !== this.config.origin || request.headers.get("sec-fetch-site") !== "same-origin")
      throw new Denied(403, "Same-origin browser approval required");
    const session = await this.owner(request);
    exact(body, ["digest", "csrf"]);
    const { plan } = await this.pending(id);
    if (body.digest !== plan.digest) throw new Denied(409, "Exact preview digest required");
    this.csrf.verify(body.csrf, session.sessionId, plan);
    const reservation = await this.repository.reserve(plan, session.uid, this.now());
    try {
      await this.repository.commit(plan, reservation, session.uid, this.now());
    } catch {
      // A committed transaction may have lost its acknowledgement. Never blind retry.
      return { state: "needs_reconciliation" as const, id: plan.id };
    }
    let refresh = "not_configured";
    if (this.invalidateSiteContent) {
      try { await this.invalidateSiteContent(); refresh = "requested"; }
      catch { refresh = "deferred"; } // Never replay an edit to repair cache refresh.
    }
    return { state: "committed" as const, id: plan.id, refresh };
  }
  async cancel(request: Request, id: string, body: unknown) {
    if (request.headers.get("origin") !== this.config.origin || request.headers.get("sec-fetch-site") !== "same-origin")
      throw new Denied(403, "Same-origin browser cancellation required");
    const session = await this.owner(request);
    exact(body, ["digest", "csrf"]);
    const { plan } = await this.pending(id);
    if (body.digest !== plan.digest) throw new Denied(409, "Exact preview digest required");
    this.csrf.verify(body.csrf, session.sessionId, plan);
    await this.repository.cancel(plan, session.uid, this.now());
    return { id: plan.id, state: "cancelled" as const };
  }
  async status(request: Request, id: string) {
    const principal = await this.authority.requester(request);
    this.requesterIdentity(principal);
    const result = await this.repository.get(id);
    if (!result || result.plan.client !== principal.client || result.plan.subject !== principal.subject ||
        result.plan.store !== this.config.store || result.plan.environment !== this.config.environment ||
        result.plan.digest !== fingerprint(result.plan) || result.plan.command !== "banner_text.edit_text.v1")
      throw new Denied(404, "Preview not found");
    return { id, state: result.state === "reserved" ? "needs_reconciliation" : result.state };
  }
  async ownerStatus(request: Request, id: string) {
    await this.owner(request);
    const result = await this.repository.get(id);
    if (!result || result.plan.digest !== fingerprint(result.plan) || result.plan.store !== this.config.store ||
        result.plan.environment !== this.config.environment) throw new Denied(404, "Preview not found");
    return { id, state: result.state === "reserved" ? "needs_reconciliation" : result.state };
  }
  private async recoveryOutcome(id: string): Promise<Outcome> {
    const outcome = await this.repository.get(id); // Repository must verify final receipt in one consistent snapshot.
    if (!outcome || outcome.plan.digest !== fingerprint(outcome.plan) || outcome.plan.store !== this.config.store ||
        outcome.plan.environment !== this.config.environment || outcome.plan.command !== "banner_text.edit_text.v1")
      throw new Denied(404, "Preview not found");
    return outcome;
  }
  async recoveryReview(request: Request, id: string) {
    const session = await this.owner(request);
    const outcome = await this.recoveryOutcome(id);
    if (outcome.state !== "reserved") return { id, state: outcome.state, canFence: false };
    if (!outcome.reservation || outcome.owner !== session.uid) throw new Denied(409, "Reservation identity mismatch");
    return { id, state: "reserved" as const, canFence: true, plan: outcome.plan, reservation: outcome.reservation,
      csrf: this.csrf.issue(session.sessionId, outcome.plan, "fence_reserved_plan") };
  }
  async recover(request: Request, id: string, body: unknown) {
    if (request.headers.get("origin") !== this.config.origin || request.headers.get("sec-fetch-site") !== "same-origin")
      throw new Denied(403, "Same-origin browser recovery required");
    const session = await this.owner(request);
    exact(body, ["digest", "reservation", "csrf"]);
    const outcome = await this.recoveryOutcome(id);
    if (outcome.state === "committed") return { id, state: "committed" as const, fenced: false };
    if (outcome.state !== "reserved" || outcome.owner !== session.uid || !outcome.reservation ||
        body.reservation !== outcome.reservation || body.digest !== outcome.plan.digest)
      throw new Denied(409, "Only the exact unresolved reservation can be fenced");
    this.csrf.verify(body.csrf, session.sessionId, outcome.plan, "fence_reserved_plan");
    try {
      const state = await this.repository.fence(outcome.plan, outcome.reservation, session.uid, this.now());
      return { id, state, fenced: state === "blocked" };
    } catch {
      return { id, state: "needs_reconciliation" as const, fenced: false };
    }
  }
}
