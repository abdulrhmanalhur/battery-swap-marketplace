import { createHash } from "node:crypto";
import type { ClientSession, Connection, Model } from "mongoose";
import { Denied, fingerprint, type Banner, type Outcome, type Plan, type Repository } from "./core";

type BannerRow = { _id: unknown; text: string; __v: number; language: "ar" | "en"; enabled: boolean };
export type LedgerRow = { _id: string; plan: Plan; state: "pending" | "reserved" | "committed" | "cancelled" | "blocked"; reservation?: string; owner?: string; activeTarget?: string; blockedAt?: number; blockedBy?: string };
export type AuditRow = { _id: string; digest: string; reservation: string; owner: string; client: string; subject: string; target: string; before: string; after: string; version: number; committedAt: number };
const transactionOptions = { readPreference: "primary" as const, readConcern: { level: "snapshot" as const }, writeConcern: { w: "majority" as const, j: true } };
const targetKey = (target: string, store: string, environment: string) => createHash("sha256").update(JSON.stringify([store, environment, target])).digest("hex");

export function checkedOutcome(held: LedgerRow | null, receipt: AuditRow | null): Outcome | null {
  if (!held) { if (receipt) throw new Denied(503, "Receipt without preview; outcome ambiguous"); return null; }
  const p = held.plan;
  if (held._id !== p.id || p.digest !== fingerprint(p)) throw new Denied(503, "Stored preview integrity failure");
  if (receipt) {
    if (receipt._id !== p.id || receipt.digest !== p.digest || receipt.reservation !== held.reservation || !held.reservation ||
        receipt.owner !== held.owner || !held.owner || receipt.client !== p.client || receipt.subject !== p.subject ||
        receipt.target !== p.target || receipt.before !== p.before || receipt.after !== p.after ||
        receipt.version !== p.version + 1 || !Number.isSafeInteger(receipt.committedAt) ||
        receipt.committedAt < p.issuedAt || receipt.committedAt >= p.expiresAt)
      throw new Denied(503, "Receipt binding inconsistent; outcome ambiguous");
    // A verified durable FINAL receipt wins. Never fence or repeat this edit.
    return { state: "committed", plan: p, owner: held.owner, reservation: held.reservation, receiptWins: held.state !== "committed" };
  }
  if (held.state === "committed") throw new Denied(503, "Committed outcome lacks final receipt");
  return { state: held.state, plan: p, owner: held.owner, reservation: held.reservation };
}

// Models/connection must be explicitly supplied by trusted application wiring.
// No schema compilation, index creation, connection, or credentials on import.
export class MongooseBannerRepository implements Repository {
  constructor(private readonly connection: Connection, private readonly banners: Model<BannerRow>,
    private readonly ledger: Model<LedgerRow>, private readonly audit: Model<AuditRow>, expectedDatabase: string) {
    if (!expectedDatabase || connection.name !== expectedDatabase ||
        [banners, ledger, audit].some(model => model.db !== connection) ||
        banners.collection.name !== "bannertexts" || ledger.collection.name !== "approved_edit_previews" ||
        audit.collection.name !== "approved_edit_audit") throw new Error("Fixed application model namespace required");
  }
  async readBanner(id: string): Promise<Banner | null> {
    const row = await this.banners.findById(id).read("primary").readConcern("majority").select("text __v language enabled").lean();
    if (!row || !Number.isSafeInteger(row.__v) || row.__v < 0) return null;
    return { id: String(row._id), text: row.text, version: row.__v, language: row.language, enabled: row.enabled };
  }
  async save(plan: Plan) { await this.ledger.create([{ _id: plan.id, plan, state: "pending" }], { writeConcern: { w: "majority", j: true } }); }
  async get(id: string): Promise<Outcome | null> {
    return this.connection.transaction(async (session: ClientSession) => {
      const held = await this.ledger.findById(id).session(session).lean();
      const receipt = await this.audit.findById(id).session(session).lean();
      return checkedOutcome(held, receipt);
    }, transactionOptions);
  }
  async ensureTargetAvailable(target: string, store: string, environment: string): Promise<void> {
    const held = await this.ledger.findOne({ state: "reserved", activeTarget: targetKey(target, store, environment) })
      .read("primary").readConcern("majority").lean();
    if (held) throw new Denied(409, "Resolve the existing reservation before a fresh preview");
  }
  async reserve(plan: Plan, owner: string, now: number): Promise<string> {
    if (plan.digest !== fingerprint(plan)) throw new Denied(409, "Tampered preview");
    // Required partial unique index closes the race between independent previews.
    const indexes = await this.ledger.collection.indexes();
    if (!indexes.some(index => index.name === "unique_reserved_target" && index.unique === true &&
        JSON.stringify(index.key) === JSON.stringify({ activeTarget: 1 }) &&
        JSON.stringify(index.partialFilterExpression) === JSON.stringify({ state: "reserved" })))
      throw new Denied(503, "Reserved-target uniqueness index not provisioned");
    const { randomUUID } = await import("node:crypto");
    const reservation = randomUUID();
    const result = await this.ledger.updateOne({ _id: plan.id, state: "pending", "plan.digest": plan.digest,
      "plan.expiresAt": { $gt: now } }, { $set: { state: "reserved", owner, reservation,
        activeTarget: targetKey(plan.target, plan.store, plan.environment) } },
    { upsert: false, writeConcern: { w: "majority", j: true } });
    if (result.modifiedCount !== 1) throw new Denied(409, "Preview used or expired");
    return reservation;
  }
  async cancel(plan: Plan, owner: string, now: number): Promise<void> {
    if (plan.digest !== fingerprint(plan)) throw new Denied(409, "Tampered preview");
    const result = await this.ledger.updateOne({ _id: plan.id, state: "pending", "plan.digest": plan.digest,
      "plan.expiresAt": { $gt: now } }, { $set: { state: "cancelled", owner } },
    { upsert: false, writeConcern: { w: "majority", j: true } });
    if (result.modifiedCount !== 1) throw new Denied(409, "Preview used or expired");
  }
  async commit(plan: Plan, reservation: string, owner: string, now: number): Promise<void> {
    if (plan.digest !== fingerprint(plan)) throw new Denied(409, "Tampered preview");
    await this.connection.transaction(async (session: ClientSession) => {
      const held = await this.ledger.findOne({ _id: plan.id, state: "reserved", reservation, owner }).session(session).lean();
      const receipt = await this.audit.findById(plan.id).session(session).lean();
      if (checkedOutcome(held, receipt)?.state === "committed") throw new Denied(409, "Already committed; never replay");
      if (!held || held.plan.digest !== fingerprint(held.plan) || held.plan.digest !== plan.digest ||
          now >= held.plan.expiresAt || Date.now() >= held.plan.expiresAt) throw new Denied(409, "Reservation invalid or expired");
      const authoritative = held.plan;
      const changed = await this.banners.updateOne({ _id: authoritative.target, __v: authoritative.version, text: authoritative.before,
        language: authoritative.language, enabled: authoritative.enabled }, { $set: { text: authoritative.after }, $inc: { __v: 1 } },
      { session, upsert: false, runValidators: true });
      if (changed.modifiedCount !== 1) throw new Denied(409, "Banner changed; fresh preview required");
      const finalizedAt = Date.now();
      if (finalizedAt < authoritative.issuedAt || finalizedAt >= authoritative.expiresAt) throw new Denied(409, "Preview expired before finalization");
      await this.audit.create([{ _id: authoritative.id, digest: authoritative.digest, reservation, owner, client: authoritative.client, subject: authoritative.subject,
        target: authoritative.target, before: authoritative.before, after: authoritative.after, version: authoritative.version + 1, committedAt: finalizedAt }], { session });
      if (Date.now() >= authoritative.expiresAt) throw new Denied(409, "Preview expired before final state transition");
      const done = await this.ledger.updateOne({ _id: plan.id, state: "reserved", reservation, owner },
        { $set: { state: "committed" } }, { session, upsert: false });
      if (done.modifiedCount !== 1) throw new Denied(409, "Reservation lost");
    }, transactionOptions);
  }
  async fence(plan: Plan, reservation: string, owner: string, now: number): Promise<"blocked" | "committed"> {
    if (plan.digest !== fingerprint(plan)) throw new Denied(409, "Tampered recovery preview");
    return this.connection.transaction(async (session: ClientSession) => {
      const held = await this.ledger.findById(plan.id).session(session).lean();
      const receipt = await this.audit.findById(plan.id).session(session).lean();
      const outcome = checkedOutcome(held, receipt);
      if (outcome?.state === "committed") return "committed" as const;
      if (!held || held.state !== "reserved" || held.reservation !== reservation || held.owner !== owner || held.plan.digest !== plan.digest)
        throw new Denied(409, "Exact reservation no longer available for fencing");
      const result = await this.ledger.updateOne({ _id: plan.id, state: "reserved", reservation, owner, "plan.digest": plan.digest },
        { $set: { state: "blocked", blockedAt: now, blockedBy: owner } }, { session, upsert: false });
      if (result.modifiedCount !== 1) throw new Denied(409, "Recovery lost race; inspect outcome");
      // No business operation, no success receipt and no reset to pending here.
      // Original worker's final reserved→committed CAS conflicts if it read an older snapshot.
      return "blocked" as const;
    }, transactionOptions);
  }
}
