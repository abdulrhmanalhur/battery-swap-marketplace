import { Schema, type Connection } from "mongoose";
import type { LedgerRow, AuditRow } from "./mongooseRepository";

// Design/review only; runtime.ts never imports or calls this factory.
// autoCreate/autoIndex are disabled. Collections/indexes require separate provisioning.
export function defineApprovalModels(connection: Connection) {
  const options = { autoCreate: false, autoIndex: false, strict: "throw", versionKey: false } as const;
  if (connection.models.ApprovedEditPreview || connection.models.ApprovedEditAudit) throw new Error("Approval models already registered; review existing schemas explicitly");
  const ledger = new Schema<LedgerRow>({ _id: { type: String, required: true }, plan: { type: Schema.Types.Mixed, required: true },
    state: { type: String, enum: ["pending", "reserved", "committed", "cancelled", "blocked"], required: true },
    reservation: String, owner: String, activeTarget: String, blockedAt: Number, blockedBy: String }, { ...options, collection: "approved_edit_previews" });
  ledger.index({ activeTarget: 1 }, { name: "unique_reserved_target", unique: true, partialFilterExpression: { state: "reserved" } });
  const audit = new Schema<AuditRow>({ _id: { type: String, required: true }, digest: { type: String, required: true }, reservation: { type: String, required: true },
    owner: { type: String, required: true }, client: { type: String, required: true }, subject: { type: String, required: true },
    target: { type: String, required: true }, before: { type: String, required: true }, after: { type: String, required: true },
    version: { type: Number, required: true }, committedAt: { type: Number, required: true } },
  { ...options, collection: "approved_edit_audit" });
  return { ledger: connection.model<LedgerRow>("ApprovedEditPreview", ledger),
    audit: connection.model<AuditRow>("ApprovedEditAudit", audit) };
}
