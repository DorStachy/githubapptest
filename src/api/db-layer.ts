/**
 * Database access layer — INTENTIONALLY VULNERABLE for CodeFence testing.
 *
 * Covers: NoSQL injection, connection string exposure, excessive data exposure,
 *         missing auth checks, and SAFE counterparts.
 */

import { MongoClient, ObjectId } from 'mongodb';

// ─────────────────────── HARDCODED CONNECTION STRING (CRITICAL) ─────────
const MONGO_URI = 'mongodb://admin:P@ssw0rd123@db.prod.internal:27017/appdb?authSource=admin';

let client: MongoClient;

async function getDb() {
  if (!client) {
    client = new MongoClient(MONGO_URI);
    await client.connect();
  }
  return client.db('appdb');
}

// ─────────────────────── NOSQL INJECTION (CRITICAL) ─────────────────────
export async function findUser(query: Record<string, unknown>) {
  const db = await getDb();
  // Passing user-controlled object directly — allows { "$gt": "" } attacks
  return db.collection('users').findOne(query);
}

// ─────────────────────── NOSQL INJECTION — SAFE (no vuln) ──────────────
export async function findUserSafe(username: string) {
  const db = await getDb();
  // Only allow string matching on known field
  if (typeof username !== 'string') throw new Error('invalid input');
  return db.collection('users').findOne({ username });
}

// ─────────────────────── EXCESSIVE DATA EXPOSURE (MEDIUM) ──────────────
export async function getUserProfile(userId: string) {
  const db = await getDb();
  // Returns ALL fields including password hash, SSN, internal flags
  return db.collection('users').findOne({ _id: new ObjectId(userId) });
}

// ─────────────────────── SAFE PROJECTION (no vuln) ─────────────────────
export async function getUserProfileSafe(userId: string) {
  const db = await getDb();
  return db.collection('users').findOne(
    { _id: new ObjectId(userId) },
    { projection: { password: 0, ssn: 0, internalFlags: 0 } },
  );
}

// ─────────────────────── MISSING AUTH CHECK (HIGH) ─────────────────────
export async function deleteUser(userId: string) {
  const db = await getDb();
  // No authorization check — any caller can delete any user
  return db.collection('users').deleteOne({ _id: new ObjectId(userId) });
}

// ─────────────────────── IDOR — INSECURE DIRECT OBJECT REF (HIGH) ──────
export async function getInvoice(invoiceId: string) {
  const db = await getDb();
  // No ownership check — user A can read user B's invoices
  return db.collection('invoices').findOne({ _id: new ObjectId(invoiceId) });
}

// ─────────────────────── SAFE WITH OWNERSHIP CHECK (no vuln) ───────────
export async function getInvoiceSafe(invoiceId: string, currentUserId: string) {
  const db = await getDb();
  return db.collection('invoices').findOne({
    _id: new ObjectId(invoiceId),
    ownerId: currentUserId,
  });
}

// ─────────────────────── UNVALIDATED BULK INSERT (MEDIUM) ──────────────
export async function bulkInsert(collectionName: string, docs: unknown[]) {
  const db = await getDb();
  // User controls collection name AND documents — dangerous
  return db.collection(collectionName).insertMany(docs as any[]);
}

// ─────────────────────── LOG INJECTION (LOW) ───────────────────────────
export function logAction(userId: string, action: string): void {
  // User-controlled data written directly to logs — enables log forging
  console.log(`[AUDIT] user=${userId} action=${action}`);
}

// ─────────────────────── SAFE LOGGING (no vuln) ───────────────────────
export function logActionSafe(userId: string, action: string): void {
  const safeUserId = userId.replace(/[\r\n]/g, '_');
  const safeAction = action.replace(/[\r\n]/g, '_').slice(0, 200);
  console.log(`[AUDIT] user=${safeUserId} action=${safeAction}`);
}
