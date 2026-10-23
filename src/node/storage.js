// Mailbox storage for the self-hosted relay: one SQLite file, opened with the
// SQLite built into Node (node:sqlite). It offers the subset of the Durable
// Object storage API that core.js uses, scoped to one mailbox.
//
// secure_delete overwrites deleted ciphertext with zeros, so an envelope that
// was read and pruned does not linger in free pages of the file.

import { DatabaseSync } from "node:sqlite";

const JSON_VALUE = 0;
const BYTES_VALUE = 1;

export class Database {
  constructor(path) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA secure_delete = ON;
      CREATE TABLE IF NOT EXISTS entries (
        mailbox TEXT NOT NULL,
        key TEXT NOT NULL,
        kind INTEGER NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (mailbox, key)
      ) WITHOUT ROWID;
      CREATE TABLE IF NOT EXISTS alarms (
        mailbox TEXT PRIMARY KEY,
        at INTEGER NOT NULL
      ) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS alarms_at ON alarms (at);
    `);
    this.statements = {
      get: this.db.prepare("SELECT kind, value FROM entries WHERE mailbox = ? AND key = ?"),
      put: this.db.prepare(
        "INSERT INTO entries (mailbox, key, kind, value) VALUES (?, ?, ?, ?) " +
          "ON CONFLICT (mailbox, key) DO UPDATE SET kind = excluded.kind, value = excluded.value",
      ),
      delete: this.db.prepare("DELETE FROM entries WHERE mailbox = ? AND key = ?"),
      deleteAll: this.db.prepare("DELETE FROM entries WHERE mailbox = ?"),
      setAlarm: this.db.prepare(
        "INSERT INTO alarms (mailbox, at) VALUES (?, ?) " +
          "ON CONFLICT (mailbox) DO UPDATE SET at = excluded.at",
      ),
      getAlarm: this.db.prepare("SELECT at FROM alarms WHERE mailbox = ?"),
      deleteAlarm: this.db.prepare("DELETE FROM alarms WHERE mailbox = ?"),
      due: this.db.prepare("SELECT mailbox FROM alarms WHERE at <= ? ORDER BY at LIMIT 256"),
    };
  }

  storage(mailbox) {
    return new Storage(this, mailbox);
  }

  /** Mailboxes whose idle alarm is due. */
  due(now) {
    return this.statements.due.all(now).map((row) => row.mailbox);
  }

  transaction(work) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      work();
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  close() {
    this.db.close();
  }
}

function encode(value) {
  if (value instanceof Uint8Array) return [BYTES_VALUE, value];
  return [JSON_VALUE, JSON.stringify(value)];
}

function decode(row) {
  if (row.kind === BYTES_VALUE) return new Uint8Array(row.value);
  const text = typeof row.value === "string" ? row.value : new TextDecoder().decode(row.value);
  return JSON.parse(text);
}

class Storage {
  constructor(database, mailbox) {
    this.database = database;
    this.mailbox = mailbox;
  }

  async get(key) {
    const row = this.database.statements.get.get(this.mailbox, key);
    return row ? decode(row) : undefined;
  }

  async put(keyOrEntries, value) {
    const entries = typeof keyOrEntries === "string" ? { [keyOrEntries]: value } : keyOrEntries;
    this.database.transaction(() => {
      for (const [key, entry] of Object.entries(entries)) {
        this.database.statements.put.run(this.mailbox, key, ...encode(entry));
      }
    });
  }

  /** Sorted by key; `start` inclusive, `end` exclusive, as Durable Objects do. */
  async list({ prefix = "", start, end, limit } = {}) {
    const where = ["mailbox = ?", "substr(key, 1, ?) = ?"];
    const parameters = [this.mailbox, prefix.length, prefix];
    if (start !== undefined) {
      where.push("key >= ?");
      parameters.push(start);
    }
    if (end !== undefined) {
      where.push("key < ?");
      parameters.push(end);
    }
    let sql = `SELECT key, kind, value FROM entries WHERE ${where.join(" AND ")} ORDER BY key`;
    if (limit !== undefined) {
      sql += " LIMIT ?";
      parameters.push(limit);
    }
    const rows = this.database.db.prepare(sql).all(...parameters);
    return new Map(rows.map((row) => [row.key, decode(row)]));
  }

  async delete(keys) {
    this.database.transaction(() => {
      for (const key of keys) this.database.statements.delete.run(this.mailbox, key);
    });
  }

  async deleteAll() {
    this.database.statements.deleteAll.run(this.mailbox);
  }

  async setAlarm(at) {
    this.database.statements.setAlarm.run(this.mailbox, Math.floor(at));
  }

  async getAlarm() {
    return this.database.statements.getAlarm.get(this.mailbox)?.at ?? null;
  }

  async deleteAlarm() {
    this.database.statements.deleteAlarm.run(this.mailbox);
  }
}
