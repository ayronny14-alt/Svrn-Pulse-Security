/**
 * @svrnsec/pulse — Persistence Layer
 *
 * Handles nonce tracking (replay protection) and device registry
 * for long-term reputation scoring.
 */

import Database from 'better-sqlite3';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export class PersistenceStore {
  constructor(opts = {}) {
    this._path = opts.path || './.pulse/pulse.sqlite';
    this._db = null;
    this._nonceTTL = opts.nonceTTL || 3600 * 1000; // 1 hour
  }

  async init() {
    await mkdir(dirname(this._path), { recursive: true });
    this._db = new Database(this._path);

    // Replay protection table
    this._db.exec(`
      CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT PRIMARY KEY,
        ts INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_nonces_ts ON nonces(ts);
    `);

    // Device registry for reputation over time
    this._db.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        host_id TEXT PRIMARY KEY,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        vouch_count INTEGER DEFAULT 0,
        risk_score REAL DEFAULT 0,
        flags TEXT,
        metadata TEXT
      );
    `);

    // Cleanup expired nonces
    this._cleanup();
    setInterval(() => this._cleanup(), 300_000).unref(); // every 5 mins
  }

  /**
   * Check and record a nonce. Returns false if replayed.
   */
  useNonce(nonce) {
    try {
      const now = Date.now();
      const stmt = this._db.prepare('INSERT INTO nonces (nonce, ts) VALUES (?, ?)');
      stmt.run(nonce, now);
      return true;
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') return false;
      throw err;
    }
  }

  /**
   * Upsert device record and update reputation.
   */
  updateDevice(hostId, evaluation) {
    const now = Date.now();
    const row = this._db.prepare('SELECT * FROM devices WHERE host_id = ?').get(hostId);
    
    if (!row) {
      this._db.prepare(`
        INSERT INTO devices (host_id, first_seen, last_seen, vouch_count, risk_score, flags)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(hostId, now, now, 1, evaluation.score, JSON.stringify(evaluation.flags || []));
    } else {
      const newVouchCount = row.vouch_count + 1;
      // Exponential moving average for risk score
      const newScore = (row.risk_score * 0.7) + (evaluation.score * 0.3);
      
      this._db.prepare(`
        UPDATE devices 
        SET last_seen = ?, vouch_count = ?, risk_score = ?, flags = ?
        WHERE host_id = ?
      `).run(now, newVouchCount, newScore, JSON.stringify(evaluation.flags || []), hostId);
    }
  }

  getDevice(hostId) {
    const row = this._db.prepare('SELECT * FROM devices WHERE host_id = ?').get(hostId);
    if (!row) return null;
    return {
      ...row,
      flags: JSON.parse(row.flags || '[]'),
      metadata: JSON.parse(row.metadata || '{}')
    };
  }

  _cleanup() {
    if (!this._db) return;
    const cutoff = Date.now() - this._nonceTTL;
    this._db.prepare('DELETE FROM nonces WHERE ts < ?').run(cutoff);
  }

  close() {
    if (this._db) this._db.close();
  }
}
