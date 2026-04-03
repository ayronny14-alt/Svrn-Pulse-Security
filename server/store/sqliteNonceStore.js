/**
 * @sovereign/pulse-api — SQLite Nonce Store
 *
 * Provides a durable, single-node persistence layer for nonces
 * based on better-sqlite3.
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function createSqliteNonceStore(path, ttlSec = 300) {
    mkdirSync(dirname(path), { recursive: true });
    const db = new Database(path);

    db.exec(`
      CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_nonces_exp ON nonces(expires_at);
    `);

    const cleanup = () => {
        const now = Date.now();
        db.prepare('DELETE FROM nonces WHERE expires_at < ?').run(now);
    };

    const cleanupTimer = setInterval(cleanup, 60_000);
    cleanupTimer.unref();

    return {
        set(nonce) {
            const exp = Date.now() + ttlSec * 1000;
            db.prepare('INSERT OR REPLACE INTO nonces (nonce, expires_at) VALUES (?, ?)').run(nonce, exp);
        },
        consume(nonce) {
            const now = Date.now();
            const row = db.prepare('SELECT expires_at FROM nonces WHERE nonce = ?').get(nonce);
            
            if (!row || row.expires_at < now) return false;
            
            const info = db.prepare('DELETE FROM nonces WHERE nonce = ?').run(nonce);
            return info.changes > 0;
        },
        quit() {
            clearInterval(cleanupTimer);
            db.close();
        }
    };
}
