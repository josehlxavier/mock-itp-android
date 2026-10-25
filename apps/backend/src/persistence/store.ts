import pg from 'pg';

export interface DataStore {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
  claim(key: string, expires: number): Promise<boolean>;
  locked<T>(key: string, work: (store: DataStore) => Promise<T>): Promise<T>;
  audit(event: AuditEvent): Promise<void>;
  close(): Promise<void>;
}
export interface AuditEvent { operation: string; outcome: string; interactionId: string; elapsedMs: number; status?: number }

/** Test double only: production and lab entrypoints always use PostgreSQL. */
export class MemoryStore implements DataStore {
  readonly data = new Map<string, unknown>();
  readonly events: AuditEvent[] = [];
  private readonly locks = new Map<string, Promise<unknown>>();
  async get<T>(key: string) { return structuredClone(this.data.get(key)) as T | undefined; }
  async put(key: string, value: unknown) { this.data.set(key, structuredClone(value)); }
  async remove(key: string) { this.data.delete(key); }
  async claim(key: string, expires: number) {
    const now = Date.now(); const old = this.data.get(key) as number | undefined;
    if (old && old > now) return false;
    this.data.set(key, expires); return true;
  }
  async locked<T>(key: string, work: (store: DataStore) => Promise<T>): Promise<T> {
    const previous = this.locks.get(key) ?? Promise.resolve();
    const current: Promise<T> = previous.catch(() => {}).then(() => work(this));
    this.locks.set(key, current);
    try { return await current; } finally { if (this.locks.get(key) === current) this.locks.delete(key); }
  }
  async audit(event: AuditEvent) { this.events.push(event); }
  async close() {}
}

export class PostgresStore implements DataStore {
  private constructor(private readonly pool: pg.Pool, private readonly url: string, private readonly connection?: pg.Client) {}
  static async connect(url: string) {
    const pool = new pg.Pool({ connectionString: url, max: 8, connectionTimeoutMillis: 5000 });
    const store = new PostgresStore(pool, url);
    await pool.query(`CREATE TABLE IF NOT EXISTS itp_state (key text PRIMARY KEY, value jsonb NOT NULL);
      CREATE TABLE IF NOT EXISTS itp_replay (key text PRIMARY KEY, expires_at timestamptz NOT NULL);
      CREATE TABLE IF NOT EXISTS itp_audit (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        created_at timestamptz NOT NULL DEFAULT now(), event jsonb NOT NULL);`);
    return store;
  }
  private get db() { return this.connection ?? this.pool; }
  async get<T>(key: string): Promise<T | undefined> {
    const result = await this.db.query('SELECT value FROM itp_state WHERE key=$1', [key]);
    return result.rows[0]?.value as T | undefined;
  }
  async put(key: string, value: unknown) {
    await this.db.query('INSERT INTO itp_state(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [key, JSON.stringify(value)]);
  }
  async remove(key: string) { await this.db.query('DELETE FROM itp_state WHERE key=$1', [key]); }
  async claim(key: string, expires: number) {
    const r = await this.db.query(`INSERT INTO itp_replay(key,expires_at) VALUES($1,$2)
      ON CONFLICT(key) DO UPDATE SET expires_at=excluded.expires_at WHERE itp_replay.expires_at <= now() RETURNING key`, [key, new Date(expires)]);
    // Expired replay entries are not needed for auditing (events are stored separately).
    await this.db.query('DELETE FROM itp_replay WHERE expires_at < now()');
    return r.rowCount === 1;
  }
  async locked<T>(key: string, work: (store: DataStore) => Promise<T>): Promise<T> {
    // Dedicated lock sessions must not exhaust the query pool while waiting for network IO/audit.
    const client = new pg.Client({ connectionString: this.url, connectionTimeoutMillis: 5000 });
    await client.connect();
    try {
      // Session lock + autocommit deliberately retains "pending" after a crash/network timeout.
      await client.query("SET lock_timeout = '15s'");
      await client.query('SELECT pg_advisory_lock(hashtextextended($1,0))', [key]);
      return await work(new PostgresStore(this.pool, this.url, client));
    } finally {
      try { await client.query('SELECT pg_advisory_unlock(hashtextextended($1,0))', [key]); }
      finally { await client.end(); }
    }
  }
  async audit(event: AuditEvent) { await this.db.query('INSERT INTO itp_audit(event) VALUES($1)', [JSON.stringify(event)]); }
  async close() { await this.pool.end(); }
}
