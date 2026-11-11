import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

// Fault injection must precede even opening SQLite. Never log environment values.
if (process.env.FIXTURE_FAIL_BEFORE_WRITES === '1') process.exit(42);
if (process.getuid?.() === 0) throw new Error('Non-root fixture required');

const dataPath = process.env.FIXTURE_DATA_DIRECTORY || '/app/data';
const port = Number(process.env.FIXTURE_LISTEN_PORT || 3000);
const redisPort = Number(process.env.FIXTURE_REDIS_PORT || 6379);
const redisHost = process.env.FIXTURE_REDIS_HOST || 'redis';
fs.accessSync(dataPath, fs.constants.R_OK | fs.constants.W_OK);
const dbPath = `${dataPath}/state.sqlite`;
const first = !fs.existsSync(dbPath);
const database = new DatabaseSync(dbPath);
database.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
if (first) {
  database.exec('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), marker TEXT NOT NULL, sentinel TEXT NOT NULL, boots INTEGER NOT NULL)');
  database.prepare('INSERT INTO state VALUES (1,?,?,0)').run(crypto.randomUUID(), crypto.randomBytes(32).toString('hex'));
}
// An existing database without its row is corrupt, not permission to reseed.
const state = database.prepare('SELECT marker,sentinel,boots FROM state WHERE id=1').get();
if (!state) throw new Error('Retained SQLite state missing');

function redis(args) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({host: redisHost, port: redisPort});
    socket.setTimeout(3000);
    let buffer = Buffer.alloc(0), done = false;
    function finish(error, value) {
      if (done) return;
      done = true; socket.destroy(); error ? reject(error) : resolve(value);
    }
    socket.on('connect', () => {
      socket.write(`*${args.length}\r\n` + args.map(x => `$${Buffer.byteLength(x)}\r\n${x}\r\n`).join(''));
    });
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 1024) return finish(new Error('Redis response exceeds bound'));
      const end = buffer.indexOf('\r\n');
      if (end < 0) return;
      const line = buffer.subarray(0, end).toString();
      if (line === '$-1') return finish(null, null);
      if (line.startsWith('+')) return finish(null, line.slice(1));
      if (!/^\$[0-9]+$/.test(line)) return finish(new Error('Redis response refused'));
      const length = Number(line.slice(1));
      if (length > 256) return finish(new Error('Redis value exceeds bound'));
      if (buffer.length < end + 2 + length + 2) return;
      if (buffer.subarray(end + 2 + length, end + 4 + length).toString() !== '\r\n') return finish(new Error('Redis frame refused'));
      finish(null, buffer.subarray(end + 2, end + 2 + length).toString());
    });
    socket.on('error', () => finish(new Error('Redis unavailable')));
    socket.on('timeout', () => finish(new Error('Redis timeout')));
    socket.on('end', () => finish(new Error('Redis response incomplete')));
  });
}

// Only the first SQLite creation seeds Redis. Every later boot checks GET only;
// otherwise a missing Redis volume could be silently repaired and falsely pass.
if (first && await redis(['SET', 'fixture-sentinel', state.sentinel, 'NX']) !== 'OK') {
  throw new Error('Redis initial state collision');
}
if (await redis(['GET', 'fixture-sentinel']) !== state.sentinel) throw new Error('Retained Redis sentinel missing or changed');
database.prepare('UPDATE state SET boots=boots+1 WHERE id=1').run();
state.boots++;
const literalDigest = crypto.createHash('sha256').update(process.env.FIXTURE_LITERAL || '').digest('hex');
const sentinelDigest = crypto.createHash('sha256').update(state.sentinel).digest('hex');
const server = http.createServer(async (_req, res) => {
  try {
    if (await redis(['GET', 'fixture-sentinel']) !== state.sentinel) throw new Error('Redis mismatch');
    res.writeHead(200, {'content-type': 'application/json'});
    res.end(JSON.stringify({marker: state.marker, boots: state.boots, sqlite: true, redisSentinelDigest: sentinelDigest, literalDigest, uid: process.getuid?.() ?? null}));
  } catch {
    res.writeHead(503); res.end('Persistence check failed');
  }
});
server.listen(port, '0.0.0.0');
// The local test parent gets only the ephemeral listening port, never state/ENV.
server.on('listening', () => process.send?.({ready: true, port: server.address().port}));
for (const signal of ['SIGTERM','SIGINT']) process.on(signal, () => server.close(() => {database.close();process.exit(0);}));
