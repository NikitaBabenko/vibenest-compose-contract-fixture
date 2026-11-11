import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fork} from 'node:child_process';
import {once} from 'node:events';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

const app = fileURLToPath(new URL('../private-app/server.mjs', import.meta.url));

// This is explicitly a RESP test double; real Redis AOF/volume persistence is a
// separate disposable acceptance requirement. SQLite below is the real module.
async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'vn-private-sqlite-'));
  let stored = null, sets = 0;
  const clients = new Set();
  const redis = net.createServer(socket => {
    clients.add(socket); socket.on('close', () => clients.delete(socket));
    let buffer = '';
    socket.on('data', chunk => {
      buffer += chunk.toString();
      const lines = buffer.split('\r\n');
      const count = Number(lines[0].slice(1));
      if (lines.length < 2*count+2) return;
      const args = Array.from({length: count}, (_, i) => lines[2*i+2]);
      if (args[0] === 'SET') {
        sets++;
        if (stored !== null) socket.end('$-1\r\n');
        else {stored = args[2]; socket.end('+OK\r\n');}
      } else if (args[0] === 'GET') {
        socket.end(stored === null ? '$-1\r\n' : `$${Buffer.byteLength(stored)}\r\n${stored}\r\n`);
      } else socket.end('-ERR unsupported\r\n');
    });
  });
  redis.listen(0, '127.0.0.1'); await once(redis, 'listening');
  const children = [];
  const literal = 'synthetic-$literal\n${CHANGED_PROVIDER_ENV}\n"quote"';
  async function launch(extra = {}) {
    const child = fork(app, [], {silent: true, env: {...process.env,
      FIXTURE_DATA_DIRECTORY: directory, FIXTURE_LISTEN_PORT: '0',
      FIXTURE_REDIS_HOST: '127.0.0.1', FIXTURE_REDIS_PORT: String(redis.address().port),
      FIXTURE_LITERAL: literal, ...extra}});
    children.push(child); child.stdout.resume(); child.stderr.resume();
    const exit = new Promise(resolve => child.once('exit', (code, signal) => resolve({code, signal})));
    const outcome = await Promise.race([
      new Promise(resolve => child.once('message', resolve)), exit,
      new Promise((_, reject) => {const timer = setTimeout(() => reject(new Error('Fixture startup timeout')), 10000);timer.unref();})
    ]);
    return {child, exit, outcome};
  }
  async function stop(run) {if (run.child.exitCode === null) run.child.kill(); await run.exit;}
  t.after(async () => {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) {child.kill();await once(child, 'exit');}
    for (const client of clients) client.destroy();
    await new Promise(resolve => redis.close(resolve));
    // Known files only, no recursive Windows filesystem deletion.
    for (const file of ['state.sqlite', 'state.sqlite-wal', 'state.sqlite-shm']) await fs.rm(path.join(directory, file), {force: true});
    await fs.rmdir(directory);
  });
  return {directory, launch, stop, literal, sets: () => sets, clearRedis: () => {stored = null;}};
}

test('real SQLite survives restart and missing Redis is never reseeded', async t => {
  const f = await fixture(t);
  const first = await f.launch(); assert.equal(first.outcome.ready, true);
  const a = await (await fetch(`http://127.0.0.1:${first.outcome.port}`)).json();
  assert.equal(a.sqlite, true); assert.equal(a.boots, 1);
  assert.equal(a.literalDigest, crypto.createHash('sha256').update(f.literal).digest('hex'));
  await f.stop(first);
  const second = await f.launch(); assert.equal(second.outcome.ready, true);
  const b = await (await fetch(`http://127.0.0.1:${second.outcome.port}`)).json();
  assert.equal(b.marker, a.marker); assert.equal(b.redisSentinelDigest, a.redisSentinelDigest);
  assert.equal(b.boots, 2); assert.equal(f.sets(), 1);
  await f.stop(second); f.clearRedis();
  const third = await f.launch(); assert.equal(third.outcome.code, 1); assert.equal(f.sets(), 1);
});

test('fault 42 occurs before creating any SQLite files', async t => {
  const f = await fixture(t);
  const failed = await f.launch({FIXTURE_FAIL_BEFORE_WRITES: '1'});
  assert.equal(failed.outcome.code, 42); assert.deepEqual(await fs.readdir(f.directory), []);
  assert.equal(f.sets(), 0);
});
