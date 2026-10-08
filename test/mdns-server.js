'use strict'

const { EventEmitter } = require('events')
const tape = require('tape')
const { Server } = require('../dist/lib/mdns-server')
const { Registry } = require('../dist/lib/registry')

// Minimal stand-in for a dgram socket, so no real sockets are needed
class FakeSocket extends EventEmitter {
  bind (port, iface, cb) { setImmediate(cb) }
  address () { return { address: '0.0.0.0', port: 5353 } }
  addMembership () {}
  dropMembership () {}
  setMulticastTTL () {}
  setMulticastLoopback () {}
  setMulticastInterface () {}
  send (buf, offset, length, port, address, cb) { if (cb) cb() }
  close (cb) { if (cb) cb() }
}

const FQDN = 'foo._http._tcp.local'
const HOST = 'myhost.local'

const records = () => [
  { name: '_http._tcp.local', type: 'PTR', ttl: 28800, data: FQDN },
  { name: FQDN, type: 'SRV', ttl: 120, data: { port: 3000, weight: 0, priority: 0, target: HOST } },
  { name: FQDN, type: 'TXT', ttl: 4500, data: [] },
  { name: HOST, type: 'A', ttl: 120, data: '192.168.1.10' },
  { name: HOST, type: 'AAAA', ttl: 120, data: 'fe80::1' }
]

const setup = function () {
  const server = new Server({ socket: new FakeSocket() })
  const sent = []
  let time = 10000
  let timers = []
  server.now = () => time
  server.schedule = (fn, ms) => {
    const timer = { at: time + ms, fn }
    timers.push(timer)
    return () => { timers = timers.filter((t) => t !== timer) }
  }
  server.mdns.respond = (packet, cb) => { sent.push(packet); if (cb) cb() }
  server.register(records())

  // Advance the fake clock, running any timers that fall due
  const tick = (ms) => {
    const end = time + ms
    for (;;) {
      const due = timers.filter((t) => t.at <= end).sort((a, b) => a.at - b.at)[0]
      if (!due) break
      timers = timers.filter((t) => t !== due)
      time = due.at
      due.fn()
    }
    time = end
  }

  return {
    server,
    sent,
    tick,
    query: (...questions) => server.mdns.emit('query', { questions: questions.map(([name, type]) => ({ name, type })) }, {})
  }
}

const summary = (list) => list.map((r) => `${r.type} ${r.name}`).sort()

tape('a repeat query within 1s is deferred until 1s after the last reply', function (t) {
  const { server, sent, tick, query } = setup()
  query([FQDN, 'SRV'])
  t.equal(sent.length, 1, 'first query answered straight away')
  tick(500)
  query([FQDN, 'SRV'])
  tick(200)
  query([FQDN, 'SRV'])
  t.equal(sent.length, 1, 'repeats within 1s not sent yet')
  tick(299)
  t.equal(sent.length, 1, 'still held just before 1s')
  tick(1)
  t.equal(sent.length, 2, 'held repeats sent as one reply at 1s')
  t.deepEqual(summary(sent[1].answers), ['SRV ' + FQDN])
  tick(5000)
  t.equal(sent.length, 2, 'nothing else sent')
  server.destroy()
  t.end()
})

tape('a continuous stream of queries gets at most one reply per second', function (t) {
  const { server, sent, tick, query } = setup()
  const sentAt = []
  server.mdns.respond = (packet, cb) => { sentAt.push(server.now()); sent.push(packet); if (cb) cb() }
  for (let i = 0; i < 30; i++) {
    query([FQDN, 'SRV'])
    tick(100)
  }
  t.deepEqual(sentAt.map((at) => at - sentAt[0]), [0, 1000, 2000, 3000], 'replies exactly 1s apart')
  server.destroy()
  t.end()
})

tape('rate limit is per record, and counts announcements', function (t) {
  const { server, sent, tick, query } = setup()
  server.markMulticast(records().filter((r) => r.type === 'SRV'))
  tick(100)
  query([FQDN, 'TXT'])
  t.equal(sent.length, 1, 'a record not recently sent gets a reply straight away')
  t.deepEqual(summary(sent[0].answers), ['TXT ' + FQDN])
  query([FQDN, 'SRV'])
  t.equal(sent.length, 1, 'record just announced is held')
  tick(900)
  t.equal(sent.length, 2, 'and sent 1s after the announcement')
  t.deepEqual(summary(sent[1].answers), ['SRV ' + FQDN])
  server.destroy()
  t.end()
})

tape('a reply is held whole when only some of its answers were recently sent', function (t) {
  const { server, sent, tick, query } = setup()
  query([FQDN, 'TXT'])
  query([FQDN, 'ANY'])
  t.equal(sent.length, 1, 'ANY reply held, rather than sending SRV alone')
  query(['_http._tcp.local', 'PTR'])
  t.equal(sent.length, 1, 'later queries join the held reply')
  tick(1000)
  t.equal(sent.length, 2)
  t.deepEqual(summary(sent[1].answers), ['PTR _http._tcp.local', 'SRV ' + FQDN, 'TXT ' + FQDN], 'everything sent together')
  t.deepEqual(summary(sent[1].additionals), ['A ' + HOST, 'AAAA ' + HOST])
  server.destroy()
  t.end()
})

tape('held answers that are sent in the meantime are left out', function (t) {
  const { server, sent, tick, query } = setup()
  query([FQDN, 'SRV'])
  query([FQDN, 'SRV'], [FQDN, 'TXT'])
  tick(500)
  server.markMulticast(records().filter((r) => r.type === 'TXT'))
  tick(500)
  t.equal(sent.length, 2)
  t.deepEqual(summary(sent[1].answers), ['SRV ' + FQDN], 'TXT went out in the meantime')
  server.destroy()
  t.end()
})

tape('goodbyes are not held, and unregister clears the rate limit and held answers', function (t) {
  const { server, sent, tick, query } = setup()
  const registry = new Registry(server)
  const service = registry.publish({ name: 'baz', type: 'http', port: 3001, host: HOST, probe: false })
  const fqdn = 'baz._http._tcp.local'
  t.equal(sent.length, 1, 'announced')

  query([fqdn, 'TXT'])
  t.equal(sent.length, 1, 'query straight after the announcement is held')

  service.stop(function () {
    t.equal(sent.length, 2, 'goodbye sent straight after the announcement')
    t.ok(sent[1].every((r) => r.ttl === 0), 'goodbye records have ttl 0')
    tick(2000)
    t.equal(sent.length, 2, 'held reply for the unpublished record is not sent')

    // Re-publish without any time passing
    server.register(sent[0])
    query([fqdn, 'TXT'])
    t.equal(sent.length, 3, 're-published record is answered straight away')
    server.destroy()
    t.end()
  })
})

tape('destroy cancels a held reply', function (t) {
  const { server, sent, tick, query } = setup()
  query([FQDN, 'SRV'])
  query([FQDN, 'SRV'])
  server.destroy()
  tick(2000)
  t.equal(sent.length, 1)
  t.end()
})

tape('a multi-question query gives one reply with all answers, without duplicates', function (t) {
  const { server, sent, query } = setup()
  query([FQDN, 'SRV'], [FQDN, 'TXT'], [FQDN, 'SRV'])
  t.equal(sent.length, 1, 'one respond call')
  t.deepEqual(summary(sent[0].answers), ['SRV ' + FQDN, 'TXT ' + FQDN])
  t.deepEqual(summary(sent[0].additionals), ['A ' + HOST, 'AAAA ' + HOST])
  server.destroy()
  t.end()
})

tape('SRV answers include the target addresses as additionals', function (t) {
  const { server, sent, query } = setup()
  query([FQDN, 'SRV'])
  t.deepEqual(summary(sent[0].additionals), ['A ' + HOST, 'AAAA ' + HOST])
  server.destroy()
  t.end()
})

tape('ANY answers include the target addresses as additionals', function (t) {
  const { server, sent, query } = setup()
  query([FQDN, 'ANY'])
  t.deepEqual(summary(sent[0].answers), ['SRV ' + FQDN, 'TXT ' + FQDN])
  t.deepEqual(summary(sent[0].additionals), ['A ' + HOST, 'AAAA ' + HOST])
  server.destroy()
  t.end()
})

tape('PTR answers include SRV, TXT and addresses, but not records already answered', function (t) {
  const { server, sent, query } = setup()
  query(['_http._tcp.local', 'PTR'], [FQDN, 'TXT'])
  t.deepEqual(summary(sent[0].answers), ['PTR _http._tcp.local', 'TXT ' + FQDN])
  t.deepEqual(summary(sent[0].additionals), ['A ' + HOST, 'AAAA ' + HOST, 'SRV ' + FQDN])
  server.destroy()
  t.end()
})

tape('no reply when nothing matches', function (t) {
  const { server, sent, query } = setup()
  query(['other.local', 'A'])
  t.equal(sent.length, 0)
  server.destroy()
  t.end()
})
