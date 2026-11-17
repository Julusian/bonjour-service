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

tape('a probe is answered straight away, even just after the records were sent, but at most once per 250ms', function (t) {
  const { server, sent, tick } = setup()
  const probe = () => server.mdns.emit('query', { questions: [{ name: FQDN, type: 'ANY' }], authorities: [{ name: FQDN, type: 'SRV', data: {} }] }, {})
  server.markMulticast(records())
  tick(300)
  probe()
  t.equal(sent.length, 1, 'answered straight away, rather than 1s after the records were sent')
  tick(100)
  probe()
  t.equal(sent.length, 1, 'not again within 250ms')
  tick(900)
  t.equal(sent.length, 2, 'held one sent once allowed')
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

// Publish with probe queries answered by `answer(name)`, returning what was probed for and announced
const probeWith = function (answer, config, onUp) {
  const { server, sent } = setup()
  const registry = new Registry(server)
  const probed = []
  server.mdns.query = (query, done) => {
    const name = query.questions[0].name
    probed.push(name)
    done()
    const answers = answer(name)
    if (answers.length) server.mdns.emit('response', { answers, additionals: [] })
  }
  const keepAlive = setTimeout(() => {}, 10000) // probe timers are unref'd
  const service = registry.publish({ type: 'http', port: 3001, host: HOST, ...config })
  const renames = []
  service.on('rename', (name) => renames.push(name))
  service.on('up', function () {
    clearTimeout(keepAlive)
    onUp({ service, probed, renames, sent })
  })
}

const srv = (name, target, ttl = 120) => ({ name, type: 'SRV', ttl, data: { port: 3001, target } })

tape('a service that loses probing moves to the next name, without sending anything for the taken one', function (t) {
  probeWith((name) => name.startsWith('taken.') ? [srv(name, 'other.local')] : [], { name: 'taken' }, function ({ service, probed, renames, sent }) {
    t.equal(service.name, 'taken (2)', 'renamed')
    t.equal(service.fqdn, 'taken (2)._http._tcp.local')
    t.deepEqual(renames, ['taken (2)'], 'rename emitted')
    t.equal(probed.filter((name) => name === 'taken (2)._http._tcp.local').length, 3, 'new name probed in full')
    t.ok(sent.length > 0, 'announced')
    t.ok(sent.every((packet) => [].concat(packet.answers || packet).every((r) => !String(r.name).startsWith('taken.') && r.data !== 'taken._http._tcp.local')), 'nothing sent for the taken name')
    t.end()
  })
})

tape('each further conflict moves to the next number', function (t) {
  const taken = ['dup', 'dup (2)', 'dup (3)'].map((n) => `${n}._http._tcp.local`)
  probeWith((name) => taken.includes(name) ? [srv(name, 'other.local')] : [], { name: 'dup' }, function ({ service, renames }) {
    t.equal(service.name, 'dup (4)')
    t.deepEqual(renames, ['dup (2)', 'dup (3)', 'dup (4)'])
    t.end()
  })
})

tape('goodbyes for the name are not a conflict', function (t) {
  probeWith((name) => [srv(name, 'other.local', 0)], { name: 'baz' }, function ({ service, renames }) {
    t.equal(service.name, 'baz')
    t.deepEqual(renames, [])
    t.end()
  })
})

tape('records the same as the ones proposed are not a conflict', function (t) {
  probeWith((name) => [srv(name, HOST)], { name: 'baz' }, function ({ service, renames }) {
    t.equal(service.name, 'baz')
    t.deepEqual(renames, [])
    t.end()
  })
})

tape('unpublishing a service leaves other services of the same type answering', function (t) {
  const { server, sent, tick, query } = setup()
  const registry = new Registry(server)
  const a = registry.publish({ name: 'a', type: 'http', port: 3001, host: HOST, probe: false })
  registry.publish({ name: 'b', type: 'http', port: 3002, host: HOST, probe: false })
  a.stop(function () {
    sent.length = 0
    query(['_http._tcp.local', 'PTR'])
    tick(1000) // b was just announced, so the reply is held for 1s
    const ptrs = sent.flatMap((p) => p.answers).filter((r) => r.type === 'PTR').map((r) => r.data)
    t.ok(ptrs.includes('b._http._tcp.local'), 'b still answers')
    t.notOk(ptrs.includes('a._http._tcp.local'), 'a no longer answers')
    t.end()
  })
})

tape('announcements start 1s apart, then back off, stopping after eight', function (t) {
  const { server, sent } = setup()
  const registry = new Registry(server)
  const delays = []
  const pending = []
  const realSetTimeout = global.setTimeout
  global.setTimeout = (fn, ms) => { delays.push(ms); pending.push(fn); return { unref () {} } }
  try {
    registry.publish({ name: 'baz', type: 'http', port: 3001, host: HOST, probe: false })
    while (pending.length) pending.shift()()
  } finally {
    global.setTimeout = realSetTimeout
  }
  t.equal(sent.length, 8, 'eight announcements')
  t.deepEqual(delays, [1000, 3000, 9000, 27000, 81000, 243000, 729000], 'first two 1s apart, then tripling')
  t.end()
})

tape('answers the querier already knows with at least half their TTL are left out', function (t) {
  const { server, sent } = setup()
  const ptr = { name: '_http._tcp.local', type: 'PTR', data: 'foo._http._tcp.local' }
  const ask = (ttl) => server.mdns.emit('query', { questions: [{ name: '_http._tcp.local', type: 'PTR' }], answers: [{ ...ptr, ttl }] }, {})

  ask(14400)
  t.equal(sent.length, 0, 'known with half the TTL left: no reply')
  ask(14399)
  t.equal(sent.length, 1, 'known with less than half the TTL left: answered')
  t.end()
})

tape('a known answer with different data does not suppress the answer', function (t) {
  const { server, sent } = setup()
  const ask = (known) => server.mdns.emit('query', { questions: [{ name: FQDN, type: known.type }], answers: [{ name: FQDN, ttl: 4500, ...known }] }, {})

  ask({ type: 'SRV', data: { port: 4000, weight: 0, priority: 0, target: HOST } })
  t.equal(sent.length, 1, 'SRV with an old port: answered')
  ask({ type: 'TXT', data: [Buffer.from('a=b')] })
  t.equal(sent.length, 2, 'TXT with old contents: answered')

  const fresh = setup()
  fresh.server.mdns.emit('query', { questions: [{ name: FQDN, type: 'SRV' }], answers: [{ name: FQDN.toUpperCase(), type: 'SRV', ttl: 120, data: { port: 3000, weight: 0, priority: 0, target: HOST } }] }, {})
  t.equal(fresh.sent.length, 0, 'matching SRV, compared case-insensitively: no reply')
  t.end()
})

tape('queries from a port other than 5353 get a unicast reply, as a conventional DNS response', function (t) {
  const { server, sent, query } = setup()
  const unicast = []
  server.mdns.respond = (packet, rinfo, cb) => {
    if (typeof rinfo === 'function') return sent.push(packet)
    unicast.push({ packet, rinfo })
  }
  const questions = [{ name: '_http._tcp.local', type: 'PTR' }]

  server.mdns.emit('query', { id: 1234, questions }, { address: '192.168.1.20', port: 54321 })
  t.equal(sent.length, 0, 'nothing multicast')
  t.equal(unicast.length, 1, 'one unicast reply')
  const { packet, rinfo } = unicast[0]
  t.deepEqual(rinfo, { address: '192.168.1.20', port: 54321 }, 'sent to the querier')
  t.equal(packet.id, 1234, 'repeats the query ID')
  t.deepEqual(packet.questions, questions, 'repeats the questions')
  const all = packet.answers.concat(packet.additionals)
  t.deepEqual(summary(all), ['A myhost.local', 'AAAA myhost.local', 'PTR _http._tcp.local', 'SRV foo._http._tcp.local', 'TXT foo._http._tcp.local'], 'answers with additionals')
  t.ok(all.every((r) => r.ttl <= 10), 'TTLs capped at 10s')
  t.ok(all.every((r) => !r.flush), 'no cache-flush bit')

  server.mdns.emit('query', { id: 1235, questions }, { address: '192.168.1.20', port: 54321 })
  t.equal(unicast.length, 2, 'not rate limited')

  query(['_http._tcp.local', 'PTR'])
  t.equal(sent.length, 1, 'and does not hold back a following multicast reply')
  t.end()
})

tape('service type enumeration lists each published type once, until its last service is stopped', function (t) {
  const { server, sent, tick, query } = setup()
  const types = () => {
    sent.length = 0
    query(['_services._dns-sd._udp.local', 'PTR'])
    tick(1000)
    return sent.flatMap((p) => p.answers).map((r) => r.data).sort()
  }
  t.deepEqual(types(), ['_http._tcp.local'], 'type from the registered records')

  const more = { name: '_http._tcp.local', type: 'PTR', ttl: 4500, flush: false, data: 'bar._http._tcp.local' }
  const sub = { name: '_printer._sub._http._tcp.local', type: 'PTR', ttl: 4500, flush: false, data: 'bar._http._tcp.local' }
  const other = { name: '_ipp._tcp.local', type: 'PTR', ttl: 4500, flush: false, data: 'bar._ipp._tcp.local' }
  server.register([more, sub, other])
  t.deepEqual(types(), ['_http._tcp.local', '_ipp._tcp.local'], 'listed once per type, subtypes not listed')

  server.unregister(records()[0])
  t.deepEqual(types(), ['_http._tcp.local', '_ipp._tcp.local'], 'still listed while another service of the type remains')
  server.unregister([more, sub, other])
  t.deepEqual(types(), [], 'removed with the last service of the type')
  t.end()
})

tape('probes ask for the name, with the proposed records in the authority section', function (t) {
  const { server } = setup()
  const registry = new Registry(server)
  const probes = []
  server.mdns.query = (query, cb) => { probes.push(query); cb() }
  const keepAlive = setTimeout(() => {}, 5000) // probe timers are unref'd
  const service = registry.publish({ name: 'baz', type: 'http', port: 3001, host: HOST, txt: { a: 'b' } })
  service.on('up', function () {
    clearTimeout(keepAlive)
    t.equal(probes.length, 3, 'three probes')
    t.deepEqual(probes[0].questions, [{ name: 'baz._http._tcp.local', type: 'ANY' }], 'question for the name')
    t.deepEqual(summary(probes[0].authorities), ['SRV baz._http._tcp.local', 'TXT baz._http._tcp.local'], 'proposed records')
    t.end()
  })
})
