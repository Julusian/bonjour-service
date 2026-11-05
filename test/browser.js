'use strict'

const { EventEmitter } = require('events')
const tape = require('tape')
const { Browser } = require('../dist/lib/browser')

const fakeMdns = function () {
  const mdns = new EventEmitter()
  mdns.queries = []
  mdns.query = (query) => mdns.queries.push(query)
  return mdns
}

const announce = (mdns, name, ttl) => mdns.emit('response', {
  answers: [
    { name: '_http._tcp.local', type: 'PTR', ttl, data: `${name}._http._tcp.local` },
    { name: `${name}._http._tcp.local`, type: 'SRV', ttl: 120, data: { port: 80, target: 'host.local' } }
  ],
  additionals: []
}, { address: '192.168.1.20', port: 5353 })

tape('browser queries list services already found as known answers', function (t) {
  const mdns = fakeMdns()
  const browser = new Browser(mdns, { type: 'http' })
  t.deepEqual(mdns.queries[0], { questions: [{ name: '_http._tcp.local', type: 'PTR' }], answers: [] }, 'first query has no known answers')

  announce(mdns, 'fresh', 4500)
  announce(mdns, 'stale', 4500)
  // stale was seen long enough ago that less than half its TTL remains
  browser.services.find((s) => s.name === 'stale').lastSeen -= 2251 * 1000

  browser.update()
  const answers = mdns.queries[1].answers
  t.equal(answers.length, 1, 'only services with more than half their TTL remaining')
  t.equal(answers[0].data, 'fresh._http._tcp.local')
  t.equal(answers[0].name, '_http._tcp.local')
  t.equal(answers[0].type, 'PTR')
  t.ok(answers[0].ttl <= 4500 && answers[0].ttl > 4490, 'with the remaining TTL')
  t.end()
})

tape('expire() removes expired services before emitting down', function (t) {
  const mdns = fakeMdns()
  const browser = new Browser(mdns, { type: 'http' })
  announce(mdns, 'old', 120)
  announce(mdns, 'new', 120)
  browser.services.find((s) => s.name === 'old').lastSeen -= 121 * 1000

  const seen = []
  browser.on('down', function (service) {
    seen.push(service.name)
    t.deepEqual(browser.services.map((s) => s.name), ['new'], 'services no longer includes the expired service')
  })
  browser.expire()
  t.deepEqual(seen, ['old'], 'down emitted for the expired service only')
  t.end()
})
