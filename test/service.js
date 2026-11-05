'use strict'

const os = require('os')
const test = require('tape')
const { Service } = require('../dist/lib/service')

const getAddressesRecords = function (host) {
  const records = []
  const itrs = Object.values(os.networkInterfaces())
  for (const addrs of itrs) {
    for (const { internal, address, family, mac } of addrs) {
      if (internal === false && mac !== '00:00:00:00:00:00') {
        records.push({ data: address, name: host, ttl: 120, type: family === 'IPv4' ? 'A' : 'AAAA', flush: true })
      }
    }
  }
  return records
}

test('service must throw an exception if no name is specified', function (t) {
  t.throws(function () {
    new Service({ type: 'http', port: 3000 }) // eslint-disable-line no-new
  }, 'Required name not given')
  t.end()
})

test('service must throw an exception if no type is specified', function (t) {
  t.throws(function () {
    new Service({ name: 'Foo Bar', port: 3000 }) // eslint-disable-line no-new
  }, 'Required type not given')
  t.end()
})

test('no port', function (t) {
  t.throws(function () {
    new Service({ name: 'Foo Bar', type: 'http' }) // eslint-disable-line no-new
  }, 'Required port not given')
  t.end()
})

test('minimal', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', port: 3000 })
  t.equal(s.name, 'Foo Bar')
  t.equal(s.protocol, 'tcp')
  t.equal(s.type, '_http._tcp')
  t.ok(/-[0-9a-f]{4}\.local$/.test(s.host), 'host is a unique library-owned label')
  t.notEqual(s.host, os.hostname(), 'host does not reuse the bare OS hostname')
  t.equal(s.port, 3000)
  t.equal(s.fqdn, 'Foo Bar._http._tcp.local')
  t.equal(s.txt, undefined)
  t.equal(s.subtypes, undefined)
  t.equal(s.published, false)
  t.end()
})

test('protocol', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', port: 3000, protocol: 'udp' })
  t.deepEqual(s.protocol, 'udp')
  t.end()
})

test('host', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', port: 3000, host: 'example.com' })
  t.deepEqual(s.host, 'example.com')
  t.end()
})

test('txt', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', port: 3000, txt: { foo: 'bar' } })
  t.deepEqual(s.txt, { foo: 'bar' })
  t.end()
})

test('subtypes', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', port: 3000, subtypes: ['foo', 'bar'] })
  t.deepEqual(s.subtypes, ['foo', 'bar'])
  t.end()
})

test('_records() - minimal', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', protocol: 'tcp', port: 3000 })
  t.deepEqual(s.records(), [
    { data: s.fqdn, name: '_http._tcp.local', ttl: 28800, type: 'PTR', flush: false },
    { data: { port: 3000, target: s.host }, name: s.fqdn, ttl: 120, type: 'SRV', flush: true },
    { data: [Buffer.alloc(0)], name: s.fqdn, ttl: 4500, type: 'TXT', flush: true }
  ].concat(getAddressesRecords(s.host)))
  t.end()
})

test('_records() - everything', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'http', protocol: 'tcp', port: 3000, host: 'example.com', txt: { foo: 'bar' }, subtypes: ['foo', 'bar'] })
  t.deepEqual(s.records(), [
    { data: s.fqdn, name: '_http._tcp.local', ttl: 28800, type: 'PTR', flush: false },
    { data: { port: 3000, target: 'example.com' }, name: s.fqdn, ttl: 120, type: 'SRV', flush: true },
    { data: [Buffer.from('666f6f3d626172', 'hex')], name: s.fqdn, ttl: 4500, type: 'TXT', flush: true },
    { data: s.fqdn, name: '_foo._sub._http._tcp.local', ttl: 28800, type: 'PTR', flush: false },
    { data: s.fqdn, name: '_bar._sub._http._tcp.local', ttl: 28800, type: 'PTR', flush: false }
  ].concat(getAddressesRecords(s.host)))
  t.end()
})

test('service type must comply with RFC 6763 section 7.2', function (t) {
  const valid = ['http', 'a', 'companion-sat', 'abcdefghijklmno', 'switcher_ctrl']
  for (const type of valid) {
    t.doesNotThrow(function () {
      new Service({ name: 'Foo Bar', type, port: 3000 }) // eslint-disable-line no-new
    }, `accepts ${type}`)
  }

  const invalid = {
    'companion-satellite': /longer than 15 characters/,
    abcdefghijklmnop: /longer than 15 characters/,
    'foo.bar': /must not contain dots/
  }
  for (const [type, message] of Object.entries(invalid)) {
    t.throws(function () {
      new Service({ name: 'Foo Bar', type, port: 3000 }) // eslint-disable-line no-new
    }, message, `rejects ${type}`)
  }
  t.end()
})

test('allowInvalidType bypasses service type validation', function (t) {
  const s = new Service({ name: 'Foo Bar', type: 'companion-satellite', port: 3000, allowInvalidType: true })
  t.equal(s.type, '_companion-satellite._tcp')
  t.end()
})
