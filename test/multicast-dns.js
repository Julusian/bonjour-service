'use strict'

const os = require('os')
const { EventEmitter } = require('events')
const tape = require('tape')
const mdns = require('../multicast-dns')
const { Bonjour } = require('../dist')

// Records the interface each packet goes out of. `failOn` lists interfaces whose sends fail
class FakeSocket extends EventEmitter {
  constructor (failOn = []) {
    super()
    this.failOn = failOn
    this.iface = null
    this.sends = []
  }

  bind (port, iface, cb) {
    setImmediate(() => {
      this.emit('listening')
      cb()
    })
  }

  address () { return { address: '0.0.0.0', port: 5353 } }
  addMembership () {}
  dropMembership () {}
  setMulticastTTL () {}
  setMulticastLoopback () {}
  setMulticastInterface (iface) { this.iface = iface }
  send (buf, offset, length, port, address, cb) {
    const iface = this.iface
    this.sends.push({ iface, address, port })
    // Like dgram, the packet is only sent on a later tick
    setImmediate(() => cb(this.failOn.includes(iface) ? new Error(`send failed on ${iface}`) : null))
  }

  close (cb) { if (cb) cb() }
}

const v4 = (address, internal = false) => ({ address, family: 'IPv4', internal, mac: '00:11:22:33:44:55' })
const v6 = (address) => ({ address, family: 'IPv6', internal: false, mac: '00:11:22:33:44:55' })

// Run with os.networkInterfaces() giving `interfaces`
const withInterfaces = function (interfaces, fn) {
  const original = os.networkInterfaces
  os.networkInterfaces = () => interfaces
  return fn(() => { os.networkInterfaces = original })
}

const HYPER_V = {
  lo: [v4('127.0.0.1', true)],
  'vEthernet (External)': [v6('fe80::1'), v4('192.168.20.100'), v4('192.168.20.101')],
  'vEthernet (Default Switch)': [v4('172.31.16.1')],
  'Ethernet 2': [v6('fe80::2')]
}

tape('multicast goes out of the first IPv4 address of each interface other than loopback', function (t) {
  withInterfaces(HYPER_V, (restore) => {
    const socket = new FakeSocket()
    const dns = mdns({ socket })
    dns.respond([{ name: 'foo.local', type: 'A', data: '192.168.20.100' }], function (err) {
      restore()
      t.error(err)
      t.deepEqual(socket.sends, [
        { iface: '192.168.20.100', address: '224.0.0.251', port: 5353 },
        { iface: '172.31.16.1', address: '224.0.0.251', port: 5353 }
      ])
      dns.destroy()
      t.end()
    })
  })
})

tape('packets sent together go out one after another, so each keeps its interface', function (t) {
  withInterfaces(HYPER_V, (restore) => {
    const socket = new FakeSocket()
    const dns = mdns({ socket })
    const done = []
    const finish = () => {
      if (done.length < 2) return
      restore()
      t.deepEqual(done, ['a', 'b'], 'callbacks in order')
      t.deepEqual(socket.sends.map((s) => s.iface), ['192.168.20.100', '172.31.16.1', '192.168.20.100', '172.31.16.1'])
      dns.destroy()
      t.end()
    }
    dns.query('a.local', 'A', () => { done.push('a'); finish() })
    dns.query('b.local', 'A', () => { done.push('b'); finish() })
  })
})

tape('a failure on some interfaces is a warning, and only an error when none worked', function (t) {
  withInterfaces(HYPER_V, (restore) => {
    const warnings = []
    const partial = mdns({ socket: new FakeSocket(['172.31.16.1']) })
    partial.on('warning', (err) => warnings.push(err.message))
    partial.query('a.local', 'A', function (err) {
      t.error(err, 'no error when one interface worked')
      t.deepEqual(warnings, ['send failed on 172.31.16.1'])
      partial.destroy()

      const failing = mdns({ socket: new FakeSocket(['192.168.20.100', '172.31.16.1']) })
      failing.on('warning', () => {})
      failing.query('a.local', 'A', function (err) {
        restore()
        t.equal(err && err.message, 'send failed on 172.31.16.1', 'error when none worked')
        failing.destroy()
        t.end()
      })
    })
  })
})

tape('without an interface other than loopback, the OS picks', function (t) {
  withInterfaces({ lo: [v4('127.0.0.1', true)] }, (restore) => {
    const socket = new FakeSocket()
    const dns = mdns({ socket })
    dns.query('a.local', 'A', function (err) {
      restore()
      t.error(err)
      t.deepEqual(socket.sends, [{ iface: null, address: '224.0.0.251', port: 5353 }])
      dns.destroy()
      t.end()
    })
  })
})

tape('an explicit interface, unicast, and multicast: false are sent once', function (t) {
  withInterfaces(HYPER_V, (restore) => {
    const explicit = new FakeSocket()
    const a = mdns({ socket: explicit, interface: '192.168.20.100' })
    a.query('a.local', 'A', function () {
      t.deepEqual(explicit.sends.map((s) => s.address), ['224.0.0.251'], 'explicit interface')
      a.destroy()

      const unicast = new FakeSocket()
      const b = mdns({ socket: unicast })
      b.respond([], { address: '192.168.20.50', port: 12345 }, function () {
        t.deepEqual(unicast.sends.map((s) => s.address), ['192.168.20.50'], 'unicast')
        b.destroy()

        const noMulticast = new FakeSocket()
        const c = mdns({ socket: noMulticast, ip: '127.0.0.1', multicast: false })
        c.query('a.local', 'A', function () {
          restore()
          t.deepEqual(noMulticast.sends.map((s) => s.address), ['127.0.0.1'], 'multicast: false')
          c.destroy()
          t.end()
        })
      })
    })
  })
})

tape('a failed announcement is passed to the error callback, and ignored without one', function (t) {
  withInterfaces(HYPER_V, (restore) => {
    const errors = []
    const reported = new Bonjour({ socket: new FakeSocket(['192.168.20.100', '172.31.16.1']) }, (err) => errors.push(err.message))
    reported.server.mdns.on('warning', () => {})
    const a = reported.publish({ name: 'a', type: 'http', port: 3000, probe: false })
    a.on('up', function () {
      t.deepEqual(errors, ['send failed on 172.31.16.1'], 'reported')
      reported.destroy()

      const silent = new Bonjour({ socket: new FakeSocket(['192.168.20.100', '172.31.16.1']) })
      silent.server.mdns.on('warning', () => {})
      const b = silent.publish({ name: 'b', type: 'http', port: 3000, probe: false })
      b.on('up', function () {
        restore()
        t.pass('did not throw')
        silent.destroy()
        t.end()
      })
    })
  })
})
