'use strict'

const { EventEmitter } = require('events')
const tape = require('tape')
const { Bonjour } = require('../dist')

// Minimal stand-in for a dgram socket, so a bind failure can be simulated
// without needing to actually hold port 5353
class FakeSocket extends EventEmitter {
  constructor (bindError) {
    super()
    this.bindError = bindError
    this.closed = false
  }

  bind (port, iface, cb) {
    setImmediate(() => {
      if (this.bindError) this.emit('error', this.bindError)
      else {
        cb()
        this.emit('listening')
      }
    })
  }

  address () { return { address: '0.0.0.0', port: 5353 } }
  addMembership () {}
  dropMembership () {}
  setMulticastTTL () {}
  setMulticastLoopback () {}
  setMulticastInterface () {}
  send (buf, offset, length, port, address, cb) { if (cb) cb() }
  close (cb) { this.closed = true; if (cb) cb() }
}

tape('socket bind error is passed to the error callback', function (t) {
  const bindError = new Error('bind failed')
  bindError.code = 'EADDRINUSE'

  const errors = []
  const bonjour = new Bonjour({ socket: new FakeSocket(bindError) }, function (err) {
    errors.push(err)
  })

  setTimeout(function () {
    t.deepEqual(errors, [bindError], 'error callback called once with the bind error')
    bonjour.destroy()
    t.end()
  }, 50)
})

tape('socket error after bind is passed to the error callback', function (t) {
  const socket = new FakeSocket()
  const errors = []
  const bonjour = new Bonjour({ socket }, function (err) {
    errors.push(err)
  })

  const socketError = new Error('no access')
  socketError.code = 'EACCES'

  setTimeout(function () {
    socket.emit('error', socketError)
    t.deepEqual(errors, [socketError], 'error callback called with the socket error')
    bonjour.destroy()
    t.end()
  }, 50)
})
