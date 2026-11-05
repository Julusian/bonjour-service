'use strict'

const tape = require('tape')
const { DnsTxt } = require('../dist/lib/dns-txt')

const decode = (...strings) => new DnsTxt().decodeAll(strings.map((s) => Buffer.from(s)))

tape('encode - no data gives a single empty string, not an empty record', function (t) {
  t.deepEqual(new DnsTxt().encode({}), [Buffer.alloc(0)])
  t.deepEqual(new DnsTxt().encode(), [Buffer.alloc(0)])
  t.deepEqual(new DnsTxt().encode({ foo: 'bar' }), [Buffer.from('foo=bar')])
  t.end()
})

tape('decode - values', function (t) {
  t.deepEqual(decode('foo=bar'), { foo: 'bar' })
  t.deepEqual(decode('foo=bar=baz'), { foo: 'bar=baz' }, 'value may contain =')
  t.deepEqual(decode('foo='), { foo: '' }, 'empty value')
  t.deepEqual(decode('a=1'), { a: '1' }, 'one letter key')
  t.end()
})

tape('decode - boolean attributes', function (t) {
  t.deepEqual(decode('flag'), { flag: undefined })
  t.ok('a' in decode('a'), 'one letter boolean attribute is kept')
  t.end()
})

tape('decode - strings without a key, and empty strings, are ignored', function (t) {
  t.deepEqual(decode('=foo', 'bar=baz'), { bar: 'baz' })
  t.deepEqual(decode(''), {})
  t.end()
})

tape('decode - only the first occurrence of a key counts, ignoring case', function (t) {
  t.deepEqual(decode('foo=1', 'foo=2'), { foo: '1' })
  t.deepEqual(decode('Foo=1', 'FOO=2'), { Foo: '1' })
  t.end()
})
