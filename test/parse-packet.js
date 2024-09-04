'use strict'

const tape = require('tape')
const { DnsTxt } = require('../dist/lib/dns-txt')
const { parsePacketToServices } = require('../dist/lib/utils/parse-packet')

tape('parse blackmagic atem constellation hd', function (t) {
  const packet = {
    id: 0,
    type: 'response',
    flags: 0,
    flag_qr: true,
    opcode: 'QUERY',
    flag_aa: false,
    flag_tc: false,
    flag_rd: false,
    flag_ra: false,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    rcode: 'NOERROR',
    questions: [],
    answers: [
      {
        name: '_switcher_ctrl._udp.local',
        type: 'PTR',
        ttl: 4500,
        class: 'IN',
        flush: false,
        data: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local'
      }
    ],
    authorities: [],
    additionals: [
      {
        name: 'ATEM-2-ME-Constellation-HD.local',
        type: 'A',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.42.13.86'
      },
      {
        name: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local',
        type: 'SRV',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: {
          priority: 0,
          weight: 0,
          port: 9910,
          target: 'ATEM-2-ME-Constellation-HD.local'
        }
      },
      {
        name: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local',
        type: 'TXT',
        ttl: 4500,
        class: 'IN',
        flush: true,
        data: [
          Buffer.from([
            117, 110, 105, 113, 117, 101, 32, 105, 100, 61, 53, 51, 97, 102, 57,
            99, 51, 57, 48, 53, 54, 48, 52, 56, 53, 101, 56, 100, 101, 97, 54,
            99, 56, 55, 55, 101, 51, 99, 51, 98, 99, 56
          ])
        ]
      },
      {
        name: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local',
        type: 'NSEC',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: {
          nextDomain: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local',
          rrtypes: ['TXT', 'SRV']
        }
      },
      {
        name: 'ATEM-2-ME-Constellation-HD.local',
        type: 'NSEC',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: {
          nextDomain: 'ATEM-2-ME-Constellation-HD.local',
          rrtypes: ['A']
        }
      }
    ]
  }

  const txt = new DnsTxt()
  const matches = parsePacketToServices(
    txt,
    '_switcher_ctrl._udp.local',
    packet,
    'fake-remoteinfo',
    12345
  )

  t.ok(matches.length !== 0)
  t.deepEqual(matches, [
    {
      addresses: ['10.42.13.86'],
      subtypes: [],
      name: 'ATEM 2 M/E Constellation HD',
      fqdn: 'ATEM 2 M/E Constellation HD._switcher_ctrl._udp.local',
      type: 'switcher_ctrl',
      protocol: 'udp',
      host: 'ATEM-2-ME-Constellation-HD.local',
      port: 9910,
      referer: 'fake-remoteinfo',
      txt: { 'unique id': '53af9c390560485e8dea6c877e3c3bc8' },
      rawTxt: [
        Buffer.from([
          117, 110, 105, 113, 117, 101, 32, 105, 100, 61, 53, 51, 97, 102, 57,
          99, 51, 57, 48, 53, 54, 48, 52, 56, 53, 101, 56, 100, 101, 97, 54, 99,
          56, 55, 55, 101, 51, 99, 51, 98, 99, 56
        ])
      ],
      ttl: 4500,
      lastSeen: 12345
    }
  ])

  t.end()
})

tape('parse blackmagic atem slim 2me', function (t) {
  const packet = {
    id: 0,
    type: 'response',
    flags: 1024,
    flag_qr: true,
    opcode: 'QUERY',
    flag_aa: true,
    flag_tc: false,
    flag_rd: false,
    flag_ra: false,
    flag_z: false,
    flag_ad: false,
    flag_cd: false,
    rcode: 'NOERROR',
    questions: [],
    answers: [
      {
        name: '_blackmagic._tcp.local',
        type: 'PTR',
        ttl: 4500,
        class: 'IN',
        flush: false,
        data: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local'
      }
    ],
    authorities: [],
    additionals: [
      {
        name: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local',
        type: 'TXT',
        ttl: 4500,
        class: 'IN',
        flush: true,
        data: [
          Buffer.from([116, 120, 116, 118, 101, 114, 115, 61, 49]),
          Buffer.from([
            110, 97, 109, 101, 61, 66, 108, 97, 99, 107, 109, 97, 103, 105, 99,
            32, 65, 84, 69, 77, 32, 50, 32, 77, 47, 69, 32, 80, 114, 111, 100,
            117, 99, 116, 105, 111, 110, 32, 83, 119, 105, 116, 99, 104, 101,
            114
          ]),
          Buffer.from([
            99, 108, 97, 115, 115, 61, 65, 116, 101, 109, 83, 119, 105, 116, 99,
            104, 101, 114
          ]),
          Buffer.from([
            112, 114, 111, 116, 111, 99, 111, 108, 32, 118, 101, 114, 115, 105,
            111, 110, 61, 48, 46, 48
          ]),
          Buffer.from([
            105, 110, 116, 101, 114, 110, 97, 108, 32, 118, 101, 114, 115, 105,
            111, 110, 61, 67, 80, 85, 58, 102, 102, 45, 70, 87, 58, 48, 48, 50,
            56, 45, 69, 77, 58, 50, 101, 48, 55, 55, 97, 53, 99
          ]),
          Buffer.from([
            117, 110, 105, 113, 117, 101, 32, 105, 100, 61, 55, 99, 50, 101, 48,
            100, 48, 48, 54, 100, 97, 99
          ])
        ]
      },
      {
        name: 'ATEM-2ME-7c2e0d006dac.local',
        type: 'A',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: '10.42.13.99'
      },
      {
        name: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local',
        type: 'SRV',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: {
          priority: 0,
          weight: 0,
          port: 9910,
          target: 'ATEM-2ME-7c2e0d006dac.local'
        }
      },
      {
        name: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local',
        type: 'NSEC',
        ttl: 4500,
        class: 'IN',
        flush: true,
        data: {
          nextDomain: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local',
          rrtypes: ['TXT', 'SRV']
        }
      },
      {
        name: 'ATEM-2ME-7c2e0d006dac.local',
        type: 'NSEC',
        ttl: 120,
        class: 'IN',
        flush: true,
        data: { nextDomain: 'ATEM-2ME-7c2e0d006dac.local', rrtypes: ['A'] }
      }
    ]
  }

  const txt = new DnsTxt()
  const matches = parsePacketToServices(
    txt,
    '_blackmagic._tcp.local',
    packet,
    'fake-remoteinfo',
    12345
  )

  t.ok(matches.length !== 0)
  t.deepEqual(matches, [
    {
      addresses: ['10.42.13.99'],
      subtypes: [],
      name: 'ATEM 2 M/E Production Switcher',
      fqdn: 'ATEM 2 M/E Production Switcher._blackmagic._tcp.local',
      type: 'blackmagic',
      protocol: 'tcp',
      host: 'ATEM-2ME-7c2e0d006dac.local',
      port: 9910,
      referer: 'fake-remoteinfo',
      txt: {
        txtvers: '1',
        name: 'Blackmagic ATEM 2 M/E Production Switcher',
        class: 'AtemSwitcher',
        'protocol version': '0.0',
        'internal version': 'CPU:ff-FW:0028-EM:2e077a5c',
        'unique id': '7c2e0d006dac'
      },
      rawTxt: [
        Buffer.from([116, 120, 116, 118, 101, 114, 115, 61, 49]),
        Buffer.from([
          110, 97, 109, 101, 61, 66, 108, 97, 99, 107, 109, 97, 103, 105, 99,
          32, 65, 84, 69, 77, 32, 50, 32, 77, 47, 69, 32, 80, 114, 111, 100,
          117, 99, 116, 105, 111, 110, 32, 83, 119, 105, 116, 99, 104, 101,
          114
        ]),
        Buffer.from([
          99, 108, 97, 115, 115, 61, 65, 116, 101, 109, 83, 119, 105, 116, 99,
          104, 101, 114
        ]),
        Buffer.from([
          112, 114, 111, 116, 111, 99, 111, 108, 32, 118, 101, 114, 115, 105,
          111, 110, 61, 48, 46, 48
        ]),
        Buffer.from([
          105, 110, 116, 101, 114, 110, 97, 108, 32, 118, 101, 114, 115, 105,
          111, 110, 61, 67, 80, 85, 58, 102, 102, 45, 70, 87, 58, 48, 48, 50,
          56, 45, 69, 77, 58, 50, 101, 48, 55, 55, 97, 53, 99
        ]),
        Buffer.from([
          117, 110, 105, 113, 117, 101, 32, 105, 100, 61, 55, 99, 50, 101, 48,
          100, 48, 48, 54, 100, 97, 99
        ])
      ],
      ttl: 4500,
      lastSeen: 12345
    }
  ])

  t.end()
})
