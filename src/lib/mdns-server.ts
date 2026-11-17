import { ServiceConfig, ServiceRecord }     from './service'
import MulticastDNS                         from '../../multicast-dns'
import KeyValue                             from './KeyValue'
import deepEqual                            from 'fast-deep-equal/es6'
import dnsEqual                             from './utils/dns-equal'
import { RemoteInfo }                       from 'dgram'

/**
 * Minimum interval between multicasts of the same record (RFC 6762 section 6)
 */
const MULTICAST_INTERVAL_MS : number = 1000

/**
 * Minimum interval between multicasts of the same record when answering probes (RFC 6762 section 6)
 */
const PROBE_REPLY_INTERVAL_MS : number = 250

/**
 * Maximum TTL in replies to legacy unicast queries (RFC 6762 section 6.7)
 */
const LEGACY_UNICAST_TTL    : number = 10

/**
 * Name queried to list the service types on the network (RFC 6763 section 9)
 */
const SERVICE_TYPE_ENUMERATION : string = '_services._dns-sd._udp.local'

interface MulticastEntry {
    type    : string
    name    : string
    time    : number
}

export class Server {

    public mdns             : any
    // The mDNS port we listen on. Queries from any other port are legacy unicast queries
    private port            : number
    private registry        : KeyValue = {}
    private errorCallback   : Function
    // Failing to send a packet isn't fatal, so is only reported to a callback given by the user
    private sendErrorCallback : Function | null
    // When each record (by name, type and data) was last multicast, for rate limiting replies
    private lastMulticast   : Map<string, MulticastEntry> = new Map()

    // Answers held back by the rate limit, sent together once they are all allowed again
    private pendingAnswers  : Array<ServiceRecord> = []
    private pendingTime     : number = 0
    private cancelPending   : (() => void) | null = null

    /**
     * Clock and timer used for reply rate limiting. Only replaced by tests.
     * @internal
     */
    public now              : () => number = Date.now
    /** @internal */
    public schedule         : (fn: () => void, ms: number) => () => void = (fn, ms) => {
        const timer = setTimeout(fn, ms)
        timer.unref()
        return () => clearTimeout(timer)
    }

    constructor(opts: Partial<ServiceConfig>, errorCallback?: Function | undefined) {
        this.errorCallback = errorCallback ?? function(err: any) { throw err }
        this.sendErrorCallback = errorCallback ?? null
        const port = (opts as any).port
        this.port = typeof port === 'number' ? port : 5353
        this.mdns = MulticastDNS(opts as any)
        this.mdns.setMaxListeners(0)
        this.mdns.on('query', this.respondToQuery.bind(this))
        // multicast-dns emits `error` for fatal socket failures, such as the socket failing
        // to bind (EADDRINUSE/EACCES). Without a listener node treats these as uncaught
        // exceptions and terminates the process, so route them to the error callback instead.
        this.mdns.on('error', (err: any) => this.errorCallback(err))
    }

    public destroy(callback?: CallableFunction) {
        this.clearPending()
        this.mdns.destroy(callback)
    }

    public register(records: Array<ServiceRecord> | ServiceRecord) {
        // Register a record
        const shouldRegister = (record: ServiceRecord) => {
            var subRegistry = this.registry[record.type]
            if (!subRegistry) {
                subRegistry = this.registry[record.type] = []
            } else if(subRegistry.some(this.isDuplicateRecord(record))) {
                return
            }
            subRegistry.push(record)

            // List the service type, for service type enumeration queries
            if (this.isServiceTypePTR(record)) {
                shouldRegister({ name: SERVICE_TYPE_ENUMERATION, type: 'PTR', ttl: record.ttl, flush: false, data: record.name })
            }
        }

        if(Array.isArray(records)) {
            // Multiple records
            records.forEach(shouldRegister)
        } else {
            // Single record
            shouldRegister(records as ServiceRecord)
        }
    }

    public unregister(records: Array<ServiceRecord> | ServiceRecord) {
        // Unregister a record
        const shouldUnregister = (record: ServiceRecord) => {
            let type = record.type
            if(!(type in this.registry)) {
                return
            }
            // Match on data as well as name, as other services share PTR names such as `_http._tcp.local`
            const isRecord = this.isDuplicateRecord(record)
            this.registry[type] = this.registry[type].filter((i: ServiceRecord) => !isRecord(i))

            // Forget when this was last sent, so a later re-publish isn't held back
            this.lastMulticast.delete(this.multicastKey(record))
            this.pendingAnswers = this.pendingAnswers.filter((i: ServiceRecord) => !isRecord(i))
            if (this.pendingAnswers.length === 0) this.clearPending()

            // Stop listing the service type once no services of that type remain
            if (this.isServiceTypePTR(record) && !this.registry.PTR.some((i: ServiceRecord) => this.isServiceTypePTR(i) && dnsEqual(i.name, record.name))) {
                const listing = this.registry.PTR.find((i: ServiceRecord) => i.name === SERVICE_TYPE_ENUMERATION && dnsEqual(i.data, record.name))
                if (listing) shouldUnregister(listing)
            }
        }

        if(Array.isArray(records)) {
            // Multiple records
            records.forEach(shouldUnregister)
        } else {
            // Single record
            shouldUnregister(records as ServiceRecord)
        }
    }

    /**
     * Whether this is the PTR record listing a service under its type, e.g. `_http._tcp.local`,
     * rather than a subtype or service type enumeration record
     */
    private isServiceTypePTR(record: ServiceRecord): boolean {
        return record.type === 'PTR' && record.name !== SERVICE_TYPE_ENUMERATION && !record.name.includes('._sub.')
    }

    /**
     * Note that the given records have just been multicast, so that queries arriving
     * shortly afterwards don't cause them to be sent again.
     */
    public markMulticast(records: Array<ServiceRecord>): void {
        const now = this.now()
        this.pruneMulticast(now)
        records.forEach((record) => {
            this.lastMulticast.set(this.multicastKey(record), { type: record.type, name: record.name, time: now })
        })
    }

    private respondToQuery(query: KeyValue, rinfo?: RemoteInfo): void {
        const now = this.now()

        // generate the answers section, for all questions in the packet
        var answers: Array<any> = []
        query.questions.forEach((question: any) => {
            var type = question.type
            var name = question.name

            answers = answers.concat(type === 'ANY'
              ? Object.keys(this.registry).map(this.recordsFor.bind(this, name)).flat(1)
              : this.recordsFor(name, type))
        })

        // Known-Answer Suppression: leave out answers the querier already holds with at least
        // half their TTL remaining (RFC 6762 section 7.1)
        const knownAnswers: Array<any> = query.answers ?? []
        answers = answers
            .filter(this.unique())
            .filter((record) => !knownAnswers.some((known) => known.ttl >= record.ttl / 2 && this.isSameRecord(record, known)))
        if (answers.length === 0) return

        if (rinfo && typeof rinfo.port === 'number' && rinfo.port !== this.port) {
            this.sendLegacyReply(query, answers, rinfo)
            return
        }

        // Answering a probe defends the name, so must reach the prober before it finishes probing. That is allowed
        // once per 250ms rather than once a second (RFC 6762 section 6)
        const isProbe = Array.isArray(query.authorities) && query.authorities.length > 0
        if (isProbe && !answers.some((record) => this.multicastAllowedAt(record) - MULTICAST_INTERVAL_MS + PROBE_REPLY_INTERVAL_MS > now)) {
            this.sendReply(answers)
            return
        }

        // A record must not be multicast again within a second of the last time (RFC 6762 section 6).
        // Rather than dropping those answers, which would leave a client that missed the earlier
        // packet with a partial reply, hold the whole reply until all of its answers are allowed.
        // Queries arriving in the meantime are merged into the same held reply.
        if (this.pendingAnswers.length > 0 || answers.some((record) => this.multicastAllowedAt(record) > now)) {
            this.deferReply(answers)
        } else {
            this.sendReply(answers)
        }
    }

    private deferReply(answers: Array<ServiceRecord>): void {
        this.pendingAnswers = this.pendingAnswers.concat(answers).filter(this.unique())

        const sendAt = Math.max(...this.pendingAnswers.map((record) => this.multicastAllowedAt(record)))
        if (this.cancelPending && sendAt <= this.pendingTime) return

        if (this.cancelPending) this.cancelPending()
        this.pendingTime = sendAt
        this.cancelPending = this.schedule(() => this.flushPending(), Math.max(0, sendAt - this.now()))
    }

    private flushPending(): void {
        const now = this.now()
        const answers = this.pendingAnswers
            // drop anything unpublished in the meantime
            .filter((record) => (this.registry[record.type] ?? []).indexOf(record) !== -1)
            // and anything that has gone out in the meantime, such as a re-announcement
            .filter((record) => this.multicastAllowedAt(record) <= now)
        this.clearPending()

        if (answers.length > 0) this.sendReply(answers)
    }

    private clearPending(): void {
        if (this.cancelPending) this.cancelPending()
        this.cancelPending = null
        this.pendingAnswers = []
        this.pendingTime = 0
    }

    private sendReply(answers: Array<ServiceRecord>): void {
        const additionals = this.additionalsFor(answers)

        this.markMulticast(answers)

        this.mdns.respond({ answers: answers, additionals: additionals }, (err: any) => this.reportSendError(err))
    }

    /**
     * Reply to a query from a simple resolver not listening on the mDNS port (RFC 6762 section 6.7).
     * This goes straight back to the querier by unicast, so is not rate limited. It must look like
     * a conventional unicast DNS reply: repeating the query ID and questions, without the cache-flush
     * bit, and with short TTLs as the resolver won't see later updates.
     */
    private sendLegacyReply(query: KeyValue, answers: Array<ServiceRecord>, rinfo: RemoteInfo): void {
        const legacy = (record: ServiceRecord): ServiceRecord => ({
            ...record,
            ttl     : Math.min(record.ttl, LEGACY_UNICAST_TTL),
            flush   : false
        })

        this.mdns.respond({
            id          : query.id,
            questions   : query.questions,
            answers     : answers.map(legacy),
            additionals : this.additionalsFor(answers).map(legacy)
        }, { address: rinfo.address, port: rinfo.port }, (err: any) => this.reportSendError(err))
    }

    /**
     * Report a failure to send a packet, if the user gave an error callback
     * @internal
     */
    public reportSendError(err: any): void {
        if (err && this.sendErrorCallback) this.sendErrorCallback(err)
    }

    private additionalsFor(answers: Array<ServiceRecord>): Array<ServiceRecord> {
        // generate the additionals section, with the records a resolver will need next (RFC 6763 section 12)
        var additionals: Array<any> = []
        answers.forEach((answer: any) => {
          if (answer.type !== 'PTR') return
          additionals = additionals
            .concat(this.recordsFor(answer.data, 'SRV'))
            .concat(this.recordsFor(answer.data, 'TXT'))
        })

        // to populate the A and AAAA records, we need to get a set of unique
        // targets from the SRV records
        answers.concat(additionals)
          .filter((record: any) => record.type === 'SRV')
          .map((record: any) => record.data.target)
          .filter(this.unique())
          .forEach((target: string) => {
            additionals = additionals
              .concat(this.recordsFor(target, 'A'))
              .concat(this.recordsFor(target, 'AAAA'))
          })

        return additionals
          .filter(this.unique())
          .filter((record: any) => answers.indexOf(record) === -1)
    }

    private multicastKey(record: ServiceRecord): string {
        return JSON.stringify([record.type, record.name.toLowerCase(), record.data])
    }

    private multicastAllowedAt(record: ServiceRecord): number {
        const entry = this.lastMulticast.get(this.multicastKey(record))
        return entry === undefined ? 0 : entry.time + MULTICAST_INTERVAL_MS
    }

    private pruneMulticast(now: number): void {
        for (const [key, entry] of this.lastMulticast) {
            if (now - entry.time >= MULTICAST_INTERVAL_MS) this.lastMulticast.delete(key)
        }
    }

    private recordsFor(name: string, type: string): Array<ServiceRecord> {
        if (!(type in this.registry)) {
            return []
        }

        return this.registry[type].filter((record: ServiceRecord) => {
          var _name = ~name.indexOf('.') ? record.name : record.name.split('.')[0]
          return dnsEqual(_name, name)
        })
    }

    private isDuplicateRecord (a: ServiceRecord): (b: ServiceRecord) => boolean {
        return (b: ServiceRecord) => {
            return a.type === b.type &&
                a.name === b.name &&
                deepEqual(a.data, b.data)
        }
    }

    /**
     * Compare one of our records with one decoded from a packet, ignoring the TTL
     * @internal
     */
    public isSameRecord(ours: ServiceRecord, theirs: any): boolean {
        if (ours.type !== theirs.type || !dnsEqual(ours.name, theirs.name)) return false
        switch (ours.type) {
            case 'PTR':
                return typeof theirs.data === 'string' && dnsEqual(ours.data, theirs.data)
            case 'SRV':
                return theirs.data?.port === ours.data.port && typeof theirs.data.target === 'string' && dnsEqual(ours.data.target, theirs.data.target)
            case 'TXT': {
                const a = [].concat(ours.data).map((i: any) => Buffer.from(i))
                const b = [].concat(theirs.data).map((i: any) => Buffer.from(i))
                return a.length === b.length && a.every((buf: Buffer, i: number) => buf.equals(b[i]))
            }
            default:
                return deepEqual(ours.data, theirs.data)
        }
    }

    private unique(): (obj: any) => boolean {
        var set: Array<any> = []
        return (obj: any) => {
            if (~set.indexOf(obj)) return false
            set.push(obj)
            return true
        }
    }

}

export default Server
