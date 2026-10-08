import { ServiceConfig, ServiceRecord }     from './service'
import MulticastDNS                         from '../../multicast-dns'
import KeyValue                             from './KeyValue'
import deepEqual                            from 'fast-deep-equal/es6'
import dnsEqual                             from './utils/dns-equal'

/**
 * Minimum interval between multicasts of the same record (RFC 6762 section 6)
 */
const MULTICAST_INTERVAL_MS : number = 1000

interface MulticastEntry {
    type    : string
    name    : string
    time    : number
}

export class Server {

    public mdns             : any
    private registry        : KeyValue = {}
    private errorCallback   : Function
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
            this.registry[type] = this.registry[type].filter((i: ServiceRecord) => i.name !== record.name)

            // Forget when these were last sent, so a later re-publish isn't held back
            for (const [key, entry] of this.lastMulticast) {
                if (entry.type === type && entry.name === record.name) this.lastMulticast.delete(key)
            }
            this.pendingAnswers = this.pendingAnswers.filter((i: ServiceRecord) => i.type !== type || i.name !== record.name)
            if (this.pendingAnswers.length === 0) this.clearPending()
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

    private respondToQuery(query: KeyValue): void {
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

        answers = answers.filter(this.unique())
        if (answers.length === 0) return

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

        additionals = additionals
          .filter(this.unique())
          .filter((record: any) => answers.indexOf(record) === -1)

        this.markMulticast(answers)

        this.mdns.respond({ answers: answers, additionals: additionals }, (err: any) => {
          if (err) {
              this.errorCallback(err);
          }
        })
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
