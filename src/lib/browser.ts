import KeyValue                                                     from './KeyValue'
import DnsTxt                                                       from './dns-txt'
import dnsEqual                                                     from './utils/dns-equal'
import { EventEmitter }                                             from 'events'
import { ServiceRecord }                                            from './service'
import { toString as ServiceToString }                              from './service-types'
import filterService                                                from './utils/filter-service'
import filterTxt                                                    from './utils/filter-txt'
import equalTxt                                                     from './utils/equal-txt'
import { RemoteInfo } from 'dgram'
import { parsePacketToServices } from './utils/parse-packet'

const TLD           = '.local'
const WILDCARD      = '_services._dns-sd._udp' + TLD

export interface BrowserConfig {
    type        : string
    name?       : string
    protocol?   : 'tcp' | 'udp'
    subtypes?   : string[]
    txt?        : KeyValue
}

export type BrowserOnUp = (service: DiscoveredService) => void

export interface DiscoveredService {
    fqdn: string
    name: string
    type: string | undefined

    subtypes: string[]

    protocol: 'tcp' | 'udp' | string | null | undefined

    addresses: string[]
    host: string
    port: number

    txt: Record<string, string>
    rawTxt: Array<string | Buffer> | undefined

    referer: RemoteInfo

    ttl: number | undefined
    lastSeen: number
}

export interface BrowserEvents {
    up: [service: DiscoveredService]
    down: [service: DiscoveredService]
    'srv-update': [newService: DiscoveredService, existingService: DiscoveredService]
    'txt-update': [newService: DiscoveredService, existingService: DiscoveredService]
}

/**
 * Start a browser
 *
 * The browser listens for services by querying for PTR records of a given
 * type, protocol and domain, e.g. _http._tcp.local.
 *
 * If no type is given, a wild card search is performed.
 *
 * An internal list of online services is kept which starts out empty. When
 * ever a new service is discovered, it's added to the list and an "up" event
 * is emitted with that service. When it's discovered that the service is no
 * longer available, it is removed from the list and a "down" event is emitted
 * with that service.
 */

export class Browser extends EventEmitter<BrowserEvents> {

    private mdns        : any
    private onresponse  : CallableFunction | undefined  = undefined

    private txt         : DnsTxt
    private name?       : string
    private txtQuery    : KeyValue | undefined
    private wildcard    : boolean   = false

    private _services    : DiscoveredService[] = []

    constructor(mdns: any, opts: BrowserConfig | BrowserOnUp | null, onup?: BrowserOnUp) {
        super()

        if (typeof opts === 'function') {
            onup = opts
            opts = null
        }

        this.mdns   = mdns
        this.txt    = new DnsTxt(opts !== null && opts.txt != null ? opts.txt : undefined)


        if (opts === null || opts.type === undefined) {
            this.name       = WILDCARD
            this.wildcard   = true
        } else {
            this.name = ServiceToString({ name: opts.type, protocol: opts.protocol || 'tcp'}) + TLD
            if (opts.name) this.name = opts.name + '.' + this.name
            this.wildcard = false
        }

        // Provide a txt query, filter binary key if provided
        if(opts != null && opts.txt !== undefined) this.txtQuery = filterTxt(opts.txt)

        if (onup) this.on('up', onup)

        this.start()
    }

    /**
     * Start looking for matching services.
     */
    public start() {
        if (this.onresponse || this.name === undefined) return

        var self = this

        // List of names for the browser to listen for. In a normal search this will
        // be the primary name stored on the browser. In case of a wildcard search
        // the names will be determined at runtime as responses come in.
        var nameMap: KeyValue = {}
        if (!this.wildcard) nameMap[this.name] = true

        this.onresponse = (packet: any, rinfo: RemoteInfo) => {
            if (self.wildcard) {
                packet.answers.forEach((answer: any) => {
                    if (answer.type !== 'PTR' || answer.name !== self.name || answer.name in nameMap) return
                    nameMap[answer.data] = true // TODO - isn't this a leak?
                    self.mdns.query(answer.data, 'PTR')
                })
            }

            const receiveTime = Date.now()

            Object.keys(nameMap).forEach(function (name) {
                // unregister all services shutting down
                self.goodbyes(name, packet).forEach(self.removeService.bind(self))

                console.log('packet', JSON.stringify(packet))

                // register all new services
                const matches = parsePacketToServices(self.txt, name, packet, rinfo, receiveTime)
                if (matches.length === 0) return

                matches.forEach((service) => {
                    const existingService = self._services.find((s) => dnsEqual(s.fqdn, service.fqdn))
                    if (existingService) {
                        existingService.lastSeen = service.lastSeen
                        self.updateServiceSrv(existingService, service)
                        self.updateServiceTxt(existingService, service)
                        return
                    }
                    self.addService(service)
                })
            })
        }

        this.mdns.on('response', this.onresponse)
        this.update()
    }

    /**
     * Stop looking for matching services.
     */
    public stop() {
        if (!this.onresponse) return

        this.mdns.removeListener('response', this.onresponse)
        this.onresponse = undefined
    }

    /**
     * Broadcast the query again.
     */
    public update() {
        this.mdns.query(this.name, 'PTR')
    }

    /**
     * Check any services for an expired TTL and emit stop events.
     */
    public expire() {
        const currentTime = Date.now()

        this._services = this._services.filter((service) => {
            if (!service.ttl) return true // No expiry

            const expireTime = service.lastSeen + service.ttl * 1000

            if (expireTime < currentTime) {
                this.emit('down', service)
                return false
            }

            return true
        })
    }

    /**
     * An array of services known by the browser to be online.
     */
    public get services() {
        return this._services;
    }

    private addService(service: DiscoveredService) {
        // Test if service allowed by TXT query
        if(filterService(service, this.txtQuery) === false) return
        this._services.push(service)
        this.emit('up', service)
    }

    private updateServiceSrv(existingService: DiscoveredService, newService: DiscoveredService) {
        // check if any properties derived from SRV are updated
        if (existingService.name !== newService.name 
            || existingService.host !== newService.host 
            || existingService.port !== newService.port
            || existingService.type !== newService.type
            || existingService.protocol !== newService.protocol
        ){
            // replace service
            this.replaceService(newService)

            this.emit('srv-update', newService, existingService);
        }
    }

    private updateServiceTxt(existingService: DiscoveredService, service: DiscoveredService) {
        // check if txt updated
        if (equalTxt(service.txt, existingService?.txt || {})) return
        // if the new service is not allowed by the txt query, remove it
        if(!filterService(service, this.txtQuery)) {
            this.removeService(service.fqdn)
            return
        }

        // replace service
        this.replaceService(service)
        
        this.emit('txt-update', service, existingService);
    }

    private replaceService(service: DiscoveredService) {
        this._services = this._services.map((s) =>{
            if (!dnsEqual(s.fqdn, service.fqdn)) return s
            return service
        })
    }

    private removeService(fqdn: string) {
        var service, index
        this._services.some(function (s, i) {
            if(dnsEqual(s.fqdn, fqdn)) {
                service = s
                index = i
                return true
            }
        })
        if (!service || index === undefined) return
        this._services.splice(index, 1)
        this.emit('down', service)
    }

    // PTR records with a TTL of 0 is considered a "goodbye" announcement. I.e. a
    // DNS response broadcasted when a service shuts down in order to let the
    // network know that the service is no longer going to be available.
    //
    // For more info see:
    // https://tools.ietf.org/html/rfc6762#section-8.4
    //
    // This function returns an array of all resource records considered a goodbye
    // record
    private goodbyes(name: string, packet: any) {
        return packet.answers.concat(packet.additionals)
        .filter((rr: ServiceRecord) => rr.type === 'PTR' && rr.ttl === 0 && dnsEqual(rr.name, name))
        .map((rr: ServiceRecord) => rr.data)
    }

   

}

export default Browser