import dnsEqual                                     from './utils/dns-equal'
import Server                                       from './mdns-server'
import Service, { ServiceConfig, ServiceRecord }    from './service'

export interface PublishOptions {
    announceOnInterval?: number
}

const REANNOUNCE_MAX_MS : number    = 60 * 60 * 1000
const REANNOUNCE_FACTOR : number    = 3
const ANNOUNCE_COUNT    : number    = 8
const noop = function () {}

export class Registry {

    private server      : Server
    private services    : Array<Service> = []

    constructor(server: Server) {
        this.server = server
    }

    public publish(config: ServiceConfig, options?: PublishOptions): Service {

        function start(service: Service, registry: Registry, opts?: { probe: boolean }) {
            if (service.activated) return
            service.activated = true
        
            registry.services.push(service)
        
            if(!(service instanceof Service)) return
        
            if(opts?.probe) {
                const probeThenAnnounce = () => registry.probe(registry.server, service, (exists: boolean) => {
                    if(exists) {
                        // The name belongs to another host, so try the next one. Nothing has been sent for the
                        // taken name, so there is nothing to withdraw: goodbyes for it would match the other
                        // host's PTR record and remove it from every cache on the network
                        service.renameAfterConflict()
                        service.emit('rename', service.name)
                        probeThenAnnounce()
                        return
                    }
                    registry.announce(registry.server, service, options)
                })
                probeThenAnnounce()
            } else {
                registry.announce(registry.server, service, options)
            }
        }
        
        function stop(service: Service, registry: Registry, callback?: CallableFunction) {
            if (!callback) callback = noop
            if (!service.activated) return process.nextTick(callback)
        
            if(!(service instanceof Service)) return process.nextTick(callback)
            registry.teardown(registry.server, service, callback)
          
            const index = registry.services.indexOf(service)
            if (index !== -1) registry.services.splice(index, 1)
        }
        
        const service   = new Service(config)
        service.start   = start.bind(null, service, this)
        service.stop    = stop.bind(null, service, this)
        service.start({ probe: config.probe !== false })
        return service
    }

    public unpublishAll(callback: CallableFunction | undefined) {
        this.teardown(this.server, this.services, callback)
        this.services = []
    }

    public destroy() {
        this.services.map(service => service.destroyed = true)
    }

    /**
     * Check if a service name is already in use on the network.
     *
     * Used before announcing the new service.
     *
     * To guard against race conditions where multiple services are started
     * simultaneously on the network, wait a random amount of time (between
     * 0 and 250 ms) before probing.
     *
     */
    private probe(server: Server, service: Service, callback: CallableFunction) {
        const mdns = server.mdns
        var sent    : boolean   = false
        var retries : number    = 0
        var timer   : any
    
        const send = () => {
            // abort if the service have or is being stopped in the meantime
            if (!service.activated || service.destroyed) return
        
            // Include the records we propose to use in the Authority Section, so that a host probing
            // for the same name at the same time can tell which of us should back off (RFC 6762 section 8.2)
            const authorities = service.records().filter((record) => dnsEqual(record.name, service.fqdn))
            mdns.query({ questions: [{ name: service.fqdn, type: 'ANY' }], authorities }, function () {
                // This function will optionally be called with an error object. We'll
                // just silently ignore it and retry as we normally would
                sent = true
                timer = setTimeout(++retries < 3 ? send : done, 250)
                timer.unref()
            })
        }

        const onresponse = (packet: any) => {
            // Apparently conflicting Multicast DNS responses received *before*
            // the first probe packet is sent MUST be silently ignored (see
            // discussion of stale probe packets in RFC 6762 Section 8.2,
            // "Simultaneous Probe Tiebreaking" at
            // https://tools.ietf.org/html/rfc6762#section-8.2
            if (!sent) return
            if (packet.answers.some(matchRR) || packet.additionals.some(matchRR)) done(true)
        }
        
        // Only a live record that differs from what we propose is a conflict (RFC 6762 section 9). A goodbye, or a
        // copy of our own records, doesn't mean another host has the name
        const matchRR = (rr: any) => {
            if (!dnsEqual(rr.name, service.fqdn) || rr.ttl === 0) return false
            return !service.records().some((ours) => server.isSameRecord(ours, rr))
        }
        
        const done = (exists: boolean) => {
            mdns.removeListener('response', onresponse)
            clearTimeout(timer)
            callback(!!exists)
        }

        mdns.on('response', onresponse)
        setTimeout(send, Math.random() * 250)
    }


    /**
     * Initial service announcement
     *
     * Used to announce new services when they are first registered.
     *
     * Broadcasts right away, then 1 second later, then at intervals tripling each time,
     * for up to eight announcements in total (RFC 6762 section 8.3).
     */
    private announce (server: Server, service: Service, options: PublishOptions | undefined) {
        var delay = 1000
        var sent = 0
        var packet: Array<ServiceRecord> = service.records()
    
        // Register the records
        server.register(packet)

        const broadcast = () => {
            if (!service.activated || service.destroyed) return

            server.markMulticast(packet)
            server.mdns.respond(packet, function () {
                // This function will optionally be called with an error object. We'll
                // just silently ignore it and retry as we normally would
                if (!service.published) {
                    service.activated = true
                    service.published = true
                    service.emit('up')
                }
                
                sent++
                if (service.destroyed) return

                if (options?.announceOnInterval) {
                    if (options.announceOnInterval > 0 && options.announceOnInterval < REANNOUNCE_MAX_MS) {
                        setTimeout(broadcast, options.announceOnInterval).unref()
                    }
                } else if (sent < ANNOUNCE_COUNT) {
                    setTimeout(broadcast, delay).unref()
                    delay = delay * REANNOUNCE_FACTOR
                }
            })
        }
        broadcast()
    }
  
    /**
     * Stop the given services
     *
     * Besides removing a service from the mDNS registry, a "goodbye"
     * message is sent for each service to let the network know about the
     * shutdown.
     */
    private teardown (server: Server, services: Array<Service> | Service, callback: any) {
        if (!Array.isArray(services)) services = [services]
    
        services = services.filter((service: Service) =>  service.activated) // ignore services not currently starting or started
    
        var records: any = services.flatMap(function (service) {
            service.activated = false
            var records = service.records()
            records.forEach((record: ServiceRecord) => {
                record.ttl = 0 // prepare goodbye message
            })
            return records
        })
    
        if (records.length === 0) return callback && process.nextTick(callback)
        server.unregister(records)
    
        // send goodbye message
        server.mdns.respond(records, function () {
            (services as Array<Service>).forEach(function (service) {
                service.published = false
            })
            if (typeof callback === "function") {
                callback.apply(null, arguments)
            }
        })
    }
}

export default Registry
