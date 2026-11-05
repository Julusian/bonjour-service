'use strict'

import KeyValue         from './KeyValue'

export class DnsTxt {

    private binary: boolean

    constructor(opts: KeyValue = {}) {
        this.binary = opts ? opts.binary : false
    }

    /**
     * Encode the KeyValue to buffer
     * @param data 
     * @returns 
     */
    public encode(data: KeyValue = {}) {
        const items = Object.entries(data)
        .map(([key, value]) => {
            let item: string = `${key}=${value}`
            return Buffer.from(item)
        })
        // An empty TXT record is not allowed, so use a single empty string instead (RFC 6763 section 6.1)
        return items.length > 0 ? items : [Buffer.alloc(0)]
    }

    /**
     * Decode the buffer to KeyValue
     * @param buffer 
     * @returns 
     */
    public decode(buffer: Buffer | string): KeyValue {
        const data: KeyValue = {}
        // Format buffer to KeyValue
        try {
            let format  : string        = buffer.toString()
            let index   : number        = format.indexOf('=')
            if (index === -1) {
                // A boolean attribute, present without a value
                data[format] = undefined
            } else if (index > 0) {
                // Strings starting with `=` have no key, and are ignored (RFC 6763 section 6.4)
                data[format.slice(0, index)] = format.slice(index + 1)
            }
        } catch(_) {}
        // Return data a KeyValue
        return data
    }

    /**
     * Decode all buffer items to KeyValye
     * @param buffer 
     * @returns 
     */
    public decodeAll(buffer: Array<Buffer | string>) {
        return buffer
        .filter(i => i.length > 0)
        .map(i => this.decode(i))
        .reduce((prev, curr) => {
            const obj         = prev
            for (const [key, value] of Object.entries(curr)) {
                // Keys are case insensitive, and only the first occurrence counts (RFC 6763 section 6.4)
                const lower = key.toLowerCase()
                if (Object.keys(obj).some((existing) => existing.toLowerCase() === lower)) continue
                obj[key] = value
            }
            return obj
        }, {})
    }

}

export default DnsTxt
