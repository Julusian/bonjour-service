import KeyValue     from '../KeyValue'
import { DiscoveredService } from '../browser'

/**
 * Handles service filtering, true when valid or not filter provided, false when filter does not match
 * @returns boolean
 */
export default (service: DiscoveredService, txtQuery: KeyValue | undefined): boolean => {
    if(txtQuery === undefined) return true

    const queryEntries = Object.entries(txtQuery)
    if (queryEntries.length === 0) return true


    for (const [key, value] of queryEntries) {
        const queryValue = service.txt[key]
        if (queryValue === undefined || value != queryValue) return false
    }

    return true
}