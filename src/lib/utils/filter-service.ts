import KeyValue     from '../KeyValue'
import { DiscoveredService } from '../browser'

/**
 * Handles service filtering, true when valid or not filter provided, false when filter does not match
 * @returns boolean
 */
export default (service: DiscoveredService, txtQuery: KeyValue | undefined): boolean => {
    if(txtQuery === undefined) return true
    let serviceTxt = service.txt
    let query = Object.entries(txtQuery)
        .map(([key, value]) => {
            let queryValue = serviceTxt[key]
            if(queryValue === undefined) return false
            if(value != queryValue) return false
            return true
        })
    if(query.length == 0) return true
    if(query.includes(false)) return false
    return true
}