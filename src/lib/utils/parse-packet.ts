import type { ResponsePacket } from "../../../multicast-dns";
import type { DiscoveredService } from "../browser";
import type { RemoteInfo } from "dgram";
import dnsEqual from "./dns-equal";
import { toType as ServiceToType } from "../service-types";
import DnsTxt from "../dns-txt";

// subytpes are in additional PTR records, with identical service names
//
// Note that only one subtype is allowed per record, but there may be multiple records
//
// For more info see:
// https://tools.ietf.org/html/rfc6763#section-7.1
//  Selective Instance Enumeration (Subtypes)
export function parsePacketToServices(
  txtParser: DnsTxt,
  name: string,
  packet: ResponsePacket,
  referer: RemoteInfo,
  receiveTime: number
): DiscoveredService[] {
  const records = packet.answers
    .concat(packet.additionals)
    .filter((rr) => "ttl" in rr && rr.ttl && rr.ttl > 0); // ignore goodbye messages

  return records
    .map((ptr) => {
      if (ptr.type !== "PTR" || !dnsEqual(ptr.name, name)) return;

      const service: DiscoveredService = {
        addresses: [],
        subtypes: [],

        name: "",
        fqdn: "",
        type: undefined,

        protocol: undefined,
        host: "",
        port: 0,

        referer,

        txt: {},
        rawTxt: undefined,

        ttl: ptr.ttl,
        lastSeen: receiveTime,
      };

      for (const rr of records) {
        if (
          rr.type === "PTR" &&
          dnsEqual(rr.data, ptr.data) &&
          rr.name.includes("._sub")
        ) {
          const types = ServiceToType(rr.name);
          if (types.subtype) service.subtypes.push(types.subtype);
        } else if (rr.type === "SRV" && dnsEqual(rr.name, ptr.data)) {
          const parts = rr.name.split(".");
          const name = parts[0];
          const types = ServiceToType(parts.slice(1, -1).join("."));
          service.name = name;
          service.fqdn = rr.name;
          service.host = rr.data.target;
          service.port = rr.data.port;
          service.type = types.name;
          service.protocol = types.protocol;
        } else if (rr.type === "TXT" && dnsEqual(rr.name, ptr.data)) {
          const data = Array.isArray(rr.data) ? rr.data : [rr.data];
          service.rawTxt = data;
          service.txt = txtParser.decodeAll(data);
        }
      }

      if (!service.name) return;

      for (const rr of records) {
        if (
          (rr.type === "A" || rr.type === "AAAA") &&
          dnsEqual(rr.name, service.host)
        ) {
          service.addresses.push(rr.data);
        }
      }

      return service;
    })
    .filter((rr): rr is DiscoveredService => !!rr);
}
