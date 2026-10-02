/**
 * The doorman's routes for the swarm's Traefik (the wake-on-traffic plan: after the DNS flip the sleeping domain
 * resolves to the swarm host, and something there has to send it to the doorman). Traefik's docker provider only
 * reads labels, fixed when a container starts, so the advisor serves its dynamic configuration instead and Traefik
 * polls it (its HTTP provider):
 *
 *   --providers.http.endpoint=http://<advisor container>:9034/traefik/dynamic.json
 *   --providers.http.pollInterval=10s
 *
 * One HTTP router per wake profile domain and port the profile does not ignore, on the entrypoint the swarm names
 * for that port (web for 80, websecure for 443, port<N> otherwise), TLS on: from the certificate store Traefik's
 * file provider loads (a wildcard for the zone, the production swarm's way) or, with TRAEFIK_CERT_RESOLVER set, from
 * that ACME resolver (a Route 53 DNS challenge issues for the name before any traffic arrives), all to one service:
 * the doorman. The
 * doorman then matches the Host header to the profile. Profiles whose front door is not the DNS flip are left out;
 * a domain that resolves elsewhere never reaches these routers, so a route for an awake box is harmless.
 */
import os from "node:os";
import { config } from "./config.js";
import type { WakeProfile } from "./wake_profiles.js";

export const DOORMAN_SERVICE = "advisor-doorman";
/** The swarm's entrypoint name for a port (src/images/traefik.rs in sphinx-swarm). Pure. */
export const entrypointFor = (port: number) => (port === 80 ? "web" : port === 443 ? "websecure" : `port${port}`);
/** A Traefik v2 rule for one profile domain: Host for a name, HostRegexp for a wildcard. Pure. */
export const ruleFor = (domain: string) => (domain.startsWith("*.") ? `HostRegexp(\`{sub:[a-z0-9-]+}.${domain.slice(2)}\`)` : `Host(\`${domain}\`)`);
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

export interface TraefikDynamic { http: { routers: Record<string, unknown>; services: Record<string, unknown> } }

/** The dynamic configuration for these profiles, the doorman at `doormanUrl`; `certResolver` empty = the certificate store's own certificates. Pure. */
export function traefikDynamicConfig(profiles: Pick<WakeProfile, "instance_id" | "domains" | "ports" | "front_door">[], doormanUrl: string, certResolver = ""): TraefikDynamic {
  const routers: Record<string, unknown> = {};
  for (const p of profiles) {
    if (p.front_door !== "dns") continue;
    const ports = [...new Set(p.ports.filter((x) => x.proto === "tcp" && x.behaviour !== "ignore").map((x) => Number(x.port)))].filter((n) => Number.isInteger(n) && n > 0).sort((a, b) => a - b);
    p.domains.forEach((domain, i) => {
      for (const port of ports) {
        routers[`doorman-${slug(p.instance_id)}-${i}-${port}`] = {
          entryPoints: [entrypointFor(port)], rule: ruleFor(domain), service: DOORMAN_SERVICE, priority: 1000,
          ...(port === 80 ? {} : { tls: certResolver ? { certResolver, ...(domain.startsWith("*.") ? { domains: [{ main: domain.slice(2), sans: [domain] }] } : {}) } : {} }),
        };
      }
    });
  }
  return { http: { routers, services: Object.keys(routers).length ? { [DOORMAN_SERVICE]: { loadBalancer: { servers: [{ url: doormanUrl }], passHostHeader: true } } } : {} } };
}

/** Where Traefik reaches the doorman: the setting, else this container's own host name on the docker network and DOORMAN_PORT. */
export function doormanUrl(): string {
  return config.doormanUrl || `http://${os.hostname()}:${config.doormanPort || 9035}`;
}
