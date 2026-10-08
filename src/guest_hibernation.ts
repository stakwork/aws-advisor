/**
 * Whether the guest OS can finish a hibernate. EC2's HibernationOptions.Configured only says the instance was
 * launched for it; the hibernate itself is the guest's work: EC2 presses the ACPI sleep button and something in the
 * OS has to answer it (the hibernation agent, an acpid rule, or logind with HandleSuspendKey=hibernate), write the
 * memory to a swap at least as big as the RAM, and find it again on boot (resume=). A box launched for hibernation
 * whose guest has none of this sits in "stopping" until someone forces the stop (Debian 12 has no agent package).
 *
 * The reading comes from the software probe (src/probes.ts, software/3); a box without that reading falls back to
 * whether an agent package is installed. A missing package proves nothing (Debian answers the sleep button through
 * logind, with no package), so without the reading and without a package the verdict is unknown, never "cannot".
 * Unknown is not ready: the stop is a plain one until the probe has looked.
 */
import { hibernationSetupOf, HIBERNATION_AGENT_PACKAGES, type ProbeHibernation } from "./software_inventory.js";

export interface GuestHibernation {
  /** true: the guest can hibernate; false: it cannot, `reason` says why; null: nothing read from inside the box yet. */
  ready: boolean | null;
  reason: string;
  source: "probe" | "packages" | "none";
}

const gib = (b: number) => `${(b / 1024 ** 3).toFixed(1)} GiB`;
const AGENT_HINT = `install the hibernation agent (${HIBERNATION_AGENT_PACKAGES[0]}), or on a distribution without the package give it a swap file as big as the RAM, resume= and resume_offset= on the kernel command line and HandleSuspendKey=hibernate for logind`;

/** The verdict from what the software probe saw. Pure. */
export function guestReadiness(setup: { probe: ProbeHibernation | null; agent_package: string | null; packages_known: boolean }): GuestHibernation {
  const h = setup.probe;
  if (h) {
    if (!h.kernel_disk) return { ready: false, reason: "the kernel offers no hibernation (no disk in /sys/power/state)", source: "probe" };
    if (h.agent) return { ready: true, reason: `the hibernation agent (${h.agent}) answers the sleep button`, source: "probe" };
    const handler = h.acpi_sleep_handler ? "an acpid rule" : h.logind_suspend_key === "hibernate" ? "logind (HandleSuspendKey=hibernate)" : null;
    if (!handler) return { ready: false, reason: `nothing in the guest answers EC2's sleep button${h.logind_suspend_key ? ` (logind HandleSuspendKey=${h.logind_suspend_key})` : ""}: ${AGENT_HINT}`, source: "probe" };
    const swap = Math.max(h.swap_active_bytes ?? 0, h.swap_file_bytes ?? 0);
    // the kernel compresses the image, but a swap smaller than the RAM can fail with a busy box; 95 % leaves room for rounding
    if (h.mem_bytes && swap < h.mem_bytes * 0.95) return { ready: false, reason: `the swap (${gib(swap)}) is smaller than the RAM (${gib(h.mem_bytes)}): the memory has nowhere to go`, source: "probe" };
    if (!h.cmdline_resume && (!h.sys_resume || h.sys_resume === "0:0")) return { ready: false, reason: "no resume= on the kernel command line: the box would boot cold after a hibernate and lose its memory", source: "probe" };
    return { ready: true, reason: `${handler} hibernates on the sleep button, swap ${gib(swap)}, resume set`, source: "probe" };
  }
  if (setup.agent_package) return { ready: true, reason: `the hibernation agent package (${setup.agent_package}) is installed`, source: "packages" };
  // the software probe ran, but an older one (software/2 and before) that does not read the hibernation setup
  if (setup.packages_known) return { ready: null, reason: "the software probe in force predates the hibernation check (software/3): update the probe document in Settings > Probes, then probe the box again", source: "none" };
  return { ready: null, reason: "the software probe has not looked inside this box yet; the next software probe tells", source: "none" };
}

/** The verdict for one instance, from the local tables. */
export const guestHibernation = (instanceId: string): GuestHibernation => guestReadiness(hibernationSetupOf(instanceId));
