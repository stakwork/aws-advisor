/** Calendar-day arithmetic on YYYY-MM-DD strings in the server's local time zone. No imports on purpose. */
const pad = (n: number) => String(n).padStart(2, "0");
/** YYYY-MM-DD of a Date in the server's local time zone. */
export const localDay = (d = new Date()) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const parts = (day: string) => day.split("-").map(Number) as [number, number, number];
export function addDays(day: string, n: number): string {
  const [y, m, d] = parts(day);
  return localDay(new Date(y, m - 1, d + n));
}
export const monthStart = (day: string) => `${day.slice(0, 7)}-01`;
export function monthEnd(day: string): string {
  const [y, m] = parts(day);
  return localDay(new Date(y, m, 0));
}
export const daysInMonth = (day: string) => Number(monthEnd(day).slice(8, 10));
