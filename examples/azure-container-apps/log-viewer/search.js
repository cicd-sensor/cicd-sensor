import { gunzipSync } from "node:zlib";

export const LOG_TYPES = ["summary", "detection", "runtime_event"];

// Blob layout written by the manager: <prefix><log_type>/dt=YYYY-MM-DD/hour=HH/<file>.json.gz
export function datePrefixes(prefix, logTypes, from, to) {
  const out = [];
  const end = Date.UTC(to.getUTCFullYear(), to.getUTCMonth(), to.getUTCDate());
  for (
    let t = Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
    t <= end;
    t += 86400000
  ) {
    const day = new Date(t).toISOString().slice(0, 10);
    for (const type of logTypes) out.push(`${prefix}${type}/dt=${day}/`);
  }
  return out;
}

export function parseJSONL(buf) {
  const text = gunzipSync(buf).toString("utf8");
  const records = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push({ raw: line, rec: JSON.parse(line) });
    } catch {
      // skip malformed line
    }
  }
  return records;
}

export function matches({ raw, rec }, { from, to, keyword }) {
  const ts = Date.parse(rec.timestamp);
  if (from && !(ts >= from.getTime())) return false;
  if (to && !(ts <= to.getTime())) return false;
  if (keyword && !raw.toLowerCase().includes(keyword.toLowerCase())) return false;
  return true;
}

export async function search(containerClient, prefix, q) {
  const types = q.logTypes.length ? q.logTypes : LOG_TYPES;
  const prefixes = datePrefixes(prefix, types, q.from, q.to);
  const results = [];
  let scanned = 0;
  let truncated = false;
  outer: for (const p of prefixes) {
    for await (const blob of containerClient.listBlobsFlat({ prefix: p })) {
      scanned++;
      const buf = await containerClient.getBlobClient(blob.name).downloadToBuffer();
      for (const item of parseJSONL(buf)) {
        if (!matches(item, q)) continue;
        if (results.length >= q.limit) {
          truncated = true;
          break outer;
        }
        results.push({ blob: blob.name, ...item.rec });
      }
    }
  }
  results.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  return { results, scanned, truncated };
}
