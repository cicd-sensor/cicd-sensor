import { fileURLToPath } from "node:url";
import express from "express";
import { DefaultAzureCredential } from "@azure/identity";
import { BlobServiceClient } from "@azure/storage-blob";
import { LOG_TYPES, search } from "./search.js";

const account = process.env.STORAGE_ACCOUNT_NAME;
const containerName = process.env.LOG_CONTAINER_NAME || "cicd-sensor-logs";
let prefix = process.env.LOG_PREFIX ?? "cicd-sensor/";
if (prefix && !prefix.endsWith("/")) prefix += "/";
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";

if (!account) {
  console.error("STORAGE_ACCOUNT_NAME is required");
  process.exit(1);
}

const container = new BlobServiceClient(
  `https://${account}.blob.${process.env.STORAGE_SUFFIX || "core.windows.net"}`,
  new DefaultAzureCredential(),
).getContainerClient(containerName);

const app = express();
app.use(express.static(fileURLToPath(new URL("./public", import.meta.url))));

app.get("/api/search", async (req, res) => {
  const now = new Date();
  const from = req.query.from ? new Date(req.query.from) : new Date(now - 24 * 3600 * 1000);
  const to = req.query.to ? new Date(req.query.to) : now;
  if (isNaN(from) || isNaN(to) || from > to) {
    return res.status(400).json({ error: "invalid from/to" });
  }
  if (to - from > 31 * 86400000) {
    return res.status(400).json({ error: "range must be 31 days or less" });
  }
  const logTypes = String(req.query.type || "")
    .split(",")
    .filter((t) => LOG_TYPES.includes(t));
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 200, 1), 1000);
  try {
    res.json(await search(container, prefix, { from, to, logTypes, limit, keyword: String(req.query.q || "") }));
  } catch (err) {
    console.error("search_failed", err.message);
    res.status(502).json({ error: "failed to read logs from storage" });
  }
});

app.listen(port, host, () => console.log(`log viewer on http://${host}:${port}`));
