# cicd-sensor log viewer

Searches the logs that cicd-sensor-manager stores in Azure Blob Storage (`<prefix><log_type>/dt=YYYY-MM-DD/hour=HH/*.json.gz`).

```sh
npm install
STORAGE_ACCOUNT_NAME=<account> npm start   # http://127.0.0.1:3000
npm test
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `STORAGE_ACCOUNT_NAME` | required | Storage account holding the logs |
| `LOG_CONTAINER_NAME` | `cicd-sensor-logs` | Blob container |
| `LOG_PREFIX` | `cicd-sensor/` | Blob prefix configured in the manager sink URI |
| `HOST` / `PORT` | `127.0.0.1` / `3000` | Listen address |

Authentication uses `DefaultAzureCredential` (for example `az login`); the identity needs `Storage Blob Data Reader`.
The app has no user authentication, so keep it bound to localhost or put it behind an authenticated proxy.
Search scans blobs under the selected date range (max 31 days) and filters by time and a case-insensitive keyword over the raw JSON line.
