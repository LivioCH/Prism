import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

const db = openDb(config.databasePath);
// The Google key lives in prism-backend/.env (next to package.json), whatever folder the server starts from.
const envFile = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.env');
const app = createApp(db, { envFile });
app.listen(config.port, () => console.log(`Prism API listening on :${config.port}`));
