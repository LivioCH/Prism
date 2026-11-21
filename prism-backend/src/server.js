import { config } from './config.js';
import { openDb } from './db.js';
import { createApp } from './app.js';

const db = openDb(config.databasePath);
const app = createApp(db);
app.listen(config.port, () => console.log(`Prism API listening on :${config.port}`));
