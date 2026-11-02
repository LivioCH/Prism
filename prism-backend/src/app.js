import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { ZodError } from 'zod';
import { requireAuth } from './auth.js';
import { HttpError } from './errors.js';
import { authRoutes } from './routes/auth.js';
import { meRoutes } from './routes/me.js';
import { scanRoutes } from './routes/scans.js';

export function createApp(db) {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(cors());
  app.use(express.json({ limit: '32kb' }));

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  const authLimiter = rateLimit({
    windowMs: 15 * 60_000,
    limit: process.env.NODE_ENV === 'test' ? 1000 : 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: { code: 'rate_limited', message: 'Too many attempts, try again later' } },
  });

  const auth = requireAuth(db);
  app.use('/api/auth', authLimiter, authRoutes(db));
  app.use('/api', auth, meRoutes(db));
  app.use('/api/scans', auth, scanRoutes(db));

  app.use((_req, _res, next) => next(new HttpError(404, 'not_found', 'Route not found')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    if (err instanceof ZodError) {
      return res.status(400).json({
        error: { code: 'validation_error', message: err.issues[0]?.message ?? 'Invalid request', issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
      });
    }
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message, ...err.extra } });
    }
    if (err?.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'bad_json', message: 'Malformed JSON body' } });
    }
    console.error(err);
    res.status(500).json({ error: { code: 'internal_error', message: 'Something went wrong' } });
  });

  return app;
}
