import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { signToken } from '../auth.js';
import { HttpError } from '../errors.js';
import { publicUser } from '../serializers.js';

const signupSchema = z.object({
  name: z.string().trim().min(1, 'Name is required').max(80),
  email: z.string().trim().toLowerCase().email('Enter a valid email').max(254),
  password: z.string().min(6, 'Password must be at least 6 characters').max(200),
});
const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email('Enter a valid email'),
  password: z.string().min(1, 'Password is required'),
});

// Precomputed so unknown-email logins take the same time as wrong-password ones.
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

export function authRoutes(db) {
  const r = Router();
  const byEmail = db.prepare('SELECT * FROM users WHERE email = ?');
  const insert = db.prepare(
    'INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'
  );

  r.post('/signup', async (req, res, next) => {
    try {
      const { name, email, password } = signupSchema.parse(req.body);
      if (byEmail.get(email)) throw new HttpError(409, 'email_taken', 'An account with this email already exists');
      const id = randomUUID();
      insert.run(id, name, email, await bcrypt.hash(password, 10), Date.now());
      const user = byEmail.get(email);
      res.status(201).json({ token: signToken(id), user: publicUser(user) });
    } catch (e) { next(e); }
  });

  r.post('/login', async (req, res, next) => {
    try {
      const { email, password } = loginSchema.parse(req.body);
      const user = byEmail.get(email);
      const ok = await bcrypt.compare(password, user?.password_hash ?? DUMMY_HASH);
      if (!user || !ok) throw new HttpError(401, 'invalid_credentials', 'Incorrect email or password');
      res.json({ token: signToken(user.id), user: publicUser(user) });
    } catch (e) { next(e); }
  });

  return r;
}
