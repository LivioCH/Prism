import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { HttpError } from './errors.js';

export function signToken(userId) {
  return jwt.sign({ sub: userId }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

/** Use after requireAuth: only accounts with is_admin = 1 get through. */
export function requireAdmin(req, _res, next) {
  if (!req.user?.is_admin) return next(new HttpError(403, 'forbidden', 'Admin access required'));
  next();
}

export function requireAuth(db) {
  const findUser = db.prepare('SELECT * FROM users WHERE id = ?');
  return (req, _res, next) => {
    const header = req.get('authorization') || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return next(new HttpError(401, 'unauthorized', 'Missing bearer token'));
    }
    try {
      const payload = jwt.verify(token, config.jwtSecret);
      const user = findUser.get(payload.sub);
      if (!user) return next(new HttpError(401, 'unauthorized', 'Account no longer exists'));
      req.user = user;
      next();
    } catch {
      next(new HttpError(401, 'unauthorized', 'Invalid or expired token'));
    }
  };
}
