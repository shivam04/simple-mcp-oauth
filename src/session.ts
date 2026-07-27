import session from "express-session";

export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV==="production", // true when using HTTPS
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000,
  },
});