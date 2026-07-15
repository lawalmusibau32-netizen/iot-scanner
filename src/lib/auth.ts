import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { cookies } from "next/headers";

const BCRYPT_ROUNDS = 12;

function getSecret(): string {
  return process.env.JWT_SECRET_KEY || process.env.SECRET_KEY || "change-this-in-production";
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

export function verifyPassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}

export function createAccessToken(payload: { sub: number; username: string; role: string }): string {
  return jwt.sign(
    { ...payload, iat: Math.floor(Date.now() / 1000) },
    getSecret(),
    { expiresIn: "24h" }
  );
}

export function verifyAccessToken(token: string): { sub: number; username: string; role: string } | null {
  try {
    return jwt.verify(token, getSecret()) as { sub: number; username: string; role: string };
  } catch {
    return null;
  }
}

export const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME ?? "iotscanner_token";

export async function getCurrentUser() {
  const cookieStore = await cookies();
  const token = cookieStore.get(AUTH_COOKIE_NAME)?.value;
  if (!token) return null;
  return verifyAccessToken(token);
}
