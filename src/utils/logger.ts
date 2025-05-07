let debugEnabled = false;

export function setDebug(enabled?: boolean) {
  debugEnabled = Boolean(enabled);
}

export function log(...args: unknown[]): void {
  console.log(...args);
}

export function debug(...args: unknown[]): void {
  if (!debugEnabled) return;
  console.debug(...args);
}

export function warn(...args: unknown[]): void {
  console.warn(...args);
}

export const error = console.error;
