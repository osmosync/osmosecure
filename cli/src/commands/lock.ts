import { closeSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import path from 'node:path';

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Single-instance lock so two watchers or an overlapping cron tick never write the state file together. */
export function acquireLock(dataDir: string): (() => void) | null {
  mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'run.lock');
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(file, 'wx', 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
      return () => {
        try {
          unlinkSync(file);
        } catch {
          /* already gone */
        }
      };
    } catch {
      let pid = NaN;
      try {
        pid = Number(readFileSync(file, 'utf8'));
      } catch {
        /* unreadable: treat as stale */
      }
      if (Number.isInteger(pid) && pid > 0 && alive(pid)) return null;
      try {
        unlinkSync(file);
      } catch {
        /* raced with another process */
      }
    }
  }
  return null;
}
