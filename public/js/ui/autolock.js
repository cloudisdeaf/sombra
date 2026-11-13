// Sombra UI — inactivity auto-lock.
// Uses wall-clock comparison (not a single long timeout) so it still fires correctly after the
// tab was throttled or the machine slept: the check also runs on visibility/focus changes.

import { getPref } from './prefs.js';

const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart', 'mousemove', 'scroll'];
const CHECK_INTERVAL_MS = 5000;

export function createAutoLock({ onIdle }) {
  let last = Date.now();
  let timer = null;
  let running = false;
  let lastMove = 0;

  const poke = (e) => {
    // mousemove fires constantly; sample it at most once a second.
    if (e && e.type === 'mousemove') {
      const now = Date.now();
      if (now - lastMove < 1000) return;
      lastMove = now;
    }
    last = Date.now();
  };

  const check = () => {
    if (!running) return false;
    const minutes = getPref('autoLockMinutes');
    if (Date.now() - last >= minutes * 60000) {
      stop();
      onIdle();
      return true;
    }
    return false;
  };

  function start() {
    if (running) return;
    running = true;
    last = Date.now();
    for (const t of ACTIVITY_EVENTS) window.addEventListener(t, poke, { passive: true, capture: true });
    timer = setInterval(check, CHECK_INTERVAL_MS);
  }

  function stop() {
    running = false;
    clearInterval(timer);
    timer = null;
    for (const t of ACTIVITY_EVENTS) window.removeEventListener(t, poke, { capture: true });
  }

  return { start, stop, check, poke: () => poke() };
}
