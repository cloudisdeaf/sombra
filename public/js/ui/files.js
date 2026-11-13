// Sombra UI — blob URL lifecycle and file download helpers.
//
// SECURITY:
//  * Downloads are always served as application/octet-stream so a received HTML/SVG file can
//    never be rendered in our origin (blob: URLs inherit the creating origin).
//  * Inline images are created only after magic-byte sniffing (see format.sniffImageMime) and
//    with the sniffed raster MIME type, never the sender-declared one.
//  * Every blob: URL is revoked: downloads after a short delay, images when their message
//    leaves the screen, the conversation closes, or the app locks.

import { h } from './dom.js';
import { sanitizeFilename } from './format.js';

/** Trigger a download of `bytes` under a sanitised filename. */
export function downloadBytes(bytes, name) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: sanitizeFilename(name), rel: 'noopener', class: 'visually-hidden', tabindex: '-1' });
  document.body.append(a);
  a.click();
  a.remove();
  // Give the browser time to start the download before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 15000);
}

/** Registry of image blob URLs keyed by an id (message id), revocable as a group. */
export class BlobUrlCache {
  constructor() {
    this.map = new Map();
  }

  /** Get (or create) an object URL for `bytes` with the given sniffed MIME type. */
  get(key, bytes, mime) {
    let url = this.map.get(key);
    if (!url) {
      url = URL.createObjectURL(new Blob([bytes], { type: mime }));
      this.map.set(key, url);
    }
    return url;
  }

  peek(key) {
    return this.map.get(key);
  }

  /** Revoke every URL whose key is not in `keep`. */
  retain(keep) {
    for (const [key, url] of this.map) {
      if (!keep.has(key)) {
        URL.revokeObjectURL(url);
        this.map.delete(key);
      }
    }
  }

  revokeAll() {
    for (const url of this.map.values()) URL.revokeObjectURL(url);
    this.map.clear();
  }
}
