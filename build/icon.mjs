// Renders the Sombra icon (the favicon's shield + crescent) to PNG/ICO without any
// external tool: geometry in the favicon's 64x64 space, 4x4 supersampling, a tiny
// PNG encoder (node:zlib) and an ICO container with PNG-compressed entries.
import zlib from 'node:zlib';

const SHIELD = '#5288c1';
const NIGHT = '#0e1621';

function cubic(p0, p1, p2, p3, n = 24) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    out.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return out;
}
// favicon.svg: M32 4 8 13v17c0 15 10.5 25.5 24 30 13.5-4.5 24-15 24-30V13L32 4z
const shield = [[32, 4], [8, 13], [8, 30],
  ...cubic([8, 30], [8, 45], [18.5, 55.5], [32, 60]),
  ...cubic([32, 60], [45.5, 55.5], [56, 45], [56, 30]),
  [56, 13]];

function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
// Crescent: inside circle (33,32) r13 and outside circle (47,32) r15.
const inCrescent = (x, y) => (x - 33) ** 2 + (y - 32) ** 2 <= 169 && (x - 47) ** 2 + (y - 32) ** 2 > 225;

const hex = (c) => [parseInt(c.slice(1, 3), 16), parseInt(c.slice(3, 5), 16), parseInt(c.slice(5, 7), 16)];

export function renderRGBA(size) {
  const px = new Uint8Array(size * size * 4);
  const S = 4;
  const [sr, sg, sb] = hex(SHIELD);
  const [nr, ng, nb] = hex(NIGHT);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let a = 0; let r = 0; let g = 0; let b = 0;
      for (let j = 0; j < S; j++) {
        for (let i = 0; i < S; i++) {
          const fx = ((x + (i + 0.5) / S) / size) * 64;
          const fy = ((y + (j + 0.5) / S) / size) * 64;
          if (!inPoly(fx, fy, shield)) continue;
          a++;
          if (inCrescent(fx, fy)) { r += nr; g += ng; b += nb; } else { r += sr; g += sg; b += sb; }
        }
      }
      const o = (y * size + x) * 4;
      if (a) { px[o] = Math.round(r / a); px[o + 1] = Math.round(g / a); px[o + 2] = Math.round(b / a); }
      px[o + 3] = Math.round((a / (S * S)) * 255);
    }
  }
  return px;
}

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(td) >>> 0);
  return Buffer.concat([len, td, crc]);
}

export function png(size) {
  const rgba = renderRGBA(size);
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    Buffer.from(rgba.buffer, y * size * 4, size * 4).copy(raw, y * (size * 4 + 1) + 1);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

export function ico(sizes = [256, 64, 48, 32, 24, 16]) {
  const images = sizes.map((s) => ({ s, data: png(s) }));
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(images.length, 4);
  const dir = Buffer.alloc(16 * images.length);
  let offset = 6 + dir.length;
  images.forEach(({ s, data }, i) => {
    const e = i * 16;
    dir[e] = s >= 256 ? 0 : s; dir[e + 1] = s >= 256 ? 0 : s; dir[e + 2] = 0; dir[e + 3] = 0;
    dir.writeUInt16LE(1, e + 4); dir.writeUInt16LE(32, e + 6);
    dir.writeUInt32LE(data.length, e + 8); dir.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([header, dir, ...images.map((x) => x.data)]);
}
