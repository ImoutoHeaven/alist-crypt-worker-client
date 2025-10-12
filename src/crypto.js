import { cloneUint8 } from './utils.js';

export const NONCE_SIZE = 24;
export const RCLONE_MAGIC = new Uint8Array([82, 67, 76, 79, 78, 69, 0, 0]);

const toUint8 = (value) => {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  return new Uint8Array(0);
};

export const extractNonceFromHeader = (header, fileHeaderSize, nonceSize = NONCE_SIZE) => {
  const data = toUint8(header);
  if (data.length < fileHeaderSize) {
    throw new Error(`header length insufficient: expected ${fileHeaderSize}, got ${data.length}`);
  }
  for (let i = 0; i < RCLONE_MAGIC.length; i += 1) {
    if (data[i] !== RCLONE_MAGIC[i]) {
      throw new Error('invalid crypt header magic');
    }
  }
  const start = RCLONE_MAGIC.length;
  const end = start + nonceSize;
  if (end > data.length) {
    throw new Error('nonce exceeds header length');
  }
  return cloneUint8(data.subarray(start, end));
};
