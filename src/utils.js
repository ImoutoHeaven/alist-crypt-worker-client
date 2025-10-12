export const rotLower = (value = '') => value.toLowerCase();

export const cloneUint8 = (source) => {
  if (!source) return new Uint8Array(0);
  if (source instanceof Uint8Array) return source.slice();
  return new Uint8Array(source);
};

export const uint8ToBase64 = (bytes) => {
  if (!bytes || bytes.length === 0) return '';
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

export const parseBoolean = (value, defaultValue = false) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  const lowered = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(lowered)) return true;
  if (['0', 'false', 'no', 'off'].includes(lowered)) return false;
  return defaultValue;
};

export const parseInteger = (value, defaultValue) => {
  if (value === undefined || value === null || value === '') return defaultValue;
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed)) return defaultValue;
  return parsed;
};
