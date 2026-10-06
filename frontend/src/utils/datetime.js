// The API returns UTC timestamps without an offset (for example,
// "2026-07-22T04:29:14"). Make that timezone explicit before converting it
// to the analyst's local time; otherwise browsers interpret it as local time.
export const formatUtcDateTime = (value) => {
  if (!value) return 'Unavailable';

  const timestamp = typeof value === 'string' && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(value)
    ? `${value}Z`
    : value;
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) return 'Unavailable';

  return date.toLocaleString(undefined, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
};
