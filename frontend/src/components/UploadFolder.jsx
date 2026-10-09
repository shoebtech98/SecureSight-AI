export default function UploadFolder() {
  return <svg className="upload-folder" viewBox="0 0 160 132" role="img" aria-label="Blue upload folder">
    <defs>
      <linearGradient id="folder-face" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#5fa0ff" /><stop offset="1" stopColor="#155be5" /></linearGradient>
      <linearGradient id="folder-back" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#b7d4ff" /><stop offset="1" stopColor="#4385f5" /></linearGradient>
      <filter id="folder-shadow"><feDropShadow dx="0" dy="10" stdDeviation="9" floodColor="#1e5dc6" floodOpacity=".23" /></filter>
    </defs>
    <ellipse cx="80" cy="118" rx="59" ry="7" fill="#cadbfa" opacity=".75" />
    <g className="upload-folder-float" filter="url(#folder-shadow)">
      <path d="M20 42a9 9 0 0 1 9-9h34l11 10h57a9 9 0 0 1 9 9v50a9 9 0 0 1-9 9H29a9 9 0 0 1-9-9z" fill="url(#folder-back)" />
      <rect x="50" y="18" width="60" height="66" rx="5" fill="white" stroke="#d8e5ff" strokeWidth="2" transform="rotate(-6 80 51)" />
      <path d="M62 40h34M62 49h28M62 58h32" stroke="#9dbef2" strokeWidth="4" strokeLinecap="round" transform="rotate(-6 80 51)" />
      <path d="M19 59a9 9 0 0 1 9-9h104a9 9 0 0 1 9 9l-7 44a10 10 0 0 1-10 9H36a10 10 0 0 1-10-9z" fill="url(#folder-face)" />
      <path d="M19 59a9 9 0 0 1 9-9h104a9 9 0 0 1 9 9v4H20z" fill="#9bc4ff" opacity=".55" />
      <circle cx="80" cy="81" r="17" fill="white" opacity=".2" />
      <path d="M80 91V73m0 0-7 7m7-7 7 7" fill="none" stroke="white" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" />
    </g>
  </svg>;
}
