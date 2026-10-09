import { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';

const SIZE = 280;

export default function AvatarCropper({ file, onCancel, onSave }) {
  const [image, setImage] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const drag = useRef(null);

  useEffect(() => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => setImage(img);
    img.src = url;
    return () => URL.revokeObjectURL(url);
  }, [file]);

  const base = image ? Math.max(SIZE / image.naturalWidth, SIZE / image.naturalHeight) : 1;
  const width = image ? image.naturalWidth * base * zoom : SIZE;
  const height = image ? image.naturalHeight * base * zoom : SIZE;
  const clamp = (value, dimension) => Math.max((SIZE - dimension) / 2, Math.min((dimension - SIZE) / 2, value));
  const move = (event) => {
    if (!drag.current) return;
    setOffset({ x: clamp(drag.current.x + event.clientX - drag.current.clientX, width), y: clamp(drag.current.y + event.clientY - drag.current.clientY, height) });
  };
  const save = () => {
    if (!image) return;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 256;
    const context = canvas.getContext('2d');
    context.fillStyle = '#fff';
    context.fillRect(0, 0, 256, 256);
    const factor = 256 / SIZE;
    context.drawImage(image, ((SIZE - width) / 2 + offset.x) * factor, ((SIZE - height) / 2 + offset.y) * factor, width * factor, height * factor);
    onSave(canvas.toDataURL('image/jpeg', 0.82));
  };

  return <div className="avatar-crop-layer" role="dialog" aria-modal="true" aria-label="Crop profile photo">
    <div className="avatar-crop-dialog">
      <div className="avatar-crop-heading"><div><h2>Crop profile photo</h2><p>Drag to position your face inside the circle.</p></div><button type="button" onClick={onCancel} aria-label="Close crop dialog"><X size={20}/></button></div>
      <div className="avatar-crop-viewport" onPointerDown={(event) => { event.currentTarget.setPointerCapture(event.pointerId); drag.current = { clientX: event.clientX, clientY: event.clientY, ...offset }; }} onPointerMove={move} onPointerUp={() => { drag.current = null; }} onPointerCancel={() => { drag.current = null; }}>
        {image && <img src={image.src} alt="Profile crop preview" draggable="false" style={{ width, height, left: (SIZE - width) / 2 + offset.x, top: (SIZE - height) / 2 + offset.y }} />}
        <div className="avatar-crop-mask" />
      </div>
      <label htmlFor="avatar-zoom">Zoom</label><input id="avatar-zoom" type="range" min="1" max="2.5" step="0.01" value={zoom} onChange={(event) => { const next = Number(event.target.value); const ratio = next / zoom; setOffset({ x: clamp(offset.x * ratio, width * ratio), y: clamp(offset.y * ratio, height * ratio) }); setZoom(next); }} />
      <div className="avatar-crop-actions"><button type="button" onClick={onCancel}>Cancel</button><button type="button" disabled={!image} onClick={save}>Save photo</button></div>
    </div>
  </div>;
}
