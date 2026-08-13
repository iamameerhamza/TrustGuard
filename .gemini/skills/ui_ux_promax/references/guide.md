# UI/UX ProMax - Component Reference Guide

## 1. Modern Glassmorphic Container
```tsx
<div className="glass-card">
  <div className="card-header">
    <span className="badge badge-neon">FEATURED</span>
    <h3>Interactive Analytics</h3>
  </div>
  <div className="card-body">
    <p>Real-time data telemetry and visual metrics.</p>
  </div>
</div>
```

## 2. Interactive File Dropzone
```tsx
<label className="file-dropzone">
  <UploadIcon className="icon-glow" />
  <span className="drop-title">Drag & Drop Files Here</span>
  <span className="drop-sub">Supports PNG, JPG, PDF (Max 25MB)</span>
  <input type="file" className="hidden" />
</label>
```

## 3. Glowing Neon Status Badge
```css
.badge-neon {
  background: rgba(56, 189, 248, 0.15);
  color: #38bdf8;
  border: 1px solid rgba(56, 189, 248, 0.4);
  box-shadow: 0 0 12px rgba(56, 189, 248, 0.2);
  border-radius: 9999px;
  padding: 0.25rem 0.75rem;
  font-weight: 700;
  font-size: 0.75rem;
  text-transform: uppercase;
}
```
