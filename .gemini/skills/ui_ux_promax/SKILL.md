---
name: ui-ux-promax
description: Specialized skill for designing and engineering world-class, state-of-the-art Web UI/UX interfaces with rich glassmorphism aesthetics, curated color systems, modern typography, fluid micro-interactions, responsive CSS layouts, and interactive accessibility best practices.
---

# 🎨 UI/UX ProMax Skill - Ultimate Interface Design & Engineering Guide

This skill equips Antigravity with advanced UI/UX design patterns, visual systems, and component engineering principles to create stunning, premium web applications.

---

## 1. 🌈 Design System & Color Tokens
- **Avoid Generic Browser Colors**: Never use plain red (`#ff0000`), blue (`#0000ff`), or green (`#00ff00`).
- **Curated Glassmorphic Dark System**:
  - `Background`: `#090d16` with ambient radial gradients (`radial-gradient(circle at 15% 15%, rgba(56, 189, 248, 0.08) 0%, transparent 40%)`)
  - `Card Background`: `rgba(15, 23, 42, 0.75)` with `backdrop-filter: blur(16px)`
  - `Borders`: `rgba(51, 65, 85, 0.6)`
  - `Primary Accent`: `#38bdf8` (Cyan Neon) and `#3b82f6` (Electric Blue)
  - `Status Safe`: `#10b981` (Emerald Green)
  - `Status Warning`: `#f59e0b` (Amber Glow)
  - `Status Danger`: `#ef4444` (Crimson Neon)
  - `Text Main`: `#f8fafc` | `Text Muted`: `#94a3b8`

---

## 2. 🔤 Typography & Hierarchy
- Import Google Fonts in HTML: `Inter`, `Outfit`, `Plus Jakarta Sans`, or `Space Grotesk`.
- **Heading 1**: `font-weight: 800; letter-spacing: -0.5px; background: linear-gradient(to right, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;`
- **Body & Inputs**: `font-size: 0.95rem; line-height: 1.6; color: #f8fafc;`

---

## 3. ✨ Micro-Animations & Dynamic States
- **Smooth Hover Scale**:
  ```css
  .interactive-card {
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  }
  .interactive-card:hover {
    transform: translateY(-2px);
    border-color: #38bdf8;
    box-shadow: 0 12px 32px rgba(56, 189, 248, 0.2);
  }
  ```
- **Pulse Indicators**:
  ```css
  .status-pulse {
    animation: pulseGlow 2s infinite ease-in-out;
  }
  @keyframes pulseGlow {
    0%, 100% { opacity: 0.4; }
    50% { opacity: 1; }
  }
  ```

---

## 4. 📐 Responsive Grid & Layout Guidelines
- Use CSS Grid and Flexbox for fluid responsiveness:
  ```css
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.25rem;
  }
  ```
- Ensure mobile padding (`1rem` under `@media (max-width: 768px)`).

---

## 5. ♿ Accessibility & Interactivity
- High contrast text (`#f8fafc` over `#0f172a`).
- Accessible focus rings: `outline: 2px solid #38bdf8; outline-offset: 2px;`.
- Interactive dropzones with clear visual feedback for drag-and-drop actions.
