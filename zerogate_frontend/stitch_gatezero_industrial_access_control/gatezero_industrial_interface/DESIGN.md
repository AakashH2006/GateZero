---
name: GateZero Industrial Interface
colors:
  surface: '#0a141b'
  surface-dim: '#0a141b'
  surface-bright: '#303a42'
  surface-container-lowest: '#060f16'
  surface-container-low: '#131d24'
  surface-container: '#172128'
  surface-container-high: '#212b33'
  surface-container-highest: '#2c363e'
  on-surface: '#d9e4ee'
  on-surface-variant: '#bdc9c6'
  inverse-surface: '#d9e4ee'
  inverse-on-surface: '#283239'
  outline: '#879391'
  outline-variant: '#3e4947'
  surface-tint: '#77d7cb'
  primary: '#77d7cb'
  on-primary: '#003732'
  primary-container: '#4fb0a5'
  on-primary-container: '#003f3a'
  inverse-primary: '#006a62'
  secondary: '#c0c7cf'
  on-secondary: '#2a3137'
  secondary-container: '#40484e'
  on-secondary-container: '#afb6be'
  tertiary: '#ffb59c'
  on-tertiary: '#581e08'
  tertiary-container: '#e28a6c'
  on-tertiary-container: '#61250e'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#94f3e7'
  primary-fixed-dim: '#77d7cb'
  on-primary-fixed: '#00201d'
  on-primary-fixed-variant: '#00504a'
  secondary-fixed: '#dce3eb'
  secondary-fixed-dim: '#c0c7cf'
  on-secondary-fixed: '#151c22'
  on-secondary-fixed-variant: '#40484e'
  tertiary-fixed: '#ffdbd0'
  tertiary-fixed-dim: '#ffb59c'
  on-tertiary-fixed: '#390c00'
  on-tertiary-fixed-variant: '#75331c'
  background: '#0a141b'
  on-background: '#d9e4ee'
  surface-variant: '#2c363e'
typography:
  display-lg:
    fontFamily: Barlow Condensed
    fontSize: 48px
    fontWeight: '700'
    lineHeight: '1.1'
    letterSpacing: 0.08em
  headline-md:
    fontFamily: Barlow Condensed
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: 0.05em
  label-caps:
    fontFamily: Barlow Condensed
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.1em
  body-main:
    fontFamily: IBM Plex Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0.01em
  body-sm:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0.01em
  data-mono:
    fontFamily: IBM Plex Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0px
  status-code:
    fontFamily: IBM Plex Mono
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.02em
spacing:
  unit: 4px
  gutter: 16px
  margin-edge: 32px
  panel-gap: 1px
---

## Brand & Style
The design system is engineered for mission-critical security environments and industrial control hubs. It evokes the feeling of a physical, machined instrument panel where precision and reliability are paramount.

The aesthetic follows a **Modern Industrial / Technical** approach. It avoids all decorative flourishes like gradients, blurs, or soft shadows in favor of structural integrity. Hierarchy is communicated through "etched" hairlines, recessed paneling, and strict modularity. The emotional response is one of absolute control, cold efficiency, and high-fidelity data visualization.

## Colors
This design system utilizes a "Deep Graphite" foundation to reduce eye strain in low-light control rooms. 

- **Structural Colors:** The base layer is `bg-graphite`. Inset modules or interactive containers use `panel-recessed`. All internal boundaries are defined by `line-etched` (1px hairlines).
- **Signal Colors:** Used strictly for operational status. 
    - **Idle (Teal):** The system's "Ready" state.
    - **Pending (Amber):** Caution or processing.
    - **Granted (Green):** Access allowed or successful operation.
    - **Denied (Red):** Error, breach, or critical alert.
- **Typography:** `text-primary` for critical readouts; `text-secondary` for metadata and descriptions.

## Typography
The typographic system is split into three functional roles:
1. **Navigational/Structural:** Barlow Condensed is used for all headers and structural labels. It must always be uppercase with increased letter-spacing to mimic stamped metal plates.
2. **Reading/Information:** IBM Plex Sans provides a neutral, highly legible humanist face for long-form content or descriptions.
3. **Operational/Data:** IBM Plex Mono is used for system logs, coordinates, timestamps, and status codes. This ensures that numeric data aligns vertically for quick scanning.

## Layout & Spacing
The layout follows a **Fixed Modular Grid**. Elements are treated as physical components plugged into a rack.

- **The Hairline Grid:** Instead of wide gutters, use `1px` lines (using `line-etched`) to separate adjacent panels. This creates a "machined" look where components fit perfectly together.
- **Internal Padding:** Use a strict 4px base unit. Most containers should use 16px or 24px internal padding.
- **Breakpoints:**
    - **Desktop (1440px+):** 12-column grid, modular panels can span multiple columns.
    - **Tablet (768px):** 6-column grid, panels stack vertically but maintain 1px separation.
    - **Mobile (375px):** Single column, condensed headers, minimal internal padding (12px).

## Elevation & Depth
This design system rejects the concept of "floating" elements. There are no shadows. 

- **Recessed Surfaces:** Use `panel-recessed` for input fields, data wells, and secondary containers to make them look "milled" into the graphite base.
- **Hairline Borders:** Use 1px `line-etched` borders for all primary containers.
- **Active State:** Elements that are "active" or "pressed" should use a 1px solid border of the `signal-idle` (Teal) color rather than a shadow.
- **Z-Index:** High-priority alerts do not use shadows; they use high-contrast `line-etched` borders and an overlay of 40% opacity `bg-graphite` to dim the background.

## Shapes
The shape language is strictly **Sharp (0px)**. 

Every element—buttons, panels, input fields, and tags—must have 90-degree corners. This reinforces the industrial, high-precision instrument aesthetic. Any deviation (such as rounding) would break the technical narrative of the system.

## Components
- **Buttons:** Sharp corners. Default state: `bg-graphite` with `line-etched` border. Hover state: `bg-panel-recessed`. Active/Signal buttons use solid `signal-idle` backgrounds with `bg-graphite` text.
- **Status Indicators:** Small 8x8px square blocks (not circles) using the signal color palette.
- **Input Fields:** Background `panel-recessed` with a bottom-only 1px `line-etched` border or a full 1px border. Text is `data-mono`.
- **Data Tables:** No row separators. Use `line-etched` vertical lines between columns only. Header row is `label-caps` typography with a `panel-recessed` background.
- **Terminal Readouts:** A specialized container with `bg-graphite` and `data-mono` text in `signal-idle`, mimicking a command-line interface.
- **Cards/Panels:** Every panel must have a `label-caps` title bar at the top, separated by a 1px `line-etched` horizontal line.