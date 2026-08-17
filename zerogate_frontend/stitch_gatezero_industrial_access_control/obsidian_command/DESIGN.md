---
name: Obsidian Command
colors:
  surface: '#0c160a'
  surface-dim: '#0c160a'
  surface-bright: '#313c2e'
  surface-container-lowest: '#071106'
  surface-container-low: '#141e12'
  surface-container: '#182216'
  surface-container-high: '#222d20'
  surface-container-highest: '#2d382a'
  on-surface: '#dae6d2'
  on-surface-variant: '#b9ccb2'
  inverse-surface: '#dae6d2'
  inverse-on-surface: '#283326'
  outline: '#84967e'
  outline-variant: '#3b4b37'
  surface-tint: '#00e639'
  primary: '#ebffe2'
  on-primary: '#003907'
  primary-container: '#00ff41'
  on-primary-container: '#007117'
  inverse-primary: '#006e16'
  secondary: '#c9c6c5'
  on-secondary: '#313030'
  secondary-container: '#474646'
  on-secondary-container: '#b7b4b4'
  tertiary: '#fff8f4'
  on-tertiary: '#442b10'
  tertiary-container: '#ffd5ae'
  on-tertiary-container: '#7a5b3c'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#72ff70'
  primary-fixed-dim: '#00e639'
  on-primary-fixed: '#002203'
  on-primary-fixed-variant: '#00530e'
  secondary-fixed: '#e5e2e1'
  secondary-fixed-dim: '#c9c6c5'
  on-secondary-fixed: '#1c1b1b'
  on-secondary-fixed-variant: '#474646'
  tertiary-fixed: '#ffdcbd'
  tertiary-fixed-dim: '#e7bf99'
  on-tertiary-fixed: '#2c1701'
  on-tertiary-fixed-variant: '#5d4124'
  background: '#0c160a'
  on-background: '#dae6d2'
  surface-variant: '#2d382a'
  alert-red: '#FF003C'
  warning-amber: '#FFB000'
  laser-hairline: rgba(0, 255, 65, 0.3)
  scanline-fill: rgba(0, 0, 0, 0.2)
typography:
  display-lg:
    fontFamily: Barlow Condensed
    fontSize: 48px
    fontWeight: '700'
    lineHeight: '1.1'
    letterSpacing: 0.15em
  headline-md:
    fontFamily: Barlow Condensed
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: 0.1em
  headline-sm:
    fontFamily: Barlow Condensed
    fontSize: 18px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: 0.08em
  data-lg:
    fontFamily: IBM Plex Mono
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 24px
    letterSpacing: 0px
  data-main:
    fontFamily: IBM Plex Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0px
  data-sm:
    fontFamily: IBM Plex Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0px
  label-caps:
    fontFamily: Barlow Condensed
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.12em
  label-sm:
    fontFamily: Barlow Condensed
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 12px
    letterSpacing: 0.15em
spacing:
  unit: 4px
  gutter: 16px
  margin-edge: 24px
  panel-gap: 2px
---

## Brand & Style

This design system is a high-fidelity evolution of industrial interfaces, reimagined for elite **Cybersecurity Command** environments. The personality is aggressive, tactical, and uncompromisingly secure. It is designed to evoke the high-stakes atmosphere of a digital war room where speed of data processing and clarity of threat detection are critical.

The aesthetic follows a **Modern Brutalist** approach mixed with **Cyberpunk** technicality. It utilizes deep, "Obsidian" blacks to minimize visual noise, allowing vibrant "Terminal Green" signals to pierce through the interface. The emotional response is one of hyper-focus, technological dominance, and absolute digital sovereignty. Every pixel is treated as a tactical coordinate, and every interaction feels like a high-level system override.

## Colors

The palette is optimized for high-contrast, low-light operations, ensuring that critical data is immediately distinguishable from the background architecture.

- **Primary (Terminal Green):** Reserved for system-ready states, successful authentication, and active data streams. It is the lifeblood of the interface.
- **Secondary (Obsidian):** The foundation of the system. A near-absolute black that creates an infinite depth for the interface to live within.
- **Alert Red:** Used exclusively for denials, breaches, and critical system failures. It should be used sparingly to maintain its psychological impact.
- **Warning Amber:** Indicates pending states, encryption in progress, or non-critical anomalies.
- **Laser Hairline:** A semi-transparent variation of the primary green used for "etched glass" borders and structural grids.

## Typography

The typographic strategy is dual-layered to balance structural authority with technical precision.

1.  **Navigational Hierarchy (Barlow Condensed):** All headers and structural labels use Barlow Condensed. To enhance the "Cybersecurity Command" theme, headers utilize aggressive tracking (letter-spacing) and must always be rendered in Uppercase. In documentation and high-level headers, a "glitch" aesthetic (subtle horizontal displacement) should be applied.
2.  **Operational Intelligence (IBM Plex Mono):** To reinforce the terminal feel, **ALL** data elements, body text, logs, and interactive inputs are standardized on IBM Plex Mono. This creates a rhythmic, predictable grid of characters that mimics a command-line environment and ensures all alphanumeric data is perfectly aligned.

## Layout & Spacing

The layout utilizes a **Fixed Modular Grid** that treats the screen as a high-tech console rack. 

- **The Laser Grid:** Instead of traditional white space, use 1px "Laser Hairline" borders to define the boundaries of the grid. 
- **Scanline Texturing:** Recessed panels and background containers should feature a subtle horizontal scanline pattern (1px tall lines with 50% opacity gaps) to simulate a CRT monitor or a tactical HUD.
- **Breakpoints:**
    - **Desktop (1440px+):** 12-column rack. Elements are snapped to the grid with `panel-gap` precision.
    - **Tablet (1024px):** 8-column rack. Primary data visualization stays fixed; secondary panels collapse into tabs.
    - **Mobile (375px):** Single-column tactical view. Headers are condensed further, and margins are reduced to `12px` to maximize data density.

## Elevation & Depth

This design system avoids physical metaphors like "lifting" or "floating." Instead, it uses **Light Emission and Etching**.

- **Laser-Etched Borders:** All panels are defined by hairline borders. These are not 3D shadows but 1px solid lines that feel like they have been cut into glass.
- **Neon Glow (Active State):** High-priority or active elements use a "neon" box-shadow. This is a diffused glow using the `primary_color_hex` with 0px offset and a 10px-15px blur, making the element appear to emit light rather than cast a shadow.
- **Recessed Wells:** To create hierarchy, secondary data areas are "milled" into the Obsidian background using a slightly lighter surface color and the scanline texture, making them feel like they are behind the primary glass layer.

## Shapes

The shape language is **Strictly Sharp (0px)**. 

To maintain the aggressive, tactical narrative, all corners must remain at 90 degrees. In specific high-tech instances (such as primary buttons or status badges), a 2px "micro-chamfer" or radius is permissible, but the default state is always 0px. This reinforces the idea of a system built for precision and security rather than consumer comfort.

## Components

- **Tactical Buttons:** Sharp corners, 1px Laser Hairline border, `data-main` typography in Uppercase. 
    - *Active:* Solid Terminal Green background with Obsidian text and a 10px neon glow.
    - *Hover:* Background becomes a 10% opacity Terminal Green tint.
- **Terminal Input Fields:** Backgrounds are recessed with scanline patterns. Border is a 1px solid line on the bottom only. The cursor should be a solid Terminal Green block that blinks.
- **Alert HUDs:** Large-scale containers for critical errors. These use Alert Red borders and a flickering scanline effect to demand immediate operator attention.
- **Data Tables:** No horizontal row lines. Use vertical Laser Hairlines between columns. Headers are `label-caps` with a 20% Terminal Green background tint.
- **Status Squares:** System status is communicated via 6x6px square blocks. No circles are permitted.
- **Scrollbars:** Ultra-thin (2px) Terminal Green lines with no track background, appearing only on interaction.