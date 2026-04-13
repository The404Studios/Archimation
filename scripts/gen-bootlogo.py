#!/usr/bin/env python3
"""
Generate the ArchWindows GRUB bootloader splash image.
Modified by fourzerofour

Outputs a 1024x768 PNG suitable for GRUB background_image.
Uses only PIL (Pillow) — no external dependencies.
"""

import sys
import os
from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1024, 768

def draw_gradient(draw, w, h, top_color, bottom_color):
    """Draw a vertical gradient background."""
    for y in range(h):
        ratio = y / h
        r = int(top_color[0] + (bottom_color[0] - top_color[0]) * ratio)
        g = int(top_color[1] + (bottom_color[1] - top_color[1]) * ratio)
        b = int(top_color[2] + (bottom_color[2] - top_color[2]) * ratio)
        draw.line([(0, y), (w - 1, y)], fill=(r, g, b))

def draw_arch_logo(draw, cx, cy, size, color):
    """Draw a stylized Arch Linux 'A' shape."""
    # The iconic Arch "A" — a pointed arch
    half = size // 2
    peak_y = cy - size
    base_y = cy + half // 2

    # Outer arch shape
    points = [
        (cx, peak_y),                          # Peak
        (cx + half + 10, base_y),              # Right base outer
        (cx + half - 8, base_y),               # Right base inner
        (cx, peak_y + size // 3),              # Inner notch
        (cx - half + 8, base_y),               # Left base inner
        (cx - half - 10, base_y),              # Left base outer
    ]
    draw.polygon(points, fill=color)

    # Inner cutout (the notch in the Arch logo)
    notch_points = [
        (cx, peak_y + size // 2 + 5),
        (cx + half // 3, base_y + 1),
        (cx - half // 3, base_y + 1),
    ]
    # Draw the background color in the notch area
    draw.polygon(notch_points, fill=(10, 15, 36))

def draw_windows_logo(draw, cx, cy, size, colors):
    """Draw a stylized Windows 4-pane logo."""
    gap = 4
    pane_w = (size - gap) // 2
    pane_h = (size - gap) // 2

    # Top-left (red)
    draw.rectangle(
        [cx - pane_w - gap//2, cy - pane_h - gap//2,
         cx - gap//2, cy - gap//2],
        fill=colors[0]
    )
    # Top-right (green)
    draw.rectangle(
        [cx + gap//2, cy - pane_h - gap//2,
         cx + pane_w + gap//2, cy - gap//2],
        fill=colors[1]
    )
    # Bottom-left (blue)
    draw.rectangle(
        [cx - pane_w - gap//2, cy + gap//2,
         cx - gap//2, cy + pane_h + gap//2],
        fill=colors[2]
    )
    # Bottom-right (yellow)
    draw.rectangle(
        [cx + gap//2, cy + gap//2,
         cx + pane_w + gap//2, cy + pane_h + gap//2],
        fill=colors[3]
    )

def draw_combined_logo(draw, cx, cy):
    """Draw the combined ArchWindows hybrid logo."""
    # Windows panes in Arch blue tones
    win_colors = [
        (233, 69, 96),    # Red-pink (top-left)
        (69, 233, 150),   # Green (top-right)
        (23, 147, 209),   # Arch blue (bottom-left)
        (255, 206, 68),   # Gold (bottom-right)
    ]
    draw_windows_logo(draw, cx, cy - 20, 80, win_colors)

    # Arch "A" overlaid larger behind/above
    draw_arch_logo(draw, cx, cy + 10, 90, (23, 147, 209))

def load_font(name, size, fallback_size=None):
    """Try to load a TTF font, falling back to default."""
    paths = [
        f'/usr/share/fonts/TTF/{name}',
        f'/usr/share/fonts/truetype/dejavu/{name}',
        f'/usr/share/fonts/truetype/{name}',
        f'/usr/share/fonts/{name}',
        f'C:/Windows/Fonts/{name}',
    ]
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()

def main():
    outpath = sys.argv[1] if len(sys.argv) > 1 else "archwindows.png"

    img = Image.new('RGB', (WIDTH, HEIGHT))
    draw = ImageDraw.Draw(img)

    # Dark gradient background: deep navy to near-black
    draw_gradient(draw, WIDTH, HEIGHT, (10, 15, 36), (2, 4, 12))

    # Subtle grid lines (Windows aesthetic)
    for x in range(0, WIDTH, 64):
        draw.line([(x, 0), (x, HEIGHT)], fill=(20, 28, 55), width=1)
    for y in range(0, HEIGHT, 64):
        draw.line([(0, y), (WIDTH, y)], fill=(20, 28, 55), width=1)

    # Center point
    cx, cy = WIDTH // 2, HEIGHT // 2 - 80

    # --- Combined Logo ---
    # Windows 4-pane in the center
    win_size = 100
    gap = 6
    pane_w = (win_size - gap) // 2
    pane_h = (win_size - gap) // 2
    logo_cy = cy - 30

    # Glowing halo behind logo
    for r in range(80, 0, -2):
        alpha = int(15 * (80 - r) / 80)
        halo_color = (23 + alpha, 40 + alpha, 90 + alpha)
        draw.ellipse(
            [cx - r, logo_cy - r, cx + r, logo_cy + r],
            fill=halo_color
        )

    # Windows panes with Arch-inspired colors
    pane_colors = [
        (233, 69, 96),     # Arch red-pink  (top-left)
        (69, 210, 150),    # Green           (top-right)
        (23, 147, 209),    # Arch blue       (bottom-left)
        (255, 206, 68),    # Gold            (bottom-right)
    ]

    panes = [
        (cx - pane_w - gap//2, logo_cy - pane_h - gap//2,
         cx - gap//2, logo_cy - gap//2),
        (cx + gap//2, logo_cy - pane_h - gap//2,
         cx + pane_w + gap//2, logo_cy - gap//2),
        (cx - pane_w - gap//2, logo_cy + gap//2,
         cx - gap//2, logo_cy + pane_h + gap//2),
        (cx + gap//2, logo_cy + gap//2,
         cx + pane_w + gap//2, logo_cy + pane_h + gap//2),
    ]

    # Perspective tilt: skew panes slightly (Windows 8+ style)
    for i, (x1, y1, x2, y2) in enumerate(panes):
        # Add subtle shadow
        draw.rectangle([x1+3, y1+3, x2+3, y2+3], fill=(0, 0, 0))
        # Draw pane
        draw.rectangle([x1, y1, x2, y2], fill=pane_colors[i])

    # Arch "A" mark above the Windows logo
    arch_peak_y = logo_cy - pane_h - gap//2 - 55
    arch_points = [
        (cx, arch_peak_y),                        # Peak
        (cx + 28, logo_cy - pane_h - gap//2 - 5), # Right
        (cx + 18, logo_cy - pane_h - gap//2 - 5), # Right inner
        (cx, arch_peak_y + 20),                    # Notch
        (cx - 18, logo_cy - pane_h - gap//2 - 5), # Left inner
        (cx - 28, logo_cy - pane_h - gap//2 - 5), # Left
    ]
    draw.polygon(arch_points, fill=(23, 147, 209))

    # --- Title text ---
    font_title = load_font('DejaVuSans-Bold.ttf', 52)
    font_sub = load_font('DejaVuSans.ttf', 18)
    font_credit = load_font('DejaVuSans.ttf', 13)
    font_menu = load_font('DejaVuSans.ttf', 14)

    title_y = logo_cy + pane_h + gap//2 + 30

    # "ArchWindows" in gradient-like two-tone
    title = "ArchWindows"
    bbox = draw.textbbox((0, 0), title, font=font_title)
    tw = bbox[2] - bbox[0]

    # Shadow
    draw.text((cx - tw//2 + 2, title_y + 2), title,
              fill=(0, 0, 0), font=font_title)
    # Main text: "Arch" in blue, "Windows" in white
    arch_text = "Arch"
    windows_text = "Windows"
    arch_bbox = draw.textbbox((0, 0), arch_text, font=font_title)
    arch_tw = arch_bbox[2] - arch_bbox[0]

    start_x = cx - tw // 2
    draw.text((start_x, title_y), arch_text,
              fill=(23, 147, 209), font=font_title)
    draw.text((start_x + arch_tw, title_y), windows_text,
              fill=(220, 225, 240), font=font_title)

    # Subtitle
    subtitle = "AI-Powered Linux  |  Full Windows Compatibility"
    sub_bbox = draw.textbbox((0, 0), subtitle, font=font_sub)
    sub_tw = sub_bbox[2] - sub_bbox[0]
    draw.text((cx - sub_tw//2, title_y + 62), subtitle,
              fill=(140, 150, 180), font=font_sub)

    # Decorative line under subtitle
    line_y = title_y + 90
    line_half = 200
    draw.line([(cx - line_half, line_y), (cx + line_half, line_y)],
              fill=(40, 60, 100), width=1)

    # Credit line
    credit = "modified by fourzerofour"
    cr_bbox = draw.textbbox((0, 0), credit, font=font_credit)
    cr_tw = cr_bbox[2] - cr_bbox[0]
    draw.text((cx - cr_tw//2, HEIGHT - 45), credit,
              fill=(80, 90, 120), font=font_credit)

    # Version / build line
    version = "v1.0  |  Built with Arch Linux"
    ver_bbox = draw.textbbox((0, 0), version, font=font_credit)
    ver_tw = ver_bbox[2] - ver_bbox[0]
    draw.text((cx - ver_tw//2, HEIGHT - 25), version,
              fill=(50, 60, 85), font=font_credit)

    # Corner accents (tech aesthetic)
    accent_color = (23, 147, 209)
    # Top-left
    draw.line([(20, 20), (20, 50)], fill=accent_color, width=2)
    draw.line([(20, 20), (50, 20)], fill=accent_color, width=2)
    # Top-right
    draw.line([(WIDTH-20, 20), (WIDTH-20, 50)], fill=accent_color, width=2)
    draw.line([(WIDTH-20, 20), (WIDTH-50, 20)], fill=accent_color, width=2)
    # Bottom-left
    draw.line([(20, HEIGHT-20), (20, HEIGHT-50)], fill=accent_color, width=2)
    draw.line([(20, HEIGHT-20), (50, HEIGHT-20)], fill=accent_color, width=2)
    # Bottom-right
    draw.line([(WIDTH-20, HEIGHT-20), (WIDTH-20, HEIGHT-50)], fill=accent_color, width=2)
    draw.line([(WIDTH-20, HEIGHT-20), (WIDTH-50, HEIGHT-20)], fill=accent_color, width=2)

    img.save(outpath)
    print(f"ArchWindows boot logo saved to: {outpath}")
    print(f"  Size: {WIDTH}x{HEIGHT}")
    print(f"  Modified by fourzerofour")

if __name__ == "__main__":
    main()
