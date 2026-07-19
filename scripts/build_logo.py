#!/usr/bin/env python3
"""Derive the tintable logo mask from the full-colour source lockup.

`static/icons/logo.png` is the brand asset as exported: green-on-black, no alpha,
1254x1254, ~1 MB. That file cannot be used in the UI directly for three reasons:

  1. It has no alpha, so the baked black background renders as a black square on
     the light theme.
  2. It is green -- the same hue as `--ok`. Vantage reserves the status hues, and
     a brand mark that reads as "healthy" is exactly the confusion the achromatic
     "Halo" accent was chosen to avoid.
  3. It is ~65x larger than its display size.

So we emit a *mask*: alpha carries the artwork, RGB is flat white. The UI paints
it with `mask-image` over `background: var(--ink-1)`, which means one file that
follows the theme automatically -- white on dark, near-black on light -- instead
of two colour variants that can drift apart.

Alpha comes from luminance, which works because the source is bright artwork on a
black field. The soft outer glow survives as low alpha and reads as a soft edge.

Usage:
    python scripts/build_logo.py [src] [dst]
"""

import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SRC = ROOT / "static" / "icons" / "logo.png"
DEFAULT_DST = ROOT / "static" / "icons" / "logo-mask.png"

# Below this alpha a pixel is treated as background when finding the crop box, so
# the source's wide black margin does not survive into the mask. It is deliberately
# above zero: the glow fades asymptotically and a zero threshold crops nothing.
CROP_THRESHOLD = 12

# Longest edge of the emitted mask. The login lockup renders around 200px wide, so
# this leaves headroom for 2x displays without shipping the full 1254px source.
MAX_EDGE = 512


def build(src: Path, dst: Path) -> None:
    img = Image.open(src).convert("RGB")

    # Luminance -> alpha. The exact weighting matters little here since the artwork
    # is near-monochrome green, but using the standard one keeps the result
    # predictable if the brand colour ever changes.
    alpha = img.convert("L")

    bbox = alpha.point(lambda v: 255 if v >= CROP_THRESHOLD else 0).getbbox()
    if bbox is None:
        raise SystemExit(f"{src}: no pixels above the crop threshold -- is the source blank?")
    alpha = alpha.crop(bbox)

    if max(alpha.size) > MAX_EDGE:
        scale = MAX_EDGE / max(alpha.size)
        alpha = alpha.resize(
            (max(1, round(alpha.width * scale)), max(1, round(alpha.height * scale))),
            Image.LANCZOS,
        )

    mask = Image.new("RGBA", alpha.size, (255, 255, 255, 255))
    mask.putalpha(alpha)
    mask.save(dst, optimize=True)

    src_kb = src.stat().st_size / 1024
    dst_kb = dst.stat().st_size / 1024
    print(f"{src.name}  {img.width}x{img.height}  {src_kb:.0f} KB")
    print(f"{dst.name}  {mask.width}x{mask.height}  {dst_kb:.0f} KB")

    # A mask has no intrinsic size for CSS to inherit, so `.auth-brand` pins the
    # ratio by hand. Cropping is content-driven, which means editing the source
    # artwork silently changes it -- print the current value so a rebuild makes
    # the stale rule obvious instead of quietly letterboxing the logo.
    print(f"\n  .auth-brand needs:  aspect-ratio: {mask.width} / {mask.height};")


def _self_check() -> None:
    """Synthetic round-trip: bright shape on black must survive, margin must not."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src.png"
        dst = Path(tmp) / "dst.png"
        probe = Image.new("RGB", (100, 100), (0, 0, 0))
        for x in range(40, 60):
            for y in range(30, 70):
                probe.putpixel((x, y), (62, 207, 142))
        probe.save(src)

        build(src, dst)
        out = Image.open(dst)
        assert out.mode == "RGBA", out.mode
        # Cropped to the shape, not the 100x100 field.
        assert out.size == (20, 40), out.size
        # RGB is flat white; the artwork lives entirely in alpha.
        assert out.convert("RGB").getpixel((10, 20)) == (255, 255, 255)
        assert out.getchannel("A").getpixel((10, 20)) > 100
    print("self-check OK")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
    else:
        args = [a for a in sys.argv[1:] if not a.startswith("-")]
        build(
            Path(args[0]) if args else DEFAULT_SRC,
            Path(args[1]) if len(args) > 1 else DEFAULT_DST,
        )
