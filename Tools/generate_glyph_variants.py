#!/usr/bin/env python3
import hashlib
import sys
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "calif-glyph" / "trigger"))

from gen_font import build_pdf, build_ttf


def main():
    font = build_ttf(dx=33, n=9, trigger_x=32000)
    font.font["head"].created = 2082844800
    font.font["head"].modified = 2082844800
    buffer = BytesIO()
    font.save(buffer)
    pdf = build_pdf(buffer.getvalue(), tm_a=0.75, tm_d=1.0, ptsize=1024)
    destination = ROOT / "KexProofV3" / "Resources" / "glyph-tm075.pdf"
    destination.write_bytes(pdf)
    print(f"wrote {destination} ({len(pdf)} bytes)")
    print(f"sha256={hashlib.sha256(pdf).hexdigest()}")


if __name__ == "__main__":
    main()
