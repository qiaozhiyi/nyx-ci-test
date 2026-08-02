#!/usr/bin/env python3
"""Build a minimal valid Windows .ico wrapping the existing Tauri icon.png.

tauri-build (crates/client-ui-web/src-tauri/build.rs) requires an .ico file on
Windows targets. Without one, `cargo check --workspace --target windows-gnu`
fails inside the build script:

    "`icons/icon.ico` not found; required for generating a Windows Resource
     file during tauri-build"   (tauri-build 2.x, src/lib.rs)

The ICO container holds ONE image entry: the PNG payload embedded as-is
(PNG-in-ICO is supported since Windows Vista; a 512x512 image is representable
with the 0x00 width/height bytes, which mean 256+). This keeps the icon
byte-identical to src-tauri/icons/icon.png with zero re-encoding.

Usage:
    python3 tools/make_icon_ico.py [output.ico]

Default output: crates/client-ui-web/src-tauri/icons/icon.ico
"""

import struct
import sys
from pathlib import Path


def build_ico(png_path: Path, out_path: Path) -> None:
    png = png_path.read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n", f"{png_path} is not a PNG file"
    # ICO header: reserved(2)=0, type(2)=1 (icon), image count(2)=1
    header = struct.pack("<HHH", 0, 1, 1)
    # IHDR width/height are big-endian u32 at offsets 16/20.
    w = (png[16] << 24) | (png[17] << 16) | (png[18] << 8) | png[19]
    h = (png[20] << 24) | (png[21] << 16) | (png[22] << 8) | png[23]
    # Directory entry: width(1), height(1), color count(1), reserved(1),
    # planes(2)=1, bpp(2)=32, bytes-in-res(4), image offset(4).
    # 0x00 in width/height means 256 (the largest representable) — Windows
    # scales down for smaller targets.
    dim = 0 if (w >= 256 and h >= 256) else min(w, 255)
    entry = struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), 6 + 16)
    out_path.write_bytes(header + entry + png)
    print(f"wrote {out_path} ({6 + 16 + len(png)} bytes; PNG {w}x{h})")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    png_path = root / "crates/client-ui-web/src-tauri/icons/icon.png"
    out_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else root / "crates/client-ui-web/src-tauri/icons/icon.ico"
    )
    build_ico(png_path, out_path)
