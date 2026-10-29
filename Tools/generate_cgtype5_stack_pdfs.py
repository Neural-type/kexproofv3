#!/usr/bin/env python3
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "Resources"
HEADER = ROOT / "Sources" / "KPCGType5StackVariants.h"
ROWS = 2
VERTICES_PER_ROW = 2
TRIANGLES = 2 * (ROWS - 1) * (VERTICES_PER_ROW - 1)
ALLOCATION = 216 * TRIANGLES


def function_object():
    return b"<< /FunctionType 2 /Domain [0 1] /C0 [1.0] /C1 [1.0] /N 1 >>"


def build_pdf(range_dimension):
    function_refs = " ".join(f"{6 + index} 0 R" for index in range(range_dimension))
    stream = bytes(component for row in range(ROWS) for x in range(VERTICES_PER_ROW) for component in (x, row, 0))
    content = b"q\n/S sh\nQ\n"
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 256 256] /Resources << /Shading << /S 4 0 R >> >> /Contents 5 0 R >>",
        4: (f"<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate 8 "
            f"/BitsPerComponent 8 /VerticesPerRow {VERTICES_PER_ROW} "
            f"/Function [{function_refs}] /Decode [0 1 0 1 0 1] /Length {len(stream)} >>\n"
            "stream\n").encode("ascii") + stream + b"\nendstream",
        5: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream",
    }
    for index in range(range_dimension):
        objects[6 + index] = function_object()
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number in range(1, 6 + range_dimension):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(objects[number])
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {6 + range_dimension}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer\n<< /Size {6 + range_dimension} /Root 1 0 R >>\n".encode("ascii"))
    pdf.extend(f"startxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(pdf)


def variants():
    result = []
    for range_dimension in range(4, 257, 4):
        data = build_pdf(range_dimension)
        result.append({
            "identifier": f"type5-stack-r{range_dimension:03d}",
            "resource": f"cgtype5-stack-r{range_dimension:03d}",
            "range": range_dimension,
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": data,
        })
    return result


def render_header(items):
    lines = [
        "#ifndef KPCGType5StackVariants_h",
        "#define KPCGType5StackVariants_h",
        "",
        "typedef struct {",
        "    const char *identifier;",
        "    const char *resource;",
        "    const char *sha256;",
        "    uint32_t rangeDimension;",
        "    uint32_t colorSpaceComponents;",
        "    uint32_t verticesPerRow;",
        "    uint32_t rows;",
        "    uint32_t triangles;",
        "    uint32_t allocationSize;",
        "} KPCGType5StackVariant;",
        "",
        "static const KPCGType5StackVariant KPCGType5StackVariants[] = {",
    ]
    for item in items:
        lines.append(
            f'    {{"{item["identifier"]}", "{item["resource"]}", "{item["sha256"]}", '
            f'{item["range"]}, 1, {VERTICES_PER_ROW}, {ROWS}, {TRIANGLES}, 0x{ALLOCATION:x}}},'
        )
    lines += [
        "};",
        "",
        "static const NSUInteger KPCGType5StackVariantCount = sizeof(KPCGType5StackVariants) / sizeof(KPCGType5StackVariants[0]);",
        "",
        "#endif",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def main():
    check = len(sys.argv) == 2 and sys.argv[1] == "--check"
    if len(sys.argv) > 1 and not check:
        raise SystemExit("usage: generate_cgtype5_stack_pdfs.py [--check]")
    items = variants()
    for item in items:
        destination = RESOURCES / f'{item["resource"]}.pdf'
        if check:
            if not destination.exists() or destination.read_bytes() != item["data"]:
                raise SystemExit(f"MISMATCH: {destination}")
        else:
            destination.write_bytes(item["data"])
    expected_header = render_header(items)
    if check:
        if not HEADER.exists() or HEADER.read_bytes() != expected_header:
            raise SystemExit(f"MISMATCH: {HEADER}")
    else:
        HEADER.write_bytes(expected_header)
    main_variant = items[(136 - 4) // 4]
    print(f'count={len(items)} triangles={TRIANGLES} allocation=0x{ALLOCATION:x}')
    print(f'r004_sha256={items[0]["sha256"]}')
    print(f'r136_sha256={main_variant["sha256"]}')


if __name__ == "__main__":
    main()
