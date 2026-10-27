#!/usr/bin/env python3
import hashlib
import sys
from pathlib import Path

RESOURCES = Path(__file__).resolve().parents[1] / "Resources"
ROWS = 130
VERTICES_PER_ROW = 2
TRIANGLES = 2 * (ROWS - 1) * (VERTICES_PER_ROW - 1)


def function_object(value):
    return f"<< /FunctionType 2 /Domain [0 1] /C0 [{value}] /C1 [{value}] /N 1 >>".encode("ascii")


def build_pdf(range_dimension):
    if range_dimension < 1:
        raise ValueError("range dimension must be positive")
    values = ["0.5"] if range_dimension == 1 else ["0.5"] + [0] * (range_dimension - 2) + [1]
    function_refs = " ".join(f"{6 + index} 0 R" for index in range(range_dimension))
    stream = bytes(component for row in range(ROWS) for x in range(VERTICES_PER_ROW) for component in (x, row, 0))
    content = b"q\n/S sh\nQ\n"
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 256 256] /Resources << /Shading << /S 4 0 R >> >> /Contents 5 0 R >>",
        4: (f"<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate 8 "
            f"/BitsPerComponent 8 /VerticesPerRow {VERTICES_PER_ROW} "
            f"/Function [{function_refs}] /Decode [0 1 0 129 0 1] /Length {len(stream)} >>\n"
            "stream\n").encode("ascii") + stream + b"\nendstream",
        5: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"endstream",
    }
    for index, value in enumerate(values):
        objects[6 + index] = function_object(value)

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


def main():
    check = len(sys.argv) == 2 and sys.argv[1] == "--check"
    if len(sys.argv) > 1 and not check:
        raise SystemExit("usage: generate_cgtype5_pdfs.py [--check]")
    variants = {
        "cgtype5-benign.pdf": build_pdf(1),
        "cgtype5-r6-heap.pdf": build_pdf(6),
    }
    for name, data in variants.items():
        destination = RESOURCES / name
        if check:
            if not destination.exists() or destination.read_bytes() != data:
                raise SystemExit(f"MISMATCH: {destination}")
        else:
            destination.write_bytes(data)
        print(f"{name}: bytes={len(data)} triangles={TRIANGLES} sha256={hashlib.sha256(data).hexdigest()}")


if __name__ == "__main__":
    main()
