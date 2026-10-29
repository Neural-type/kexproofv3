#!/usr/bin/env python3
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "Resources"
HEADER = ROOT / "Sources" / "KPDOVIRPUVariants.h"


class BitWriter:
    def __init__(self):
        self.bits = []

    def u(self, value, width):
        assert 0 <= value < (1 << width)
        self.bits.extend((value >> index) & 1 for index in range(width - 1, -1, -1))

    def ue(self, value):
        marker = value + 1
        prefix = marker.bit_length() - 1
        self.u(0, prefix)
        self.u(marker, prefix + 1)

    def finish(self):
        self.u(1, 1)
        while len(self.bits) % 8:
            self.u(0, 1)
        output = bytearray()
        for offset in range(0, len(self.bits), 8):
            value = 0
            for bit in self.bits[offset:offset + 8]:
                value = (value << 1) | bit
            output.append(value)
        return bytes(output)


def build_rpu(block_ids):
    writer = BitWriter()
    writer.u(0x19, 8)
    writer.u(2, 6)
    writer.u(0, 11)
    writer.u(0, 4)
    writer.u(0, 4)
    writer.u(0, 1)
    writer.u(1, 1)
    writer.u(0, 1)
    writer.u(0, 1)
    writer.u(0, 2)
    writer.u(0, 2)
    writer.u(0, 1)
    writer.u(0, 6)
    for block_id in block_ids:
        writer.ue(0)
        writer.u(block_id, 8)
    return writer.finish()


def variants():
    result = [{
        "identifier": "rpu-baseline",
        "resource": "rpu-baseline",
        "block_id": 0,
        "capacity": 0,
        "over": 0,
        "blocks": [],
    }]
    for prefix, block_id, capacity in (("a10", 10, 4), ("b2", 2, 8), ("c6", 6, 5)):
        for over in range(1, 9):
            result.append({
                "identifier": f"rpu-{prefix}-o{over}",
                "resource": f"rpu-{prefix}-o{over}",
                "block_id": block_id,
                "capacity": capacity,
                "over": over,
                "blocks": [block_id] * (capacity + over),
            })
    for item in result:
        data = build_rpu(item["blocks"])
        item["data"] = data
        item["sha256"] = hashlib.sha256(data).hexdigest()
    return result


def render_header(items):
    lines = [
        "#ifndef KPDOVIRPUVariants_h",
        "#define KPDOVIRPUVariants_h",
        "",
        "typedef struct {",
        "    const char *identifier;",
        "    const char *resource;",
        "    const char *sha256;",
        "    uint32_t blockID;",
        "    uint32_t capacity;",
        "    uint32_t over;",
        "} KPDOVIRPUVariant;",
        "",
        "static const KPDOVIRPUVariant KPDOVIRPUVariants[] = {",
    ]
    for item in items:
        lines.append(
            f'    {{"{item["identifier"]}", "{item["resource"]}", "{item["sha256"]}", '
            f'{item["block_id"]}, {item["capacity"]}, {item["over"]}}},'
        )
    lines += [
        "};",
        "",
        "static const NSUInteger KPDOVIRPUVariantCount = sizeof(KPDOVIRPUVariants) / sizeof(KPDOVIRPUVariants[0]);",
        "",
        "#endif",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def main():
    check = len(sys.argv) == 2 and sys.argv[1] == "--check"
    if len(sys.argv) > 1 and not check:
        raise SystemExit("usage: generate_dovi_rpu.py [--check]")
    items = variants()
    for item in items:
        destination = RESOURCES / f'{item["resource"]}.bin'
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
    print(f'count={len(items)} baseline={items[0]["data"].hex()}')
    for item in items[1:4]:
        print(f'{item["identifier"]}: bytes={len(item["data"])} sha256={item["sha256"]}')


if __name__ == "__main__":
    main()
