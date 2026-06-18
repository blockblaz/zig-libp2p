#!/usr/bin/env python3
"""Apply phases 0–2 of docs/REPO_LAYOUT.md (no behavior change)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def git_mv(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "mv", str(src.relative_to(ROOT)), str(dst.relative_to(ROOT))])


def write_shim(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rel = os.path.relpath((ROOT / target).resolve(), path.parent.resolve())
    # Normalize to forward slashes for Zig imports.
    rel = rel.replace(os.sep, "/")
    if not rel.startswith("."):
        rel = "./" + rel
    path.write_text(f'pub usingnamespace @import("{rel}");\n')


def replace_in_zig_files(fn) -> None:
    for path in SRC.rglob("*.zig"):
        text = path.read_text()
        new = fn(path, text)
        if new != text:
            path.write_text(new)


def fix_protocol_imports() -> None:
    """Fix ../foo.zig imports from src/protocols/** to primitives/core."""

    primitive_map = {
        "identity.zig": "../../primitives/identity.zig",
        "keypair.zig": "../../primitives/keypair.zig",
        "protocol.zig": "../../primitives/protocol.zig",
        "multistream.zig": "../../primitives/multistream.zig",
        "varint.zig": "../../primitives/varint.zig",
        "addr_list.zig": "../../primitives/addr_list.zig",
        "wall_time.zig": "../../primitives/wall_time.zig",
        "errors.zig": "../../primitives/errors.zig",
        "metrics.zig": "../../primitives/metrics.zig",
        "protobuf/wire.zig": "../../primitives/protobuf/wire.zig",
    }
    core_map = {
        "host.zig": "../../core/host.zig",
        "swarm.zig": "../../core/swarm.zig",
        "peer_events.zig": "../../core/peer_events.zig",
        "peer_protocols.zig": "../../core/peer_protocols.zig",
        "connection_manager.zig": "../../core/connection_manager.zig",
        "layer_events.zig": "../../core/layer_events.zig",
        "identify_advertisement.zig": "../../core/identify_advertisement.zig",
    }
    protocol_flat = {
        "identify.zig": "../identify/identify.zig",
        "ping.zig": "../ping/ping.zig",
        "ping_wire_quic.zig": "../ping/ping_wire_quic.zig",
    }

    def sub_imports(text: str, prefix: str) -> str:
        for name, new in primitive_map.items():
            text = text.replace(f'@import("{prefix}{name}")', f'@import("{new}")')
        for name, new in core_map.items():
            text = text.replace(f'@import("{prefix}{name}")', f'@import("{new}")')
        for name, new in protocol_flat.items():
            text = text.replace(f'@import("{prefix}{name}")', f'@import("{new}")')
        return text

    for path in (SRC / "protocols").rglob("*.zig"):
        text = path.read_text()
        text = sub_imports(text, "../")
        text = sub_imports(text, "../../")
        path.write_text(text)


def fix_transport_security_imports() -> None:
    primitive_map = {
        "identity.zig": "../primitives/identity.zig",
        "keypair.zig": "../primitives/keypair.zig",
        "protocol.zig": "../primitives/protocol.zig",
        "multistream.zig": "../primitives/multistream.zig",
        "varint.zig": "../primitives/varint.zig",
        "addr_list.zig": "../primitives/addr_list.zig",
        "wall_time.zig": "../primitives/wall_time.zig",
        "errors.zig": "../primitives/errors.zig",
        "metrics.zig": "../primitives/metrics.zig",
        "protobuf/wire.zig": "../primitives/protobuf/wire.zig",
    }
    core_map = {
        "host.zig": "../core/host.zig",
        "swarm.zig": "../core/swarm.zig",
        "peer_events.zig": "../core/peer_events.zig",
        "peer_protocols.zig": "../core/peer_protocols.zig",
        "connection_manager.zig": "../core/connection_manager.zig",
        "layer_events.zig": "../core/layer_events.zig",
        "identify_advertisement.zig": "../core/identify_advertisement.zig",
    }
    protocol_dirs = [
        "gossipsub",
        "req_resp",
        "autonat",
        "kad_dht",
        "relay",
        "dcutr",
        "discovery",
    ]

    def fix_file(path: Path) -> None:
        text = path.read_text()
        orig = text
        for name, new in primitive_map.items():
            text = text.replace(f'@import("../{name}")', f'@import("{new}")')
        for name, new in core_map.items():
            text = text.replace(f'@import("../{name}")', f'@import("{new}")')
        for d in protocol_dirs:
            text = re.sub(
                rf'@import\("\.\./{d}/',
                f'@import("../protocols/{d}/',
                text,
            )
        text = text.replace(
            '@import("../identify.zig")',
            '@import("../protocols/identify/identify.zig")',
        )
        text = text.replace(
            '@import("../ping.zig")',
            '@import("../protocols/ping/ping.zig")',
        )
        text = text.replace(
            '@import("../ping_wire_quic.zig")',
            '@import("../protocols/ping/ping_wire_quic.zig")',
        )
        if text != orig:
            path.write_text(text)

    for sub in ("transport", "security", "internal", "core"):
        p = SRC / sub
        if p.exists():
            for zig in p.rglob("*.zig"):
                fix_file(zig)


def fix_core_imports() -> None:
    for path in (SRC / "core").rglob("*.zig"):
        text = path.read_text()
        orig = text
        # Siblings in core/
        # Primitives
        for name in (
            "identity.zig",
            "keypair.zig",
            "protocol.zig",
            "multistream.zig",
            "varint.zig",
            "addr_list.zig",
            "wall_time.zig",
            "errors.zig",
            "metrics.zig",
        ):
            text = text.replace(
                f'@import("{name}")',
                f'@import("../primitives/{name}")',
            )
        # Protocols
        for d in (
            "gossipsub",
            "req_resp",
            "autonat",
            "kad_dht",
            "relay",
            "dcutr",
            "discovery",
        ):
            text = re.sub(
                rf'@import\("{d}/',
                f'@import("../protocols/{d}/',
                text,
            )
        text = text.replace(
            '@import("identify.zig")',
            '@import("../protocols/identify/identify.zig")',
        )
        text = text.replace(
            '@import("identify_advertisement.zig")',
            '@import("identify_advertisement.zig")',
        )
        text = text.replace(
            '@import("ping.zig")',
            '@import("../protocols/ping/ping.zig")',
        )
        text = text.replace(
            '@import("ping_wire_quic.zig")',
            '@import("../protocols/ping/ping_wire_quic.zig")',
        )
        # Core siblings stay as bare names — already correct when both in core/
        if text != orig:
            path.write_text(text)


def create_flat_shims() -> None:
    flat_core = [
        "host.zig",
        "swarm.zig",
        "connection_manager.zig",
        "peer_events.zig",
        "peer_protocols.zig",
        "layer_events.zig",
        "identify_advertisement.zig",
    ]
    flat_primitives = [
        "identity.zig",
        "keypair.zig",
        "protocol.zig",
        "multistream.zig",
        "varint.zig",
        "addr_list.zig",
        "wall_time.zig",
        "errors.zig",
        "metrics.zig",
    ]
    for f in flat_core:
        write_shim(SRC / f, f"src/core/{f}")
    for f in flat_primitives:
        write_shim(SRC / f, f"src/primitives/{f}")
    write_shim(SRC / "wire_boundaries.zig", "src/internal/wire_boundaries.zig")
    write_shim(SRC / "identify.zig", "src/protocols/identify/identify.zig")
    write_shim(SRC / "ping.zig", "src/protocols/ping/ping.zig")
    write_shim(SRC / "ping_wire_quic.zig", "src/protocols/ping/ping_wire_quic.zig")

    protocol_roots = ["autonat", "kad_dht", "relay", "dcutr", "discovery"]
    for d in protocol_roots:
        write_shim(SRC / d / "root.zig", f"src/protocols/{d}/root.zig")

    for d in ("gossipsub", "req_resp"):
        proto_dir = SRC / "protocols" / d
        shim_dir = SRC / d
        shim_dir.mkdir(exist_ok=True)
        for zig in proto_dir.glob("*.zig"):
            write_shim(shim_dir / zig.name, f"src/protocols/{d}/{zig.name}")

    write_shim(SRC / "gossip" / "topic.zig", "src/protocols/gossip/topic.zig")
    write_shim(SRC / "protobuf" / "wire.zig", "src/primitives/protobuf/wire.zig")


def phase0() -> None:
    if (ROOT / "harness").exists():
        return
    git_mv(ROOT / "interop", ROOT / "harness" / "tcp")
    git_mv(ROOT / "interop_quic", ROOT / "harness" / "quic")
    git_mv(ROOT / "test" / "fixtures", ROOT / "fixtures")
    test_dir = ROOT / "test"
    if test_dir.exists() and not any(test_dir.iterdir()):
        test_dir.rmdir()


def phase1_2() -> None:
    if (SRC / "core").exists():
        return

    (SRC / "protocols").mkdir()
    (SRC / "core").mkdir()
    (SRC / "primitives").mkdir()
    (SRC / "internal").mkdir()

    for d in ("autonat", "kad_dht", "relay", "dcutr", "gossipsub", "req_resp", "discovery"):
        git_mv(SRC / d, SRC / "protocols" / d)

    git_mv(SRC / "gossip", SRC / "protocols" / "gossip")

    (SRC / "protocols" / "identify").mkdir()
    (SRC / "protocols" / "ping").mkdir()
    git_mv(SRC / "identify.zig", SRC / "protocols" / "identify" / "identify.zig")
    git_mv(SRC / "ping.zig", SRC / "protocols" / "ping" / "ping.zig")
    git_mv(SRC / "ping_wire_quic.zig", SRC / "protocols" / "ping" / "ping_wire_quic.zig")

    for f in (
        "host.zig",
        "swarm.zig",
        "connection_manager.zig",
        "peer_events.zig",
        "peer_protocols.zig",
        "layer_events.zig",
        "identify_advertisement.zig",
    ):
        git_mv(SRC / f, SRC / "core" / f)

    for f in (
        "identity.zig",
        "keypair.zig",
        "protocol.zig",
        "multistream.zig",
        "varint.zig",
        "addr_list.zig",
        "wall_time.zig",
        "errors.zig",
        "metrics.zig",
    ):
        git_mv(SRC / f, SRC / "primitives" / f)

    git_mv(SRC / "protobuf", SRC / "primitives" / "protobuf")
    git_mv(SRC / "wire_boundaries.zig", SRC / "internal" / "wire_boundaries.zig")

    fix_protocol_imports()
    fix_core_imports()
    fix_transport_security_imports()
    create_flat_shims()


def main() -> None:
    phase0()
    phase1_2()
    print("Done. Run: zig fmt . && zig build test --summary all")


if __name__ == "__main__":
    main()
