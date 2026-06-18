#!/usr/bin/env python3
"""Phases 3 and 5 of docs/REPO_LAYOUT.md (phase 4 = build/*.zig written separately)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = ROOT / "src" / "transport"
QUIC = TRANSPORT / "quic"


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def git_mv(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "mv", str(src.relative_to(ROOT)), str(dst.relative_to(ROOT))])


def write_shim(path: Path, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rel = os.path.relpath((ROOT / target).resolve(), path.parent.resolve()).replace(os.sep, "/")
    if not rel.startswith("."):
        rel = "./" + rel
    text = (ROOT / target).read_text()
    exports = re.findall(r"^pub\s+(?:const|fn)\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.M)
    lines = [
        "//! Compatibility shim for legacy import paths (Zig 0.16).",
        f'const _shim_src = @import("{rel}");',
        "",
    ]
    for name in exports:
        lines.append(f"pub const {name} = _shim_src.{name};")
    lines.append("")
    path.write_text("\n".join(lines))


def phase3_quic_dir() -> None:
    if (QUIC / "runtime.zig").exists() and not (TRANSPORT / "quic_runtime.zig").exists():
        return

    QUIC.mkdir(parents=True, exist_ok=True)

    file_moves = {
        "quic.zig": "quic.zig",
        "quic_v1.zig": "v1.zig",
        "quic_endpoint.zig": "endpoint.zig",
        "quic_peer_identity.zig": "peer_identity.zig",
        "quic_raw_stream_io.zig": "raw_stream_io.zig",
        "quic_posix_udp.zig": "posix_udp.zig",
        "quic_relay_live.zig": "relay_live.zig",
        "quic_dcutr_live.zig": "dcutr_live.zig",
    }
    for old, new in file_moves.items():
        src = TRANSPORT / old
        if src.exists():
            git_mv(src, QUIC / new)

    runtime_src = TRANSPORT / "quic_runtime.zig"
    if runtime_src.exists():
        git_mv(runtime_src, QUIC / "runtime.zig")

    split_runtime_file()
    fix_imports()

    for old, new in file_moves.items():
        write_shim(TRANSPORT / old, f"src/transport/quic/{new}")
    write_shim(TRANSPORT / "quic_runtime.zig", "src/transport/quic/runtime.zig")


def split_runtime_file() -> None:
    runtime_path = QUIC / "runtime.zig"
    if (QUIC / "config.zig").exists():
        return

    lines = runtime_path.read_text().splitlines(keepends=True)
    # 1-based line numbers from original file.
    config_slice = lines[16:218]
    conn_slice = lines[218:634]
    runtime_slice = lines[634:]

    config_prelude = """//! QUIC runtime configuration and protocol constants.

const std = @import("std");

const host_mod = @import("../../core/host.zig");
const wall_time = @import("../../primitives/wall_time.zig");
const protocol_mod = @import("../../primitives/protocol.zig");
const varint = @import("../../primitives/varint.zig");
const wire_framing = @import("../../protocols/req_resp/wire_framing.zig");
const gossipsub_wire_limits = @import("../../protocols/gossipsub/wire_limits.zig");
const relay_mod = @import("../../protocols/relay/root.zig");
const dcutr_mod = @import("../../protocols/dcutr/root.zig");
const autonat_mod = @import("../../protocols/autonat/root.zig");
const identify_mod = @import("../../protocols/identify/identify.zig");
const ping_mod = @import("../../protocols/ping/ping.zig");

"""

    conn_prelude = """//! Per-connection QUIC runtime tables and stream state.

const std = @import("std");

const identity = @import("../../primitives/identity.zig");
const protocol_mod = @import("../../primitives/protocol.zig");
const connection_manager_mod = @import("../../core/connection_manager.zig");

"""

    runtime_prelude = """//! Bundled libp2p QUIC transport runtime.

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.quic_runtime);
const testing = std.testing;

const multiaddr = @import("multiaddr");

const errors_mod = @import("../../primitives/errors.zig");
const host_mod = @import("../../core/host.zig");
const identity = @import("../../primitives/identity.zig");
const peer_events = @import("../../core/peer_events.zig");
const protocol_mod = @import("../../primitives/protocol.zig");
const swarm_mod = @import("../../core/swarm.zig");
const connection_manager_mod = @import("../../core/connection_manager.zig");
const wall_time = @import("../../primitives/wall_time.zig");

const quic = @import("quic.zig");
const quic_v1 = @import("v1.zig");
const quic_endpoint = @import("endpoint.zig");
const quic_peer_identity = @import("peer_identity.zig");
const quic_raw_stream_io = @import("raw_stream_io.zig");
const stream_multistream = @import("../stream_multistream.zig");

const wire_framing = @import("../../protocols/req_resp/wire_framing.zig");
const snappy_wire = @import("../../protocols/req_resp/snappy_wire.zig");

const gossipsub_msg = @import("../../protocols/gossipsub/message.zig");
const gossipsub_rpc = @import("../../protocols/gossipsub/rpc.zig");
const gossipsub_cfg = @import("../../protocols/gossipsub/config.zig");
const gossipsub_wire_limits = @import("../../protocols/gossipsub/wire_limits.zig");
const varint = @import("../../primitives/varint.zig");

const relay_mod = @import("../../protocols/relay/root.zig");
const dcutr_mod = @import("../../protocols/dcutr/root.zig");
const autonat_mod = @import("../../protocols/autonat/root.zig");
const identify_mod = @import("../../protocols/identify/identify.zig");
const ping_mod = @import("../../protocols/ping/ping.zig");
const libp2p_tls = @import("../../security/libp2p_tls.zig");
const libp2p_tls_cert = @import("../../security/libp2p_tls_cert.zig");
const quic_relay_live = @import("relay_live.zig");
const quic_dcutr_live = @import("dcutr_live.zig");

const zquic = @import("zquic");
const ZIo = zquic.transport.io;
const peer_id_pkg = @import("peer_id");

const config = @import("config.zig");
const conn_table = @import("conn_table.zig");

pub const TlsPemSource = config.TlsPemSource;
pub const QuicRuntimeOptions = config.QuicRuntimeOptions;
pub const RelayRuntimeOptions = config.RelayRuntimeOptions;
pub const DcutrRuntimeOptions = config.DcutrRuntimeOptions;
pub const AutonatRuntimeOptions = config.AutonatRuntimeOptions;

"""

    def pubify(body: str, names: list[str]) -> str:
        for n in names:
            body = re.sub(rf"(?<!\w)const {re.escape(n)}\b", f"pub const {n}", body)
            body = re.sub(rf"(?<!\w)fn {re.escape(n)}\b", f"pub fn {n}", body)
        return body

    config_body = pubify(
        "".join(config_slice),
        [
            "meshsub_protocol_id",
            "meshsub_protocol_id_v10",
            "meshsub_protocol_id_v12",
            "meshsub_protocol_id_v13",
            "meshsub_initiator_offer",
            "meshsub_offer_fallbacks",
            "max_inbound_gossip_acc_bytes",
            "max_inbound_req_acc_bytes",
            "identify_protocol_id",
            "identify_push_protocol_id",
            "autonat_protocol_id",
            "supported_protocols",
            "proto_meshsub_last_index",
            "proto_meshsub",
            "proto_relay_hop",
            "proto_relay_stop",
            "proto_dcutr",
            "proto_autonat",
            "proto_identify",
            "proto_ping",
            "proto_identify_push",
            "max_inbound_relay_acc_bytes",
            "PemError",
            "TlsPemSource",
            "ResolvedTlsPem",
            "QuicRuntimeOptions",
            "RelayRuntimeOptions",
            "DcutrRuntimeOptions",
            "AutonatRuntimeOptions",
        ],
    )
    config_body = config_body.replace("fn normalizeProtocolIndex", "pub fn normalizeProtocolIndex")
    config_body = config_body.replace("fn resolveTlsPemSource", "pub fn resolveTlsPemSource")

    conn_body = pubify(
        "".join(conn_slice),
        [
            "PeerIdContext",
            "PeerIdMap",
            "InboundPeerMap",
            "PersistentGossipMap",
            "RelayedConnIdMap",
            "InboundConnRef",
            "OutboundConn",
            "InboundStream",
            "OutboundRequest",
            "PublishBidiStream",
            "OutboundPublish",
            "OutboundIdentifyPush",
            "OutboundAutonatProbe",
            "PersistentGossipStream",
            "persistent_gossip_outbox_cap",
            "persistent_gossip_keepalive_interval_ms",
            "persistent_gossip_outbox_stuck_timeout_ms",
            "HookWork",
            "SpinLock",
            "InboundGossipWork",
            "inbound_gossip_work_cap_entries",
            "inbound_gossip_work_cap_bytes",
        ],
    )
    conn_body = conn_body.replace("fn freeHookWork", "pub fn freeHookWork")

    runtime_body = "".join(runtime_slice)
    mapping = [
        ("TlsPemSource", "config.TlsPemSource"),
        ("QuicRuntimeOptions", "config.QuicRuntimeOptions"),
        ("RelayRuntimeOptions", "config.RelayRuntimeOptions"),
        ("DcutrRuntimeOptions", "config.DcutrRuntimeOptions"),
        ("AutonatRuntimeOptions", "config.AutonatRuntimeOptions"),
        ("ResolvedTlsPem", "config.ResolvedTlsPem"),
        ("resolveTlsPemSource", "config.resolveTlsPemSource"),
        ("PemError", "config.PemError"),
        ("PeerIdContext", "conn_table.PeerIdContext"),
        ("PeerIdMap", "conn_table.PeerIdMap"),
        ("InboundPeerMap", "conn_table.InboundPeerMap"),
        ("PersistentGossipMap", "conn_table.PersistentGossipMap"),
        ("RelayedConnIdMap", "conn_table.RelayedConnIdMap"),
        ("InboundConnRef", "conn_table.InboundConnRef"),
        ("OutboundConn", "conn_table.OutboundConn"),
        ("InboundStream", "conn_table.InboundStream"),
        ("OutboundRequest", "conn_table.OutboundRequest"),
        ("PublishBidiStream", "conn_table.PublishBidiStream"),
        ("OutboundPublish", "conn_table.OutboundPublish"),
        ("OutboundIdentifyPush", "conn_table.OutboundIdentifyPush"),
        ("OutboundAutonatProbe", "conn_table.OutboundAutonatProbe"),
        ("PersistentGossipStream", "conn_table.PersistentGossipStream"),
        ("HookWork", "conn_table.HookWork"),
        ("SpinLock", "conn_table.SpinLock"),
        ("InboundGossipWork", "conn_table.InboundGossipWork"),
        ("freeHookWork", "conn_table.freeHookWork"),
        ("supported_protocols", "config.supported_protocols"),
        ("normalizeProtocolIndex", "config.normalizeProtocolIndex"),
        ("proto_meshsub", "config.proto_meshsub"),
        ("proto_relay_hop", "config.proto_relay_hop"),
        ("proto_relay_stop", "config.proto_relay_stop"),
        ("proto_dcutr", "config.proto_dcutr"),
        ("proto_autonat", "config.proto_autonat"),
        ("proto_identify", "config.proto_identify"),
        ("proto_ping", "config.proto_ping"),
        ("proto_identify_push", "config.proto_identify_push"),
        ("max_inbound_gossip_acc_bytes", "config.max_inbound_gossip_acc_bytes"),
        ("max_inbound_req_acc_bytes", "config.max_inbound_req_acc_bytes"),
        ("max_inbound_relay_acc_bytes", "config.max_inbound_relay_acc_bytes"),
        ("meshsub_offer_fallbacks", "config.meshsub_offer_fallbacks"),
        ("meshsub_initiator_offer", "config.meshsub_initiator_offer"),
        ("persistent_gossip_outbox_cap", "conn_table.persistent_gossip_outbox_cap"),
        ("persistent_gossip_keepalive_interval_ms", "conn_table.persistent_gossip_keepalive_interval_ms"),
        ("persistent_gossip_outbox_stuck_timeout_ms", "conn_table.persistent_gossip_outbox_stuck_timeout_ms"),
        ("inbound_gossip_work_cap_entries", "conn_table.inbound_gossip_work_cap_entries"),
        ("inbound_gossip_work_cap_bytes", "conn_table.inbound_gossip_work_cap_bytes"),
        ("identify_protocol_id", "config.identify_protocol_id"),
        ("identify_push_protocol_id", "config.identify_push_protocol_id"),
        ("autonat_protocol_id", "config.autonat_protocol_id"),
    ]
    for old, new in mapping:
        runtime_body = re.sub(rf"\b{re.escape(old)}\b", new, runtime_body)

    (QUIC / "config.zig").write_text(config_prelude + config_body)
    (QUIC / "conn_table.zig").write_text(conn_prelude + conn_body)
    runtime_path.write_text(runtime_prelude + runtime_body)


def fix_imports() -> None:
    quic_files = list(QUIC.glob("*.zig")) if QUIC.exists() else []
    for path in quic_files:
        text = path.read_text()
        orig = text
        text = text.replace('@import("quic_v1.zig")', '@import("v1.zig")')
        text = text.replace('@import("quic_endpoint.zig")', '@import("endpoint.zig")')
        text = text.replace('@import("quic_peer_identity.zig")', '@import("peer_identity.zig")')
        text = text.replace('@import("quic_raw_stream_io.zig")', '@import("raw_stream_io.zig")')
        text = text.replace('@import("quic_posix_udp.zig")', '@import("posix_udp.zig")')
        text = text.replace('@import("quic_relay_live.zig")', '@import("relay_live.zig")')
        text = text.replace('@import("quic_dcutr_live.zig")', '@import("dcutr_live.zig")')
        text = text.replace('@import("../primitives/', '@import("../../primitives/')
        text = text.replace('@import("../core/', '@import("../../core/')
        text = text.replace('@import("../protocols/', '@import("../../protocols/')
        text = text.replace('@import("../security/', '@import("../../security/')
        for name in (
            "circuit_transport.zig",
            "dcutr_punch.zig",
            "multistream_negotiate.zig",
            "over_cap.zig",
            "stream_multistream.zig",
            "zquic_feed_addr.zig",
        ):
            text = text.replace(f'@import("{name}")', f'@import("../{name}")')
        if text != orig:
            path.write_text(text)

    # Update references from outside transport/quic.
    for path in (ROOT / "src").rglob("*.zig"):
        if "vendor" in path.parts or QUIC in path.parents:
            continue
        text = path.read_text()
        orig = text
        for old, new in {
            "transport/quic_runtime.zig": "transport/quic/runtime.zig",
            "transport/quic_endpoint.zig": "transport/quic/endpoint.zig",
            "transport/quic_v1.zig": "transport/quic/v1.zig",
            "transport/quic.zig": "transport/quic/quic.zig",
            "transport/quic_raw_stream_io.zig": "transport/quic/raw_stream_io.zig",
            "transport/quic_relay_live.zig": "transport/quic/relay_live.zig",
            "transport/quic_dcutr_live.zig": "transport/quic/dcutr_live.zig",
        }.items():
            text = text.replace(f'@import("{old}")', f'@import("{new}")')
        if text != orig:
            path.write_text(text)


def phase5_vendor() -> None:
    vendor = ROOT / "vendor"
    if (vendor / "zquic_tls").exists():
        return
    vendor.mkdir(exist_ok=True)
    git_mv(ROOT / "src" / "vendor" / "zquic_tls", vendor / "zquic_tls")
    git_mv(ROOT / "src" / "vendor" / "zquic_rsa", vendor / "zquic_rsa")
    (vendor / "README.md").write_text(
        "# Vendored dependencies\n\n"
        "See `docs/REPO_LAYOUT.md` phase 5. `zquic_tls` and `zquic_rsa` are vendored "
        "outside `src/` to avoid Zig 0.16 duplicate module path errors when both "
        "`zquic` and `zig_libp2p` compile the same TLS tree.\n",
    )
    (ROOT / "src" / "vendor").mkdir(exist_ok=True)
    write_shim(ROOT / "src" / "vendor" / "zquic_tls" / "root.zig", "vendor/zquic_tls/root.zig")
    (ROOT / "src" / "testdata" / "zquic_rsa").mkdir(parents=True, exist_ok=True)
    test_rsa = ROOT / "vendor" / "zquic_rsa" / "testdata" / "id_rsa.der"
    if test_rsa.exists():
        import shutil

        shutil.copy2(test_rsa, ROOT / "src" / "testdata" / "zquic_rsa" / "id_rsa.der")
    noise = ROOT / "src" / "security" / "noise" / "identity.zig"
    if noise.exists():
        t = noise.read_text().replace(
            '@embedFile("../../vendor/zquic_rsa/testdata/id_rsa.der")',
            '@embedFile("../../testdata/zquic_rsa/id_rsa.der")',
        )
        t = t.replace(
            '@embedFile("../../../../vendor/zquic_rsa/testdata/id_rsa.der")',
            '@embedFile("../../testdata/zquic_rsa/id_rsa.der")',
        )
        noise.write_text(t)


def main() -> None:
    phase3_quic_dir()
    phase5_vendor()
    print("done")


if __name__ == "__main__":
    main()
