#!/usr/bin/env python3
"""
irk_extractor.py - Extract BLE Identity Resolving Keys from BlueZ for Bermuda.

Usage:
  sudo python3 irk_extractor.py list
  sudo python3 irk_extractor.py monitor --discoverable
  sudo python3 irk_extractor.py monitor --le-only   # headless/dual-mode adapters
  python3 irk_extractor.py pair AA:BB:CC:DD:EE:FF
  python3 irk_extractor.py verify --irk <hex> --rpa AA:BB:CC:DD:EE:FF

BlueZ stores IRKs little-endian. Bermuda/Private BLE Device expects them
big-endian (reversed). `list` and `monitor` output the Bermuda format.

Requires Python 3.8+. `list` and `monitor` use only stdlib.
`verify` needs `cryptography` (pip install cryptography).
`pair` needs `pexpect` (pip install pexpect).
"""
from __future__ import annotations

import argparse
import configparser
import ctypes
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

BLUEZ_DIR = pathlib.Path("/var/lib/bluetooth")

# MGMT socket constants (kernel API, stable across BlueZ versions)
_MGMT_HDR    = struct.Struct("<HHH")              # opcode/event, hci_index, param_len
_MGMT_EV_IRK = 0x0018                             # MGMT_EV_NEW_IDENTITY_RESOLVING_KEY
_NEW_IRK_FMT = struct.Struct("<B6s6sB16s")        # store_hint, rpa, identity, type, irk
# Payload layout verified against BlueZ monitor/packet.c mgmt_new_identity_resolving_key_evt:
#   [0]     store_hint    uint8
#   [1:7]   RPA           6-byte little-endian bdaddr_t (always random type)
#   [7:13]  identity addr 6-byte little-endian bdaddr_t
#   [13]    identity type uint8  (0=public, 1=random)
#   [14:30] IRK           16-byte little-endian

# MGMT event codes
_MGMT_EV_USER_CONFIRM_REQUEST = 0x000F

# MGMT write opcodes
_MGMT_OP_SET_POWERED        = 0x0005  # power off required before toggling BR/EDR
_MGMT_OP_SET_DISCOVERABLE   = 0x0006
_MGMT_OP_SET_CONNECTABLE    = 0x0007
_MGMT_OP_SET_BONDABLE       = 0x0009
_MGMT_OP_SET_LE             = 0x000D
_MGMT_OP_SET_ADVERTISING    = 0x0029  # kernel-managed LE advertising (no bluetoothd)
_MGMT_OP_SET_IO_CAPABILITY  = 0x0018  # was incorrectly 0x0024 (STOP_DISCOVERY)
_MGMT_OP_SET_BREDR          = 0x002A  # disable to force LE-only mode
_MGMT_OP_SET_SECURE_CONN      = 0x002D  # uint8: 0=off 1=on; disable for iOS legacy-pairing compat
_MGMT_OP_USER_CONFIRM_REPLY   = 0x001C
_MGMT_OP_PAIR_DEVICE          = 0x0019  # 6B addr + uint8 addr_type + uint8 io_cap
_MGMT_OP_ADD_ADVERTISING      = 0x003E  # add LE advertising instance with custom AD data
_MGMT_OP_LOAD_LINK_KEYS       = 0x0012  # uint8 debug + uint16 num_keys; 0 keys = flush RAM cache
_MGMT_OP_LOAD_LONG_TERM_KEYS  = 0x0013  # uint16 num_keys; 0 keys = flush RAM cache
_MGMT_OP_LOAD_IRKS            = 0x0030  # uint16 num_keys; 0 keys = flush RAM cache
_MGMT_OP_SET_PRIVACY          = 0x002F  # uint8 mode + 16B IRK; mode=1 enables LE privacy
_MGMT_OP_UNPAIR_DEVICE        = 0x001B  # 6B addr + uint8 type + uint8 disconnect


@dataclass
class Device:
    adapter: str
    address: str
    name: str
    irk_le: str | None   # little-endian hex as stored by BlueZ


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def irk_le_to_be(le_hex: str) -> str:
    """Reverse byte order: BlueZ little-endian → big-endian (Bermuda format)."""
    return bytes.fromhex(le_hex)[::-1].hex()


def resolve_rpa(irk_bytes: bytes, rpa_mac: str) -> bool:
    """
    Return True if irk_bytes (BlueZ little-endian order) resolves rpa_mac.

    Implements BLE spec Vol 6 Part B §1.3.2.1 ah(), matching kernel smp.c:
      r' = 13 zero bytes || prand
      hash = AES(irk, r')[13:16] reversed
    """
    mac = bytes(int(x, 16) for x in rpa_mac.split(":"))
    r_prime = bytes(13) + mac[0:3]   # prand = upper 3 bytes of MAC string
    cipher = Cipher(algorithms.AES(irk_bytes), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    result = enc.update(r_prime) + enc.finalize()
    return result[15] == mac[5] and result[14] == mac[4] and result[13] == mac[3]


def _bdaddr(raw: bytes) -> str:
    """6-byte little-endian bdaddr_t → 'AA:BB:CC:DD:EE:FF'."""
    return ":".join(f"{b:02X}" for b in reversed(raw))


def get_adapter_addresses() -> list[str]:
    """
    Return all Bluetooth adapter addresses found on this machine.
    Reads from sysfs (no external tool needed); falls back to hciconfig.
    """
    addrs = []
    sys_bt = pathlib.Path("/sys/class/bluetooth")
    if sys_bt.exists():
        for addr_file in sorted(sys_bt.glob("hci*/address")):
            addr = addr_file.read_text().strip().upper()
            if addr:
                addrs.append(addr)
    if not addrs:
        try:
            out = subprocess.check_output(
                ["hciconfig"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if "BD Address" in line:
                    addrs.append(line.split()[2].upper())
        except Exception:
            pass
    return addrs


def read_devices(adapter_addr: str) -> list[Device]:
    """Read all bonded devices from BlueZ database for one adapter."""
    adapter_dir = BLUEZ_DIR / adapter_addr
    if not adapter_dir.exists():
        return []

    devices = []
    for device_dir in sorted(adapter_dir.iterdir()):
        if not device_dir.is_dir():
            continue
        info_file = device_dir / "info"
        if not info_file.exists():
            continue

        cfg = configparser.ConfigParser()
        cfg.read(str(info_file))

        name   = cfg.get("General", "Name", fallback=device_dir.name)
        irk_le = None
        if cfg.has_section("IdentityResolvingKey"):
            irk_le = cfg.get("IdentityResolvingKey", "Key", fallback=None)

        devices.append(Device(adapter_addr, device_dir.name, name, irk_le))

    return devices


def print_device(dev: Device, show_raw: bool = False) -> None:
    if dev.irk_le is None:
        print(f"  # {dev.name} ({dev.address}) — no IRK (classic BT or no LE Privacy)")
        return
    print(f'  - irk: "{irk_le_to_be(dev.irk_le)}"  # {dev.name} ({dev.address})')
    if show_raw:
        print(f"    # bluez (little-endian): {dev.irk_le}")


def require_root(cmd: str) -> None:
    if os.geteuid() != 0:
        print(f"Error: '{cmd}' requires root to read /var/lib/bluetooth/")
        print(f"Run:  sudo python3 {sys.argv[0]} {cmd}")
        sys.exit(1)


def _open_mgmt_socket() -> socket.socket:
    """
    Open a BlueZ MGMT socket (AF_BLUETOOTH / HCI_CHANNEL_CONTROL).
    Works for users in the 'bluetooth' group; sudo always works.
    Uses ctypes only for bind() — Python's socket API does not expose hci_channel.
    """
    class _SockaddrHci(ctypes.Structure):
        _fields_ = [
            ("hci_family",  ctypes.c_uint16),
            ("hci_dev",     ctypes.c_uint16),  # 0xFFFF = HCI_DEV_NONE (all adapters)
            ("hci_channel", ctypes.c_uint16),  # 3     = HCI_CHANNEL_CONTROL
        ]

    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    addr = _SockaddrHci(hci_family=socket.AF_BLUETOOTH, hci_dev=0xFFFF, hci_channel=3)
    libc = ctypes.CDLL(None, use_errno=True)
    ret  = libc.bind(sock.fileno(), ctypes.byref(addr), ctypes.sizeof(addr))
    if ret < 0:
        err = ctypes.get_errno()
        sock.close()
        raise OSError(err, os.strerror(err))
    return sock


# MGMT status codes
_MGMT_STATUS = {
    0x00: "Success",       0x01: "Unknown command", 0x02: "Not connected",
    0x03: "Failed",        0x04: "Connect failed",  0x05: "Auth failed",
    0x06: "Not paired",    0x07: "No resources",    0x08: "Timeout",
    0x09: "Already connected", 0x0A: "Busy",        0x0B: "Rejected",
    0x0C: "Not supported", 0x0D: "Invalid params",  0x0E: "Disconnected",
    0x0F: "Not powered",   0x10: "Cancelled",       0x11: "Invalid index",
    0x12: "RFKilled",      0x13: "Already paired",  0x14: "Permission denied",
}
_MGMT_EV_CMD_COMPLETE = 0x0001

# MGMT read opcodes (read-only — to probe what the socket can do)
_MGMT_OP_READ_INDEX_LIST = 0x0003   # params: none, hci_index=0xFFFF
_MGMT_OP_READ_INFO       = 0x0004   # params: none, hci_index=<adapter>

# MGMT write opcodes (adapter configuration)
_MGMT_OP_SET_DISCOVERABLE  = 0x0006  # params: uint8 val, uint16 timeout
_MGMT_OP_SET_CONNECTABLE   = 0x0007  # params: uint8 val
_MGMT_OP_SET_BONDABLE      = 0x0009  # params: uint8 val
_MGMT_OP_SET_IO_CAPABILITY = 0x0024  # params: uint8 capability


_MGMT_EV_CMD_STATUS = 0x0002

def _mgmt_cmd(sock: socket.socket, hci_index: int, opcode: int,
              params: bytes = b'', timeout: float = 2.0,
              verbose: bool = False) -> tuple[int, bytes]:
    """
    Send a MGMT command and wait for CMD_COMPLETE or CMD_STATUS for that opcode.
    Returns (status_code, response_params).  status=0 means success.
    status=-1 means timeout (no response received at all).
    CMD_STATUS with non-zero status means immediate rejection (no pending async op).
    """
    pkt = _MGMT_HDR.pack(opcode, hci_index, len(params)) + params
    if verbose:
        print(f"  [mgmt send] opcode=0x{opcode:04x} idx={hci_index} "
              f"params={params.hex() or '(none)'}  raw={pkt.hex()}")
    sock.send(pkt)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rem = deadline - time.monotonic()
        if not select.select([sock], [], [], rem)[0]:
            break
        data = sock.recv(4096)
        if len(data) < _MGMT_HDR.size:
            continue
        ev, idx, plen = _MGMT_HDR.unpack_from(data)
        ev_params = data[_MGMT_HDR.size:]
        if verbose:
            print(f"  [mgmt recv] event=0x{ev:04x} idx={idx} "
                  f"plen={plen}  {ev_params.hex()}")
        if ev in (_MGMT_EV_CMD_COMPLETE, _MGMT_EV_CMD_STATUS) and len(ev_params) >= 3:
            resp_op = struct.unpack_from('<H', ev_params)[0]
            if resp_op == opcode:
                status = ev_params[2]
                # CMD_STATUS with non-zero = immediate rejection; return it.
                # CMD_STATUS with zero = command accepted, async result pending
                # (we treat pending as success for fire-and-forget commands).
                return status, ev_params[3:]
    return -1, b''


def _get_hci_index(adapter_addr: str) -> int:
    """Return the integer index of the hciN adapter with the given address."""
    for p in pathlib.Path("/sys/class/bluetooth").glob("hci*"):
        try:
            if (p / "address").read_text().strip().upper() == adapter_addr.upper():
                return int(p.name[3:])
        except (OSError, ValueError):
            pass
    return 0



def _mgmt_read_info(sock: socket.socket, hci_index: int,
                    verbose: bool = False) -> dict:
    """
    Read adapter state via MGMT (read-only, no side effects).
    Returns a dict with keys: addr, powered, le, bredr, discoverable, bondable, connectable.
    """
    st, data = _mgmt_cmd(sock, 0xFFFF, _MGMT_OP_READ_INDEX_LIST, verbose=verbose)
    if verbose:
        if st == 0:
            n = struct.unpack_from('<H', data)[0] if len(data) >= 2 else 0
            indices = [struct.unpack_from('<H', data, 2 + i*2)[0]
                       for i in range(n) if 2 + i*2 + 2 <= len(data)]
            print(f"  [mgmt] read_index_list: OK — adapters: {indices}")
        else:
            print(f"  [mgmt] read_index_list: {_MGMT_STATUS.get(st, f'0x{st:02x}')}")

    st, data = _mgmt_cmd(sock, hci_index, _MGMT_OP_READ_INFO, verbose=verbose)
    if st != 0 or len(data) < 17:
        if verbose:
            print(f"  [mgmt] read_info: {_MGMT_STATUS.get(st, f'0x{st:02x}')}")
        return {}

    addr = ":".join(f"{b:02X}" for b in reversed(data[0:6]))
    cur  = struct.unpack_from('<I', data, 13)[0]
    info = {
        "addr":        addr,
        "powered":     bool(cur & 0x0001),
        "connectable": bool(cur & 0x0002),
        "discoverable":bool(cur & 0x0008),
        "bondable":    bool(cur & 0x0010),
        "ssp":         bool(cur & 0x0040),
        "bredr":       bool(cur & 0x0080),
        "le":          bool(cur & 0x0200),
        "secure_conn": bool(cur & 0x0800),
    }
    if verbose:
        flags = " ".join(k for k, v in info.items() if v and k != "addr")
        print(f"  [mgmt] read_info: OK — {addr}  [{flags}]")
    return info


def _adapter_name(sock: socket.socket, hci_index: int, fallback: str) -> str:
    """Friendly adapter name from MGMT READ_INFO (the hostname BlueZ advertises)."""
    st, data = _mgmt_cmd(sock, hci_index, _MGMT_OP_READ_INFO)
    if st == 0 and len(data) >= 21:
        nm = data[20:20 + 249].split(b'\x00', 1)[0].decode("utf-8", "replace").strip()
        if nm:
            return nm
    return fallback


def _mgmt_setup_pairing(sock: socket.socket, hci_index: int,
                        verbose: bool = False) -> dict[str, bool]:
    """
    Configure adapter for LE pairing via MGMT socket.
    Attempts to disable BR/EDR to force LE-only (prevents phone from choosing BR/EDR).
    Returns a dict of command → success so caller can decide on fallback.
    """
    results: dict[str, bool] = {}

    def _try(name: str, opcode: int, params: bytes) -> bool:
        st, _ = _mgmt_cmd(sock, hci_index, opcode, params, verbose=verbose)
        ok = (st == 0)
        results[name] = ok
        if verbose:
            desc = "OK" if ok else _MGMT_STATUS.get(st, f"0x{st:02x}")
            print(f"  [mgmt] {name}: {desc}")
        return ok

    # Disable BR/EDR — forces phone to connect via LE only.
    # Kernel auto-clears discoverable when BR/EDR is turned off.
    # May fail if adapter is BR/EDR-only or if kernel rejects it;
    # caller will note whether it worked.
    _try("set_bredr_off",    _MGMT_OP_SET_BREDR,        struct.pack('<B', 0))
    _try("set_connectable",  _MGMT_OP_SET_CONNECTABLE,  struct.pack('<B', 1))
    _try("set_bondable",     _MGMT_OP_SET_BONDABLE,     struct.pack('<B', 1))
    _try("set_sc_off",       _MGMT_OP_SET_SECURE_CONN,  struct.pack('<B', 0))

    _try("set_privacy", _MGMT_OP_SET_PRIVACY, struct.pack('<B', 1) + os.urandom(16))

    # timeout=0 → stay discoverable indefinitely
    _try("set_discoverable", _MGMT_OP_SET_DISCOVERABLE, struct.pack('<BH', 1, 0))

    # Flush stale bond keys from kernel RAM to force fresh SMP on next connect.
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LINK_KEYS,      struct.pack('<BH', 0, 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LONG_TERM_KEYS, struct.pack('<H',  0),    verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_IRKS,           struct.pack('<H',  0),    verbose=verbose)

    # Add LE advertising only when we have MGMT control (BR/EDR is off).
    # When set_bredr_off failed we are in the bluetoothctl-fallback path: the
    # agent ("agent NoInputNoOutput") must be registered *before* advertising
    # starts so the kernel has the right IO capability in place. Advertising
    # too early lets phones connect before the agent is ready and causes the
    # wrong pairing method (Passkey Entry instead of Just Works) to be chosen.
    # In that path, bluetoothctl's own "advertise on" handles LE advertising
    # after the agent is set up.
    if results.get("set_bredr_off"):
        _ad = bytes([0x03, 0x03, 0x0D, 0x18,   # Complete 16-bit UUIDs: Heart Rate (0x180D)
                     0x03, 0x19, 0x40, 0x03])   # Appearance: Heart Rate Sensor (0x0340)
        if not _try("add_advertising", _MGMT_OP_ADD_ADVERTISING,
                    struct.pack('<BIHHBB', 1, 0x48, 0, 0, len(_ad), 0) + _ad):
            _try("set_advertising", _MGMT_OP_SET_ADVERTISING, struct.pack('<B', 1))

    return results


def _mgmt_teardown_pairing(sock: socket.socket, hci_index: int,
                           re_enable_bredr: bool = False) -> None:
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_ADVERTISING,  struct.pack('<B', 0))
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_DISCOVERABLE, struct.pack('<BH', 0, 0))
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_BONDABLE,     struct.pack('<B', 0))
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_SECURE_CONN,  struct.pack('<B', 1))
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_PRIVACY,      struct.pack('<B', 0) + bytes(16))
    if re_enable_bredr:
        _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_BREDR, struct.pack('<B', 1))


# ---------------------------------------------------------------------------
# LE-only path (headless appliances: stop bluetoothd, drive controller via MGMT)
# ---------------------------------------------------------------------------

def _bluetoothd_active() -> bool:
    """True if the bluetooth systemd service is currently active."""
    try:
        r = subprocess.run(["systemctl", "is-active", "--quiet", "bluetooth"],
                           capture_output=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _stop_bluetoothd(verbose: bool = False) -> bool:
    """
    Stop bluetoothd so it can't keep the controller in dual (BR/EDR+LE) mode.
    Returns True if we stopped it (so the caller restarts it on exit).
    No-op (returns False) if it isn't running or systemctl is unavailable.
    """
    if not _bluetoothd_active():
        return False
    if verbose:
        print("[svc] Stopping bluetooth service so it can't re-enable BR/EDR ...")
    subprocess.run(["systemctl", "stop", "bluetooth"], capture_output=True)
    time.sleep(0.5)  # let bluetoothd release the controller
    return True


def _start_bluetoothd(verbose: bool = False) -> None:
    if verbose:
        print("[svc] Restarting bluetooth service ...")
    subprocess.run(["systemctl", "start", "bluetooth"], capture_output=True)


def _mgmt_force_le_only(sock: socket.socket, hci_index: int,
                        verbose: bool = False) -> dict[str, bool]:
    """
    Force the adapter into LE-only mode via a power cycle, then make it a
    connectable/bondable/discoverable LE peripheral with NoInputNoOutput IO.

    The kernel only accepts SET_BREDR while the controller is powered off, and
    the change only sticks if bluetoothd isn't around to re-power it in dual
    mode — so the caller must stop bluetoothd first.

    Sequence: power off → bredr off → le on → bondable + io cap → power on →
              connectable → discoverable → advertising.
    """
    results: dict[str, bool] = {}

    def _try(name: str, opcode: int, params: bytes) -> bool:
        st, _ = _mgmt_cmd(sock, hci_index, opcode, params, verbose=verbose)
        ok = (st == 0)
        results[name] = ok
        if verbose:
            desc = "OK" if ok else _MGMT_STATUS.get(st, f"0x{st:02x}")
            print(f"  [mgmt] {name}: {desc}")
        return ok

    # Powered-off phase: mode changes the kernel rejects while powered.
    _try("power_off",     _MGMT_OP_SET_POWERED,  struct.pack('<B', 0))
    # Flush stale bond keys NOW while the controller is off. Some kernels reject
    # LOAD_LONG_TERM_KEYS while powered on (returns INVALID_PARAMS); calling it
    # here clears the in-memory LTK list before the controller re-initialises,
    # preventing the phone from reconnecting with its cached LTK.
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LINK_KEYS,      struct.pack('<BH', 0, 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LONG_TERM_KEYS, struct.pack('<H',  0),    verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_IRKS,           struct.pack('<H',  0),    verbose=verbose)
    _try("set_bredr_off", _MGMT_OP_SET_BREDR,    struct.pack('<B', 0))
    _try("set_le_on",     _MGMT_OP_SET_LE,       struct.pack('<B', 1))
    _try("set_bondable",  _MGMT_OP_SET_BONDABLE,   struct.pack('<B', 1))
    # Disable Secure Connections so iOS falls back to legacy Just Works pairing,
    # which reliably distributes the IRK. SC mid-handshake failures are the most
    # common reason iOS shows "Pairing failed" with no IRK event emitted.
    _try("set_sc_off",    _MGMT_OP_SET_SECURE_CONN, struct.pack('<B', 0))
    # Enable LE privacy with a fresh random IRK. Without HCI_PRIVACY set, the
    # kernel only negotiates ENC_KEY in SMP — it never adds ID_KEY (the IRK) to
    # the key distribution bitmask, so the peer's IRK is never sent to us.
    _try("set_privacy", _MGMT_OP_SET_PRIVACY, struct.pack('<B', 1) + os.urandom(16))

    # We don't set IO capability: this controller's kernel rejects
    # SET_IO_CAPABILITY (status 0x0b) regardless of power state, and the default
    # is fine — the phone drives a USER_CONFIRM_REQUEST that we auto-accept below.

    # Powered-on phase: connectable/discoverable/advertising need the controller up.
    _try("power_on",         _MGMT_OP_SET_POWERED,      struct.pack('<B', 1))
    _try("set_connectable",  _MGMT_OP_SET_CONNECTABLE,  struct.pack('<B', 1))
    _try("set_discoverable", _MGMT_OP_SET_DISCOVERABLE, struct.pack('<BH', 1, 0))
    # LE advertising payload for iOS compatibility:
    #   Heart Rate UUID (0x180D) — iOS recognises this and shows the device in
    #   Settings → Bluetooth as something to pair with
    #   Appearance: Heart Rate Sensor (0x0340) — proper device category
    # MGMT flags: bit3=Add Flags AD type (kernel sets LE_DISC|BREDR_UNSUP),
    #             bit6=Add Local Name in scan response (device hostname)
    _ad = bytes([0x03, 0x03, 0x0D, 0x18,   # Complete 16-bit UUIDs: Heart Rate (0x180D)
                 0x03, 0x19, 0x40, 0x03])   # Appearance: Heart Rate Sensor (0x0340)
    if not _try("add_advertising", _MGMT_OP_ADD_ADVERTISING,
                struct.pack('<BIHHBB', 1, 0x48, 0, 0, len(_ad), 0) + _ad):
        _try("set_advertising", _MGMT_OP_SET_ADVERTISING, struct.pack('<B', 1))
    # Realtek (and some other) adapters silently re-enable BR/EDR when advertising
    # starts. Disable it again now that advertising is up.
    _try("set_bredr_off_retry", _MGMT_OP_SET_BREDR, struct.pack('<B', 0))

    return results


def _mgmt_teardown_le_only(sock: socket.socket, hci_index: int,
                           verbose: bool = False) -> None:
    """Undo _mgmt_force_le_only: stop advertising/discoverable, restore BR/EDR."""
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_ADVERTISING,  struct.pack('<B', 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_DISCOVERABLE, struct.pack('<BH', 0, 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_BONDABLE,     struct.pack('<B', 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_PRIVACY,      struct.pack('<B', 0) + bytes(16), verbose=verbose)
    # Re-enable BR/EDR (requires powered off), then power back on so the
    # controller is left in the dual mode bluetoothd expects on restart.
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_POWERED, struct.pack('<B', 0), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_BREDR,   struct.pack('<B', 1), verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_POWERED, struct.pack('<B', 1), verbose=verbose)


def _ctl(*args: str) -> None:
    """Run a bluetoothctl command non-interactively, ignore errors."""
    subprocess.run(["bluetoothctl", *args], capture_output=True)


def _ctl_setup_pairing() -> subprocess.Popen:
    """
    Make adapter discoverable and start a persistent bluetoothctl process as a
    NoInputNoOutput pairing agent.  The process must stay alive for the duration
    of monitoring so incoming pairing confirmations are auto-accepted.
    Returns the agent process so the caller can clean it up.
    """
    _ctl("discoverable-timeout", "0")
    _ctl("pairable", "on")
    _ctl("discoverable", "on")
    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Register agent, then explicitly start LE advertising so phones can find
    # this adapter via BLE scan (SET_DISCOVERABLE alone only enables BR/EDR inquiry
    # on some adapters — ADVERTISING flag stays unset without an explicit advertise cmd).
    proc.stdin.write(b"agent NoInputNoOutput\ndefault-agent\nadvertise on\n")
    proc.stdin.flush()
    return proc


def _ctl_teardown_pairing(agent_proc: subprocess.Popen | None = None) -> None:
    _ctl("pairable", "off")
    _ctl("discoverable", "off")
    if agent_proc is not None:
        try:
            agent_proc.stdin.write(b"quit\n")
            agent_proc.stdin.flush()
            agent_proc.wait(timeout=2)
        except Exception:
            agent_proc.kill()


def _load_dbus():
    try:
        import dbus
        import dbus.service
        import dbus.mainloop.glib
        from gi.repository import GLib
    except ImportError as e:
        print(f"Error: the experimental GATT mode needs python dbus/gi: {e}")
        print("On Debian/Raspberry Pi OS install: sudo apt install python3-dbus python3-gi")
        sys.exit(1)
    return dbus, GLib


def _dbus_get_adapter(bus, adapter_addr: str | None = None):
    dbus, _ = _load_dbus()
    obj = bus.get_object("org.bluez", "/")
    mgr = dbus.Interface(obj, "org.freedesktop.DBus.ObjectManager")
    objects = mgr.GetManagedObjects()
    want = adapter_addr.upper() if adapter_addr else None
    for path, ifaces in objects.items():
        props = ifaces.get("org.bluez.Adapter1")
        if not props:
            continue
        if want is None or str(props.get("Address", "")).upper() == want:
            return path
    raise RuntimeError(f"Bluetooth adapter not found: {adapter_addr or 'auto'}")


def _dbus_props(value):
    dbus, _ = _load_dbus()
    if isinstance(value, bool):
        return dbus.Boolean(value)
    if isinstance(value, int):
        return dbus.UInt16(value)
    if isinstance(value, list):
        return dbus.Array(value, signature="s")
    return value


def _mgmt_prepare_bluez_gatt(sock: socket.socket, hci_index: int,
                            verbose: bool = False,
                            invasive: bool = False) -> dict[str, bool]:
    results: dict[str, bool] = {}

    def _try(name: str, opcode: int, params: bytes) -> bool:
        st, _ = _mgmt_cmd(sock, hci_index, opcode, params, verbose=verbose)
        ok = (st == 0)
        results[name] = ok
        if verbose:
            print(f"  [mgmt] {name}: {_MGMT_STATUS.get(st, f'0x{st:02x}') if st >= 0 else 'timeout'}")
        return ok

    if not invasive:
        if verbose:
            print("[mgmt] GATT mode: leaving power/advertising control to bluetoothd")
        return results

    if verbose:
        print("[mgmt] Preparing adapter for BlueZ GATT capture (invasive) ...")
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LINK_KEYS, struct.pack('<BH', 0, 0),
              verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_LONG_TERM_KEYS, struct.pack('<H', 0),
              verbose=verbose)
    _mgmt_cmd(sock, hci_index, _MGMT_OP_LOAD_IRKS, struct.pack('<H', 0),
              verbose=verbose)
    _try("set_bredr_off", _MGMT_OP_SET_BREDR, struct.pack('<B', 0))
    _try("set_le_on", _MGMT_OP_SET_LE, struct.pack('<B', 1))
    _try("set_bondable", _MGMT_OP_SET_BONDABLE, struct.pack('<B', 1))
    _try("set_sc_off", _MGMT_OP_SET_SECURE_CONN, struct.pack('<B', 0))
    _try("set_privacy", _MGMT_OP_SET_PRIVACY, struct.pack('<B', 1) + os.urandom(16))
    return results


def _mgmt_irk_monitor(sock: socket.socket, stop: threading.Event,
                      hci_index: int, raw: bool = False,
                      verbose: bool = False) -> None:
    seen_irks: set[str] = set()
    while not stop.is_set():
        if not select.select([sock], [], [], 0.5)[0]:
            continue
        data = sock.recv(512)
        if len(data) < _MGMT_HDR.size:
            continue
        event_code, ev_hci_index, param_len = _MGMT_HDR.unpack_from(data)
        params = data[_MGMT_HDR.size:]

        if verbose:
            ev_name = {
                0x0001: "CMD_COMPLETE",
                0x0002: "CMD_STATUS",
                0x0006: "NEW_SETTINGS",
                0x000B: "DEVICE_CONNECTED",
                0x000C: "DEVICE_DISCONNECTED",
                0x0018: "NEW_IRK",
            }.get(event_code, f"0x{event_code:04x}")
            print(f"[mgmt] {ev_name} idx={ev_hci_index} plen={param_len}  {params.hex()}")

        if event_code == 0x0006 and len(params) >= 4:
            if struct.unpack_from('<I', params)[0] & 0x0080:
                sock.send(_MGMT_HDR.pack(_MGMT_OP_SET_BREDR, hci_index, 1) + b'\x00')
                if verbose:
                    print("[gatt] BR/EDR re-enabled by firmware/bluetoothd - disabling again")
            continue

        if event_code != _MGMT_EV_IRK or len(params) < _NEW_IRK_FMT.size:
            continue

        store_hint, rpa_le, identity_le, _, irk_raw = _NEW_IRK_FMT.unpack_from(params)
        irk_le = irk_raw.hex()
        if irk_le in seen_irks:
            continue
        seen_irks.add(irk_le)
        identity = _bdaddr(identity_le)
        rpa = _bdaddr(rpa_le)
        label = identity if identity_le != bytes(6) else rpa
        print(f"\n=== IRK captured for {label} ===")
        print("known_irks:")
        print(f'  - irk: "{irk_le_to_be(irk_le)}"  # {label}')
        if raw:
            print(f"  # bluez (little-endian): {irk_le}")
            print(f"  # RPA: {rpa}  store_hint: {bool(store_hint)}")
        print()


class _BlueZGattObject:
    PATH_BASE = "/com/phil/irk_extractor"


def _make_bluez_gatt_classes():
    dbus, _ = _load_dbus()

    class Application(dbus.service.Object):
        def __init__(self, bus):
            self.path = _BlueZGattObject.PATH_BASE
            self.services = []
            super().__init__(bus, self.path)

        def add_service(self, service):
            self.services.append(service)

        @dbus.service.method("org.freedesktop.DBus.ObjectManager",
                             out_signature="a{oa{sa{sv}}}")
        def GetManagedObjects(self):
            response = {}
            for service in self.services:
                response[service.path] = service.get_properties()
                for char in service.characteristics:
                    response[char.path] = char.get_properties()
            return response

    class Service(dbus.service.Object):
        def __init__(self, bus, index: int, uuid: str, primary: bool = True):
            self.path = f"{_BlueZGattObject.PATH_BASE}/service{index}"
            self.bus = bus
            self.uuid = uuid
            self.primary = primary
            self.characteristics = []
            super().__init__(bus, self.path)

        def add_characteristic(self, characteristic):
            self.characteristics.append(characteristic)

        def get_properties(self):
            return {
                "org.bluez.GattService1": {
                    "UUID": self.uuid,
                    "Primary": dbus.Boolean(self.primary),
                    "Characteristics": dbus.Array(
                        [dbus.ObjectPath(c.path) for c in self.characteristics],
                        signature="o",
                    ),
                }
            }

        @dbus.service.method("org.freedesktop.DBus.Properties",
                             in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            return self.get_properties().get(interface, {})

    class Characteristic(dbus.service.Object):
        def __init__(self, bus, service: Service, index: int, uuid: str,
                     flags: list[str], value: bytes):
            self.path = f"{service.path}/char{index}"
            self.bus = bus
            self.service = service
            self.uuid = uuid
            self.flags = flags
            self.value = value
            self.notifying = False
            super().__init__(bus, self.path)

        def get_properties(self):
            return {
                "org.bluez.GattCharacteristic1": {
                    "Service": dbus.ObjectPath(self.service.path),
                    "UUID": self.uuid,
                    "Flags": dbus.Array(self.flags, signature="s"),
                }
            }

        @dbus.service.method("org.freedesktop.DBus.Properties",
                             in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            return self.get_properties().get(interface, {})

        @dbus.service.method("org.bluez.GattCharacteristic1",
                             in_signature="a{sv}", out_signature="ay")
        def ReadValue(self, options):
            return dbus.Array([dbus.Byte(b) for b in self.value], signature="y")

        @dbus.service.method("org.bluez.GattCharacteristic1")
        def StartNotify(self):
            self.notifying = True

        @dbus.service.method("org.bluez.GattCharacteristic1")
        def StopNotify(self):
            self.notifying = False

    class Advertisement(dbus.service.Object):
        PATH = f"{_BlueZGattObject.PATH_BASE}/advertisement0"

        def __init__(self, bus, local_name: str, service_uuid: str, appearance: int):
            self.path = self.PATH
            self.local_name = local_name
            self.service_uuid = service_uuid
            self.appearance = appearance
            super().__init__(bus, self.path)

        def get_properties(self):
            return {
                "org.bluez.LEAdvertisement1": {
                    "Type": "peripheral",
                    "ServiceUUIDs": dbus.Array([self.service_uuid], signature="s"),
                    "LocalName": self.local_name,
                    "Appearance": dbus.UInt16(self.appearance),
                    "Includes": dbus.Array(["tx-power"], signature="s"),
                }
            }

        @dbus.service.method("org.freedesktop.DBus.Properties",
                             in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            return self.get_properties().get(interface, {})

        @dbus.service.method("org.bluez.LEAdvertisement1")
        def Release(self):
            print("[gatt] Advertisement released")

    class Agent(dbus.service.Object):
        PATH = f"{_BlueZGattObject.PATH_BASE}/agent"

        def __init__(self, bus):
            super().__init__(bus, self.PATH)

        @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
        def Release(self):
            pass

        @dbus.service.method("org.bluez.Agent1", in_signature="os", out_signature="")
        def AuthorizeService(self, device, uuid):
            return

        @dbus.service.method("org.bluez.Agent1", in_signature="ou", out_signature="")
        def RequestConfirmation(self, device, passkey):
            print(f"[gatt] Auto-confirming Just Works pairing for {device}")
            return

        @dbus.service.method("org.bluez.Agent1", in_signature="o", out_signature="")
        def RequestAuthorization(self, device):
            return

        @dbus.service.method("org.bluez.Agent1", in_signature="", out_signature="")
        def Cancel(self):
            pass

    return Application, Service, Characteristic, Advertisement, Agent


def _build_heart_rate_app(bus):
    Application, Service, Characteristic, _, _ = _make_bluez_gatt_classes()
    app = Application(bus)

    hr = Service(bus, 0, "0000180d-0000-1000-8000-00805f9b34fb")
    hr.add_characteristic(Characteristic(
        bus, hr, 0, "00002a37-0000-1000-8000-00805f9b34fb",
        ["read", "encrypt-read", "notify"], bytes([0x00, 72])))
    app.add_service(hr)

    devinfo = Service(bus, 1, "0000180a-0000-1000-8000-00805f9b34fb")
    devinfo.add_characteristic(Characteristic(
        bus, devinfo, 0, "00002a29-0000-1000-8000-00805f9b34fb",
        ["read", "encrypt-read"], b"Linux"))
    devinfo.add_characteristic(Characteristic(
        bus, devinfo, 1, "00002a24-0000-1000-8000-00805f9b34fb",
        ["read", "encrypt-read"], b"IRK Capture"))
    app.add_service(devinfo)

    batt = Service(bus, 2, "0000180f-0000-1000-8000-00805f9b34fb")
    batt.add_characteristic(Characteristic(
        bus, batt, 0, "00002a19-0000-1000-8000-00805f9b34fb",
        ["read", "notify"], bytes([95])))
    app.add_service(batt)

    protected = Service(bus, 3, "12345678-90ab-cdef-fedc-ba0987654321")
    protected.add_characteristic(Characteristic(
        bus, protected, 0, "21436587-09ba-dcfe-efcd-ab9078563412",
        ["read", "encrypt-read"], b"Protected Info"))
    app.add_service(protected)
    return app


def _build_keyboard_app(bus):
    Application, Service, Characteristic, _, _ = _make_bluez_gatt_classes()
    app = Application(bus)

    hid = Service(bus, 0, "00001812-0000-1000-8000-00805f9b34fb")
    hid.add_characteristic(Characteristic(
        bus, hid, 0, "00002a4e-0000-1000-8000-00805f9b34fb",
        ["read"], b"\x01"))
    app.add_service(hid)

    devinfo = Service(bus, 1, "0000180a-0000-1000-8000-00805f9b34fb")
    devinfo.add_characteristic(Characteristic(
        bus, devinfo, 0, "00002a29-0000-1000-8000-00805f9b34fb",
        ["read", "encrypt-read"], b"Linux"))
    devinfo.add_characteristic(Characteristic(
        bus, devinfo, 1, "00002a24-0000-1000-8000-00805f9b34fb",
        ["read", "encrypt-read"], b"IRK Capture"))
    app.add_service(devinfo)

    batt = Service(bus, 2, "0000180f-0000-1000-8000-00805f9b34fb")
    batt.add_characteristic(Characteristic(
        bus, batt, 0, "00002a19-0000-1000-8000-00805f9b34fb",
        ["read", "notify"], bytes([95])))
    app.add_service(batt)

    protected = Service(bus, 3, "12345678-90ab-cdef-fedc-ba0987654321")
    protected.add_characteristic(Characteristic(
        bus, protected, 0, "21436587-09ba-dcfe-efcd-ab9078563412",
        ["read", "encrypt-read"], b"Protected Info"))
    app.add_service(protected)
    return app


def _print_bluez_power_recovery() -> None:
    print("       BlueZ cannot power the adapter right now.")
    print("       Recovery:")
    print("         sudo systemctl restart bluetooth")
    print("         sudo bluetoothctl power on")
    print("       If that still fails after the earlier MGMT power cycle:")
    print("         sudo modprobe -r btusb btrtl")
    print("         sudo modprobe btusb")
    print("         sudo systemctl restart bluetooth")


def _build_gatt_profile(bus, profile: str):
    if profile == "keyboard":
        return _build_keyboard_app(bus), "00001812-0000-1000-8000-00805f9b34fb", 0x03C1
    return _build_heart_rate_app(bus), "0000180d-0000-1000-8000-00805f9b34fb", 0x0340


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def cmd_list(args) -> None:
    require_root("list")

    adapters = [args.adapter] if args.adapter else get_adapter_addresses()
    if not adapters:
        print("Error: no Bluetooth adapters found. Use --adapter XX:XX:XX:XX:XX:XX")
        sys.exit(1)

    all_devices = []
    for adapter in adapters:
        all_devices.extend(read_devices(adapter))

    if not all_devices:
        print(f"No bonded devices found in {BLUEZ_DIR}")
        return

    irk_devices = [d for d in all_devices if d.irk_le]
    no_irk      = [d for d in all_devices if not d.irk_le]

    if irk_devices:
        print("# Paste into Home Assistant configuration.yaml:")
        print()
        print("known_irks:")
        for dev in irk_devices:
            print_device(dev, show_raw=args.raw)
    else:
        print("No IRKs found. Pair a BLE device that uses LE Privacy (e.g. a phone).")

    if no_irk:
        print()
        print("# Devices without IRK (classic BT or no LE Privacy):")
        for dev in no_irk:
            print(f"#   {dev.name} ({dev.address})")


# ---------------------------------------------------------------------------
# Subcommand: verify
# ---------------------------------------------------------------------------

def cmd_verify(args) -> None:
    if not CRYPTO_OK:
        print("Error: install 'cryptography':  pip install cryptography")
        sys.exit(1)

    irk_hex = args.irk.strip().lower().replace(" ", "").replace(":", "")
    rpa     = args.rpa.strip().upper()

    if len(irk_hex) != 32:
        print(f"Error: IRK must be 32 hex chars (16 bytes), got {len(irk_hex)}")
        sys.exit(1)

    parts = rpa.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        print(f"Error: RPA must be in AA:BB:CC:DD:EE:FF format, got: {rpa}")
        sys.exit(1)

    first_byte = int(parts[0], 16)
    if (first_byte & 0xC0) != 0x40:
        print(f"Warning: {rpa} may not be an RPA "
              f"(bits 47-46 should be 01, got {first_byte >> 6:02b})")
        print("         Only addresses in range 40:xx–7F:xx are RPAs.")
        print()

    irk_bytes    = bytes.fromhex(irk_hex)
    reversed_hex = irk_le_to_be(irk_hex)

    if resolve_rpa(irk_bytes, rpa):
        print(f"MATCH — paste this into Bermuda:")
        print(f'  irk: "{irk_hex}"')
        print(f"  (reversed would be: {reversed_hex})")
        return

    if resolve_rpa(irk_bytes[::-1], rpa):
        print(f"MATCH — paste this into Bermuda:")
        print(f'  irk: "{reversed_hex}"')
        print(f"  (your input {irk_hex} is the reversed form — don't use that)")
        return

    print(f"NO MATCH — neither byte order of this IRK resolves {rpa}")
    print("Possible causes: wrong IRK, address is not an RPA, or wrong device.")


# ---------------------------------------------------------------------------
# Subcommand: pair
# ---------------------------------------------------------------------------

def cmd_pair(args) -> None:
    try:
        import pexpect
    except ImportError:
        print("Error: install 'pexpect':  pip install pexpect")
        print("Or pair manually via:  bluetoothctl pair <address>")
        print("Then run:  sudo python3 irk_extractor.py list")
        sys.exit(1)

    mac = args.address.upper().strip()
    print(f"Pairing with {mac} via bluetoothctl ...")
    print("Make sure the device is in pairing mode.\n")

    # Prompt pattern: bluetoothctl uses ANSI codes — '\x1b[0m#' ends every prompt.
    PROMPT = r"\[0m#"

    child = pexpect.spawn("bluetoothctl --agent NoInputNoOutput", timeout=10, encoding="utf-8")
    child.expect(PROMPT)
    child.sendline("power on")
    child.expect(PROMPT)
    child.sendline("pairable on")
    child.expect(PROMPT)

    print("Scanning for device (5s) ...")
    child.sendline("scan on")
    child.expect(PROMPT)
    time.sleep(5)
    child.sendline("scan off")
    child.expect(PROMPT)

    child.sendline(f"pair {mac}")
    idx = child.expect(
        ["Pairing successful", "Failed to pair", r"org\.bluez\.Error", pexpect.TIMEOUT],
        timeout=args.timeout,
    )
    if idx != 0:
        print(f"Pairing failed or timed out.\n{child.before}")
        child.sendline("quit")
        sys.exit(1)

    print("Pairing successful. Trusting device ...")
    child.sendline(f"trust {mac}")
    child.expect(PROMPT, timeout=5)
    child.sendline("quit")
    child.close()

    adapters = [args.adapter] if args.adapter else get_adapter_addresses()
    if not adapters:
        print("Error: no adapter detected. Use --adapter XX:XX:XX:XX:XX:XX")
        sys.exit(1)

    time.sleep(1)  # give bluetoothd a moment to write the info file

    if os.geteuid() != 0:
        print("Cannot read /var/lib/bluetooth/ without root.")
        print(f"Run:  sudo python3 {sys.argv[0]} list")
        return

    for adapter in adapters:
        for dev in read_devices(adapter):
            if dev.address.upper() == mac:
                if not dev.irk_le:
                    print(f"{mac} ({dev.name}): bonded but no IRK — "
                          "device may not use LE Privacy.")
                else:
                    print("\n# known_irks entry for Home Assistant:")
                    print("known_irks:")
                    print_device(dev, show_raw=True)
                return

    print(f"Device {mac} not found in BlueZ database after pairing.")


def _print_unpair_outcome(status: int, already_warned: bool) -> bool:
    """Report the real result of the UNPAIR_DEVICE we send when PAIR_DEVICE
    completes instantly. Returns True once the full explanation has been
    printed, so callers can suppress repeats on reconnect-loop iterations."""
    if status == 0x00:
        print("      Bond removed from the Linux side. On the phone: tap this device"
              " in Bluetooth settings to pair fresh.")
        return already_warned
    if status != 0x06:  # not NOT_PAIRED
        print(f"      UNPAIR_DEVICE: {_MGMT_STATUS.get(status, f'0x{status:02x}')}")
        return already_warned
    # NOT_PAIRED: the host genuinely holds no bond record for this peer.
    if already_warned:
        return True
    print("      UNPAIR returned 'Not paired' - Linux holds no bond for this peer, so")
    print("      this is not a stale host-side bond. The peer connected and the link")
    print("      reached its security level without distributing an identity key, so no")
    print("      IRK was sent. That is typical of a transient/enumeration connection,")
    print("      not a real bonding attempt. Future reconnects from this address will")
    print("      be left connected; explicitly select the advertised Linux device in")
    print("      Bluetooth settings to make the phone initiate bonding.")
    return True


# ---------------------------------------------------------------------------
# Subcommand: monitor
# ---------------------------------------------------------------------------

def cmd_monitor(args) -> None:
    try:
        sock = _open_mgmt_socket()
    except OSError as e:
        print(f"Error opening MGMT socket: {e}")
        print("Try running with sudo, or add your user to the 'bluetooth' group.")
        sys.exit(1)

    if args.remove:
        mac = args.remove.upper().strip()
        print(f"Removing {mac} from BlueZ so re-pairing will exchange a fresh IRK ...")
        result = subprocess.run(
            ["bluetoothctl", "remove", mac], capture_output=True, text=True
        )
        if result.returncode == 0 or "Device has been removed" in result.stdout:
            print(f"Removed {mac}.\n")
        else:
            print(f"Warning: could not remove {mac}: "
                  f"{(result.stdout or result.stderr).strip()}")

    # Show existing IRKs from database (only if root can read the files).
    if os.geteuid() == 0:
        adapters = [args.adapter] if args.adapter else get_adapter_addresses()
        existing = [d for a in adapters for d in read_devices(a) if d.irk_le]
        if existing:
            print("# Already-paired devices with IRKs:")
            print("known_irks:")
            for dev in existing:
                print_device(dev, show_raw=args.raw)
            print()

    using_mgmt_setup = False
    bredr_was_disabled = False
    ctl_agent_proc = None
    stopped_bluetoothd = False
    le_only_active = False

    if args.le_only and os.geteuid() != 0:
        print("Error: --le-only needs root (it stops bluetoothd and reconfigures the "
              "controller via MGMT).")
        print(f"Run:  sudo python3 {sys.argv[0]} monitor --le-only")
        sys.exit(1)

    if args.le_only:
        adapters = [args.adapter] if args.adapter else get_adapter_addresses()
        hci_index = _get_hci_index(adapters[0]) if adapters else 0

        # bluetoothd would keep re-powering the controller in dual (BR/EDR+LE)
        # mode and re-enabling BR/EDR, so a phone bonds over Classic and no IRK
        # is exchanged. Stop it, drive the controller LE-only ourselves, restore
        # it on exit. Fully reversible — no config files touched.
        stopped_bluetoothd = _stop_bluetoothd(verbose=args.verbose)
        if not stopped_bluetoothd and _bluetoothd_active():
            print("Warning: could not stop bluetoothd via systemctl — it may re-enable "
                  "BR/EDR and prevent the LE bond.")

        if args.verbose:
            print("[mgmt] Reading adapter state ...")
            _mgmt_read_info(sock, hci_index, verbose=True)
            print("[mgmt] Forcing controller into LE-only mode ...")

        setup = _mgmt_force_le_only(sock, hci_index, verbose=args.verbose)
        le_only_active = True
        using_mgmt_setup = True  # we answer USER_CONFIRM_REQUEST ourselves

        if not setup.get("set_bredr_off"):
            print("Warning: SET_BREDR=off did not take — the phone may still bond over "
                  "BR/EDR. Verify bluetoothd is stopped and you are root.")

        print("Linux is now an LE-only discoverable peripheral.")
        print("On your phone: Settings → Bluetooth → pair with this machine.")
    elif args.discoverable:
        adapters = [args.adapter] if args.adapter else get_adapter_addresses()
        hci_index = _get_hci_index(adapters[0]) if adapters else 0

        if args.verbose:
            print("[mgmt] Reading adapter state ...")
            _mgmt_read_info(sock, hci_index, verbose=True)
            print("[mgmt] Configuring adapter for LE pairing ...")

        setup = _mgmt_setup_pairing(sock, hci_index, verbose=args.verbose)

        bredr_was_disabled = setup.get("set_bredr_off", False)
        if bredr_was_disabled:
            # Full MGMT control: BR/EDR is off, LE-only advertising
            using_mgmt_setup = True
            if args.verbose:
                print("[mgmt] BR/EDR disabled — adapter is LE-only.")
            if not setup.get("set_privacy"):
                print("Warning: LE Privacy could not be enabled — the peer's IRK may not")
                print("         be exchanged. If this happens, retry with:  monitor --le-only")
        else:
            # BR/EDR could not be disabled via MGMT; use bluetoothctl which
            # also starts proper LE advertising via bluetoothd's D-Bus path.
            if args.verbose:
                print("[mgmt] SET_BREDR=off rejected — using bluetoothctl for "
                      "full discoverable setup (LE advertising + BR/EDR inquiry).")
                print("      (For headless/Realtek adapters try: monitor --le-only)")
            ctl_agent_proc = _ctl_setup_pairing()

        print("Linux is now discoverable and pairable.")
        print("On your phone: Settings → Bluetooth → pair with this machine.")
    else:
        hci_index = 0
        print("Waiting for new IRK events.")

    print()
    print("NOTE: IRK events only fire during FRESH pairing.")
    print("      If the device is already bonded, use --remove <address> first.")
    print("Press Ctrl+C to stop.\n")

    seen_irks: set[str] = set()
    pair_async_started = False  # True once CMD_STATUS 0 for PAIR_DEVICE is seen
    unpair_explanation_printed = False
    unpair_not_paired_peers: set[tuple[bytes, int]] = set()
    pending_unpair_peer: tuple[bytes, int] | None = None

    try:
        while True:
            if not select.select([sock], [], [], 1.0)[0]:
                continue

            data = sock.recv(512)
            if len(data) < _MGMT_HDR.size:
                continue

            event_code, ev_hci_index, param_len = _MGMT_HDR.unpack_from(data)
            params = data[_MGMT_HDR.size:]

            if args.verbose:
                ev_name = {
                    0x0001: "CMD_COMPLETE",
                    0x0002: "CMD_STATUS",
                    0x0006: "NEW_SETTINGS",
                    0x000B: "DEVICE_CONNECTED",
                    0x000C: "DEVICE_DISCONNECTED",
                    0x000D: "CONNECT_FAILED",
                    0x000E: "PIN_CODE_REQUEST",
                    0x000F: "USER_CONFIRM_REQUEST",
                    0x0010: "USER_PASSKEY_REQUEST",
                    0x0011: "AUTH_FAILED",
                    0x0012: "DEVICE_FOUND",
                    0x0013: "DISCOVERING",
                    0x0018: "NEW_IRK",
                    0x001D: "PAIR_DEVICE_COMPLETE",
                }.get(event_code, f"0x{event_code:04x}")
                _ADDR_TYPE = {0: "BR/EDR", 1: "LE-public", 2: "LE-random"}
                if event_code == 0x0012:  # DEVICE_FOUND — suppress hex, show summary
                    addr = ":".join(f"{b:02X}" for b in reversed(params[:6]))
                    atype = _ADDR_TYPE.get(params[6], f"0x{params[6]:02x}") if len(params) > 6 else "?"
                    rssi  = struct.unpack_from('<b', params, 7)[0] if len(params) > 7 else "?"
                    print(f"[mgmt] DEVICE_FOUND {addr} ({atype}) rssi={rssi}")
                elif event_code in (0x000B, 0x000C):  # DEVICE_CONNECTED / DISCONNECTED
                    addr  = ":".join(f"{b:02X}" for b in reversed(params[:6]))
                    atype = _ADDR_TYPE.get(params[6], f"0x{params[6]:02x}") if len(params) > 6 else "?"
                    reason = f" reason=0x{params[7]:02x}" if event_code == 0x000C and len(params) > 7 else ""
                    print(f"[mgmt] {ev_name} {addr} ({atype}){reason}")
                else:
                    print(f"[mgmt] {ev_name} idx={ev_hci_index} "
                          f"plen={param_len}  {params.hex()}")

            # NEW_SETTINGS watchdog: Realtek firmware re-enables BR/EDR asynchronously
            # after advertising starts. Detect it and fire set_bredr_off again.
            if event_code == 0x0006 and (le_only_active or bredr_was_disabled) and len(params) >= 4:
                if struct.unpack_from('<I', params)[0] & 0x0080:
                    sock.send(_MGMT_HDR.pack(_MGMT_OP_SET_BREDR, hci_index, 1) + b'\x00')
                    if args.verbose:
                        print("[le-only] BR/EDR re-enabled by firmware — disabling again")
                continue

            # After the phone connects, actively initiate SMP from our side.
            # iOS will not start key exchange on its own unless it hits an encrypted
            # GATT characteristic, so we trigger it explicitly here.
            if event_code == 0x000B and using_mgmt_setup and len(params) >= 7:
                peer_key = (params[:6], params[6])
                if peer_key in unpair_not_paired_peers:
                    if args.verbose:
                        print(f"  - skipping PAIR_DEVICE for {_bdaddr(params[:6])}"
                              " after prior NOT_PAIRED")
                    continue
                pair_params = params[:7] + struct.pack('<B', 3)  # addr+type, NoInputNoOutput
                sock.send(_MGMT_HDR.pack(_MGMT_OP_PAIR_DEVICE, ev_hci_index,
                                         len(pair_params)) + pair_params)
                if args.verbose:
                    print(f"  → PAIR_DEVICE → {_bdaddr(params[:6])}")
                continue

            # Handle USER_CONFIRM_REQUEST only when MGMT setup succeeded
            # (if bluetoothctl setup was used, bluetoothd's own agent handles this)
            if event_code == _MGMT_EV_USER_CONFIRM_REQUEST and using_mgmt_setup:
                st, _ = _mgmt_cmd(sock, ev_hci_index, _MGMT_OP_USER_CONFIRM_REPLY,
                                  params[:7], verbose=args.verbose)
                if args.verbose:
                    desc = _MGMT_STATUS.get(st, f"0x{st:02x}") if st >= 0 else "timeout"
                    print(f"  → USER_CONFIRM_REPLY: {desc}")
                continue

            # CMD_STATUS 0 for PAIR_DEVICE = kernel accepted async pairing.
            # CMD_COMPLETE 0 without a prior CMD_STATUS means PAIR_DEVICE
            # finished synchronously. Probe with UNPAIR_DEVICE to distinguish
            # a real host-side stale bond from "not paired" transient connects.
            if event_code == 0x0002 and len(params) >= 3:
                if struct.unpack_from('<H', params)[0] == _MGMT_OP_PAIR_DEVICE and params[2] == 0:
                    pair_async_started = True
                continue

            if event_code == 0x0001 and len(params) >= 3:
                cmd_opcode = struct.unpack_from('<H', params)[0]
                cmd_status = params[2]
                if cmd_opcode == _MGMT_OP_PAIR_DEVICE and cmd_status == 0:
                    if pair_async_started:
                        pair_async_started = False  # fresh pairing completed OK
                    else:
                        addr_bytes = params[3:9] if len(params) >= 10 else bytes(6)
                        addr_type  = params[9]   if len(params) >= 10 else 2
                        addr_str   = _bdaddr(addr_bytes)
                        peer_key = (addr_bytes, addr_type)
                        if peer_key in unpair_not_paired_peers:
                            continue
                        print(f"Note: PAIR_DEVICE for {addr_str} completed immediately;"
                              " checking Linux bond state ...")
                        # UNPAIR_DEVICE (disconnect=1): removes a real host-side
                        # bond if one exists, and reports NOT_PAIRED otherwise.
                        unpair_p = addr_bytes + bytes([addr_type, 1])
                        pending_unpair_peer = peer_key
                        sock.send(_MGMT_HDR.pack(_MGMT_OP_UNPAIR_DEVICE,
                                                 ev_hci_index, len(unpair_p)) + unpair_p)
                elif cmd_opcode == _MGMT_OP_UNPAIR_DEVICE:
                    if cmd_status == 0x06:
                        if len(params) >= 10:
                            unpair_not_paired_peers.add((params[3:9], params[9]))
                        elif pending_unpair_peer is not None:
                            unpair_not_paired_peers.add(pending_unpair_peer)
                    pending_unpair_peer = None
                    unpair_explanation_printed = _print_unpair_outcome(
                        cmd_status, unpair_explanation_printed)
                continue

            if event_code != _MGMT_EV_IRK:
                continue

            if len(params) < _NEW_IRK_FMT.size:
                print(f"Warning: IRK event too short ({len(params)} bytes, expected 30)")
                continue

            store_hint, rpa_le, identity_le, identity_type, irk_raw = \
                _NEW_IRK_FMT.unpack_from(params)

            irk_le = irk_raw.hex()
            if irk_le in seen_irks:
                continue
            seen_irks.add(irk_le)

            identity = _bdaddr(identity_le)
            rpa      = _bdaddr(rpa_le)
            label    = identity if identity_le != bytes(6) else rpa

            print(f"\n=== IRK captured for {label} ===")
            print("# Paste into Home Assistant configuration.yaml:")
            print("known_irks:")
            print(f'  - irk: "{irk_le_to_be(irk_le)}"  # {label}')
            if args.raw:
                print(f"  # bluez (little-endian): {irk_le}")
                print(f"  # RPA: {rpa}  store_hint: {bool(store_hint)}")
            print()

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if le_only_active:
            _mgmt_teardown_le_only(sock, hci_index, verbose=args.verbose)
            if stopped_bluetoothd:
                _start_bluetoothd(verbose=args.verbose)
            print("LE-only mode reverted; BR/EDR restored.")
        elif args.discoverable:
            if using_mgmt_setup:
                _mgmt_teardown_pairing(sock, hci_index,
                                       re_enable_bredr=bredr_was_disabled)
            else:
                _ctl_teardown_pairing(ctl_agent_proc)
            print("Discoverable mode turned off.")
        sock.close()


# ---------------------------------------------------------------------------
# Default capture path: BlueZ D-Bus GATT peripheral
# ---------------------------------------------------------------------------

def cmd_gatt(args) -> None:
    require_root("gatt")
    dbus, GLib = _load_dbus()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    if not _bluetoothd_active():
        print("Starting bluetoothd for BlueZ D-Bus GATT support ...")
        _start_bluetoothd(verbose=args.verbose)
        time.sleep(1)

    adapters = [args.adapter] if args.adapter else get_adapter_addresses()
    if not adapters:
        print("Error: no Bluetooth adapter detected.")
        sys.exit(1)
    adapter = adapters[0]
    hci_index = _get_hci_index(adapter)
    gatt_mode = "mgmt-prep" if args.le_only else "bluez"

    profile = args.profile
    if profile == "auto":
        profile = "keyboard" if gatt_mode == "mgmt-prep" else "heart"
        if args.verbose:
            print(f"[gatt] profile: {profile} (auto-selected)")

    try:
        sock = _open_mgmt_socket()
    except OSError as e:
        print(f"Error opening MGMT socket: {e}")
        sys.exit(1)

    bus = dbus.SystemBus()
    adapter_path = _dbus_get_adapter(bus, adapter)
    adapter_obj = bus.get_object("org.bluez", adapter_path)
    adapter_props = dbus.Interface(adapter_obj, "org.freedesktop.DBus.Properties")
    gatt_mgr = dbus.Interface(adapter_obj, "org.bluez.GattManager1")
    adv_mgr = dbus.Interface(adapter_obj, "org.bluez.LEAdvertisingManager1")
    agent_mgr = dbus.Interface(bus.get_object("org.bluez", "/org/bluez"),
                               "org.bluez.AgentManager1")

    _, _, _, Advertisement, Agent = _make_bluez_gatt_classes()
    app, service_uuid, appearance = _build_gatt_profile(bus, profile)
    adv_name = "Logitech K380" if profile == "keyboard" else args.name
    adv = Advertisement(bus, adv_name, service_uuid, appearance)
    agent = Agent(bus)

    loop = GLib.MainLoop()
    stop = threading.Event()
    monitor = threading.Thread(
        target=_mgmt_irk_monitor,
        args=(sock, stop, hci_index, args.raw, args.verbose),
        daemon=True,
    )

    registered_app = False
    registered_adv = False
    registered_agent = False

    def _ok(label: str):
        def inner():
            nonlocal registered_app, registered_adv, registered_agent
            if label == "GATT":
                registered_app = True
            elif label == "advertisement":
                registered_adv = True
            print(f"[gatt] {label} registered")
        return inner

    def _err(label: str):
        def inner(error):
            print(f"[gatt] {label} registration failed: {error}")
            loop.quit()
        return inner

    try:
        if gatt_mode == "mgmt-prep":
            try:
                adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(False))
                time.sleep(0.5)
            except Exception as e:
                if args.verbose:
                    print(f"[gatt] could not power adapter off through BlueZ: {e}")
            _mgmt_prepare_bluez_gatt(sock, hci_index, verbose=args.verbose,
                                     invasive=True)
        else:
            _mgmt_prepare_bluez_gatt(sock, hci_index, verbose=args.verbose,
                                     invasive=False)

        try:
            powered = bool(adapter_props.Get("org.bluez.Adapter1", "Powered"))
        except Exception as e:
            print(f"[gatt] could not read adapter power state: {e}")
            _print_bluez_power_recovery()
            return

        if not powered:
            try:
                adapter_props.Set("org.bluez.Adapter1", "Powered", dbus.Boolean(True))
            except Exception as e:
                print(f"[gatt] could not power adapter through BlueZ: {e}")
                _print_bluez_power_recovery()
                return

        for prop, value in (
            ("Pairable", dbus.Boolean(True)),
            ("Discoverable", dbus.Boolean(True)),
            ("Alias", args.name),
        ):
            try:
                adapter_props.Set("org.bluez.Adapter1", prop, value)
            except Exception as e:
                if args.verbose:
                    print(f"[gatt] could not set Adapter1.{prop}: {e}")

        agent_mgr.RegisterAgent(agent.PATH, "NoInputNoOutput")
        registered_agent = True
        print("[gatt] agent registered")
        agent_mgr.RequestDefaultAgent(agent.PATH)

        gatt_mgr.RegisterApplication(app.path, {},
                                     reply_handler=_ok("GATT"),
                                     error_handler=_err("GATT"))
        adv_mgr.RegisterAdvertisement(adv.path, {},
                                      reply_handler=_ok("advertisement"),
                                      error_handler=_err("advertisement"))

        monitor.start()
        print(f'On the phone: Settings -> Bluetooth -> tap "{adv_name}" to pair.')
        print("Press Ctrl+C to stop.\n")
        loop.run()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        stop.set()
        try:
            if registered_adv:
                adv_mgr.UnregisterAdvertisement(adv.path)
        except Exception:
            pass
        try:
            if registered_app:
                gatt_mgr.UnregisterApplication(app.path)
        except Exception:
            pass
        try:
            if registered_agent:
                agent_mgr.UnregisterAgent(agent.PATH)
        except Exception:
            pass
        try:
            adapter_props.Set("org.bluez.Adapter1", "Discoverable", dbus.Boolean(False))
        except Exception:
            pass
        if gatt_mode == "mgmt-prep":
            _mgmt_cmd(sock, hci_index, _MGMT_OP_SET_ADVERTISING, struct.pack('<B', 0),
                      verbose=args.verbose)
        sock.close()
        print("GATT capture stopped.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract BLE IRKs from BlueZ for Bermuda / Private BLE Device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Just run it and pair your phone:

  sudo python3 irk_extractor.py

Samsung Galaxy phones need the keyboard profile:

  sudo python3 irk_extractor.py --profile keyboard

Realtek/dual-mode USB adapters need LE-only mode:

  sudo python3 irk_extractor.py --le-only

Other commands:
  sudo python3 irk_extractor.py list      # IRKs of already-paired devices
  python3 irk_extractor.py verify --irk HEX --rpa XX:XX:XX:XX:XX:XX
""",
    )
    parser.add_argument(
        "--adapter", metavar="XX:XX:XX:XX:XX:XX",
        help="Bluetooth adapter address (default: auto-detect)",
    )
    parser.add_argument(
        "--profile", choices=("auto", "heart", "keyboard"), default="auto",
        help="heart = Heart Rate sensor (iOS, Apple Watch, most Android); "
             "keyboard = Logitech K380 HID keyboard (Samsung Galaxy). "
             "auto = heart, or keyboard when --le-only is set",
    )
    parser.add_argument(
        "--le-only", dest="le_only", action="store_true",
        help="Force LE-only mode for Realtek/dual-mode adapters (stops bluetoothd temporarily, "
             "restores on exit)",
    )
    parser.add_argument(
        "--name", default="IRK Capture",
        help='BLE device name to advertise (default: "IRK Capture"; overridden to '
             '"Logitech K380" for keyboard profile)',
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Also print BlueZ little-endian IRK and RPA address",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print MGMT setup and raw events",
    )

    parser.set_defaults(func=cmd_gatt)
    sub = parser.add_subparsers(dest="command", required=False)

    p_list = sub.add_parser("list", help="List IRKs for all bonded BLE devices (requires sudo)")
    p_list.add_argument("--raw", action="store_true", help="Also show raw BlueZ little-endian IRK")
    p_list.set_defaults(func=cmd_list)

    p_verify = sub.add_parser("verify", help="Verify an IRK resolves a given RPA address")
    p_verify.add_argument("--irk", required=True, metavar="HEX", help="IRK as 32 hex chars")
    p_verify.add_argument("--rpa", required=True, metavar="AA:BB:CC:DD:EE:FF",
                          help="Observed RPA (get from: sudo bluetoothctl scan on)")
    p_verify.set_defaults(func=cmd_verify)

    p_pair = sub.add_parser("pair", help="Pair a BLE device and extract its IRK (needs pexpect)")
    p_pair.add_argument("address", metavar="AA:BB:CC:DD:EE:FF")
    p_pair.add_argument("--timeout", type=int, default=60,
                        help="Pairing timeout in seconds (default: 60)")
    p_pair.set_defaults(func=cmd_pair)

    p_mon = sub.add_parser("monitor", help="Listen for IRK events via MGMT socket (expert/debug)")
    p_mon.add_argument("--discoverable", action="store_true",
                       help="Make this machine discoverable so the phone can initiate pairing")
    p_mon.add_argument("--le-only", dest="le_only", action="store_true",
                       help="Force LE-only: stop bluetoothd, power-cycle controller, restore on exit")
    p_mon.add_argument("--remove", metavar="AA:BB:CC:DD:EE:FF",
                       help="Unpair this device first so re-pairing triggers fresh key exchange")
    p_mon.add_argument("--raw", action="store_true",
                       help="Also print BlueZ little-endian IRK and RPA address")
    p_mon.add_argument("--verbose", action="store_true",
                       help="Print every raw MGMT event")
    p_mon.set_defaults(func=cmd_monitor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
