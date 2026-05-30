# bluez-irk-extractor

Extract BLE Identity Resolving Keys (IRKs) from the Linux BlueZ Bluetooth stack
for use with [Bermuda](https://github.com/agittins/bermuda) / Private BLE Device
in Home Assistant.

**Just pair your phone with a Linux box — no ESP32 firmware to flash, no
Windows-only tools, no phone HCI snoop logs, no third-party apps.**

---

## Why this exists

To track a BLE device that uses LE Privacy (most modern phones, watches, and
tags), Home Assistant needs the device's **IRK** — a 128-bit secret the device
shares only with hosts it bonds with.

The methods people are usually pointed to all involve extra hardware or fiddly
host setups: flashing custom firmware onto an **ESP32**, capturing and decoding
**Android/iOS HCI snoop logs**, or running **Windows-only** Bluetooth tooling.

This project takes a different angle: any ordinary Linux machine with a Bluetooth
adapter already runs the **BlueZ** stack, and when you bond a phone to it, the
kernel performs the standard BLE key exchange and hands over the IRK. This tool
just listens for that exchange — the only hardware you need is a Linux machine
the phone can pair with.

## Background

BLE devices with LE Privacy use Resolvable Private Addresses (RPAs) — MAC addresses
that rotate every few minutes. To track a device despite rotating addresses, you
need its **IRK** (Identity Resolving Key), a 128-bit secret exchanged during
Bluetooth bonding.

### Byte order note

BlueZ stores IRKs **little-endian** (LSB first). Bermuda / Private BLE Device
expects them **big-endian** (MSB first, i.e. reversed). This tool handles the
conversion automatically — output is always in Bermuda format unless `--raw` is
passed.

---

## Requirements

- Linux with BlueZ ≥ 5.x
- Python 3.8+
- `python3-dbus` and `python3-gi` — required for IRK capture
  (`sudo apt install python3-dbus python3-gi` on Debian/Ubuntu/Raspberry Pi OS)
- `cryptography` package (`pip install cryptography`) — needed for `verify` only
- `pexpect` package (`pip install pexpect`) — needed for `pair` only
- `sudo` access required

### Compatibility

Verified on:
- A Linux laptop with its built-in Intel Bluetooth adapter
- A Linux VM with a Realtek USB Bluetooth adapter passed through

---

## Quickstart

### Just run it

```bash
sudo python3 irk_extractor.py
```

Auto-detects the adapter, pairs your phone, prints the IRK.

```
[gatt] mode: bluez (Intel adapter detected; ...)
[gatt] GATT registered
Waiting for your phone to pair ...  (Ctrl+C to cancel)

=== IRK captured for XX:XX:XX:XX:XX:XX ===
known_irks:
  - irk: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # XX:XX:XX:XX:XX:XX
```

On your phone, open Settings → Bluetooth and tap the machine's hostname to pair.

> **Tip:** If your phone shows the machine as *already paired*, tap **Forget This
> Device** on the phone first — an IRK is only exchanged during a fresh pairing.

### Samsung Galaxy phones

Samsung's Bluetooth stack filters generic BLE devices. Use the keyboard profile,
which advertises as a Logitech K380 keyboard:

```bash
sudo python3 irk_extractor.py --profile keyboard
```

### If no IRK appears (dual-mode adapters)

On some USB Bluetooth dongles, the phone bonds over Classic Bluetooth instead of BLE
and no IRK is exchanged. `--le-only` fixes this by temporarily stopping the Bluetooth
service, switching the adapter to BLE-only, capturing the IRK, then restoring everything:

```bash
sudo python3 irk_extractor.py --le-only
```

---

### List IRKs for already-paired devices

```bash
sudo python3 irk_extractor.py list
sudo python3 irk_extractor.py list --raw   # also show BlueZ little-endian format
```

---

### Linux pairs with the device (you need the phone's MAC)

```bash
python3 irk_extractor.py pair AA:BB:CC:DD:EE:FF
```

To find the phone's address first:

```bash
bluetoothctl scan on   # then make phone discoverable, wait a few seconds
bluetoothctl devices
bluetoothctl scan off
```

---

### Verify an IRK against an observed RPA

```bash
python3 irk_extractor.py verify \
  --irk xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --rpa XX:XX:XX:XX:XX:XX
```

Get an RPA from:

```bash
sudo bluetoothctl scan on
# Look for an address starting with 4x–7x (those are RPAs)
```

---

## Pasting into Home Assistant

Add the output to your `configuration.yaml`:

```yaml
known_irks:
  - irk: "99887766554433221100ffeeddccbbaa"  # My Phone
```

For the **Private BLE Device** integration, paste the 32-character hex string
into the IRK field when adding the integration.

---

## How it works

1. The tool registers a GATT application (Heart Rate sensor or Logitech K380
   keyboard) with `bluetoothd` via D-Bus. The encrypted-read characteristic
   triggers the phone to bond and distribute its identity key.

2. A background thread monitors the kernel Bluetooth management socket for the
   `NEW_IDENTITY_RESOLVING_KEY` event — the kernel delivers the IRK the moment
   it is received from the phone.

3. `list` reads the IRK BlueZ already stored in `/var/lib/bluetooth/` for
   previously-bonded devices.

4. `verify` implements the BLE `ah()` function using AES-128-ECB to confirm an
   IRK resolves a given RPA.

---

## Limitations

- The device must be paired with **this Linux machine**. IRKs for devices paired
  only with a phone cannot be extracted without phone HCI logs or an ESP32 sniffer.
- Classic Bluetooth devices (headphones, keyboards, etc.) do not use LE Privacy
  and have no IRK.
- Some devices reject pairing with a second host. In that case, use the ESP32
  methods documented in the
  [Bermuda wiki](https://github.com/agittins/bermuda/wiki/How-to-get-the-IRK-(Identity-Resolving-Keys)-for-iOS,-Android-etc).

---

## Alternatives

The [Bermuda wiki "How to get the IRK"](https://github.com/agittins/bermuda/wiki/How-to-get-the-IRK-(Identity-Resolving-Keys)-for-iOS,-Android-etc)
documents the other approaches:

- **ESP32 sniffer / firmware** — capture the key during pairing on an ESP32.
- **Android HCI snoop log** — enable BT HCI logging, pair, extract from `btsnoop`.
- **iOS / macOS** — pair the iPhone with a Mac and read the IRK from the key store.

---

## Credits

The GATT capture approach — advertising as a Heart Rate sensor or Logitech K380
keyboard with an encrypted-read characteristic to force full BLE identity key
distribution — is based on [DerekSeaman/irk-capture](https://github.com/DerekSeaman/irk-capture)
(MIT licensed), which implements the same idea as ESP32 ESPHome firmware. This project
is an independent Python reimplementation using Linux BlueZ.

---

## Disclaimer

This project was written with the help of
[Claude Code](https://www.anthropic.com/claude-code) (an AI coding assistant).
It is provided **as-is, without any warranty**; the authors accept **no
liability** for any damage, data loss, or other consequences of using it. Review
the code and use it at your own risk.

An IRK lets you resolve a device's rotating addresses and therefore track it.
Only extract IRKs from devices **you own or are explicitly authorized to track**,
and comply with the privacy laws that apply to you. Do not use this tool to track
people or devices without consent.
