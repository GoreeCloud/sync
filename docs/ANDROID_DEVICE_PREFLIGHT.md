# Android device compatibility preflight

**Status:** Local development preflight; **not** a platform certification, APK, completed installation, or two-device transfer acceptance.

The GoreeCloud Sync Go CLI currently has a tested **compile-only** target of `GOOS=android GOARCH=arm64 CGO_ENABLED=0`. That target does **not** establish working runtime behavior or an installable Android app. In particular, Google/Android TV devices may report `armeabi-v7a` (32-bit ARM) without `arm64-v8a` support; do **not** deploy an ARM64 executable to such a device.

## Run a read-only capability check

Use an existing trusted Android SDK platform-tools installation and an explicitly authorized device:

```sh
adb devices -l
python3 -B tools/adb_device_preflight.py --serial 'DEVICE-SELECTOR-FROM-ADB-LIST'
```

Or provide `--adb /path/to/trusted/platform-tools/adb`. The script calls only `adb devices -l` and `adb -s <selected> shell getprop` for model, Android SDK and ABIs. It does not `push`, `install`, `tcpip`, `connect`, `forward`, invoke code on the device, change settings, or copy data. Each ADB call has an eight-second timeout and any missing/unauthorized/ambiguous device fails closed. The output deliberately omits its serial, network address, hardware identifier, or pairing credentials. Handle ADB output privately even when the preflight report is shareable.

Interpret `candidateGoTarget: android/arm64` as **architecture matching an existing cross-build only**. `runtimeVerified: false` and `deploymentPerformed: false` are always set; there is no public certification. For a 32-bit-only `armeabi-v7a` target, `candidateGoTarget` is `null`: Go 1.23 Android/arm requires external cgo linking with an Android NDK toolchain, which has not been established or validated here. A Linux/arm binary must not be substituted or called an Android build.

## Gates before the first real-device run

1. Independently verify the exact target identity, authorization, Android ABI, SDK version, and any running default app or installation conflicts. ADB's `device` authorization state does not grant a blanket right to alter device settings or user files.
2. Inspect the complete source, build instructions, dependencies, binary integrity, expected permissions, and any host-to-device transfer. Produce a platform-correct executable or package; for an Android APK, follow GoreeCloud's separate verified signing and `GoreeCloud/Artifacts/` delivery requirements.
3. Start with a bounded, manually approved scratch test that reads no private user files and runs no listener; record an exact binary checksum and cleanup plan. Only then test the encrypted peer flow in a closed, explicitly trusted two-device session.
4. Test stop/failure/rollback, storage cleanup, network exposure, interoperability and post-test state before reporting physical-device acceptance. Do not enable wireless ADB, install packages, alter the default launcher, or expose ports merely to satisfy a Sync development gate.

Run offline synthetic tests with `python3 -B -m unittest discover -s tools -p 'test_*.py'`. They use a fake ADB process and **do not touch hardware**.
