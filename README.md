# ESP32-S3 Home Key Passkey

Use an ESP32-S3 SuperMini as a USB FIDO2 security key. Registering or using a passkey requires a fresh tap of an enrolled Apple Wallet Home Key on the NFC reader. The firmware supports a separate FIDO2 PIN for websites that require user verification.

## Install

1. Download the ESP32-S3 factory BIN from [Releases](../../releases).
2. In Chrome or Edge, use the [Espressif browser flasher](https://espressif.github.io/esptool-js/) to program it at `0x0`. A factory flash overwrites Wi-Fi settings, pairing, the security-key PIN, and stored passkeys.
3. Restart the board, join its open `PS_…` hotspot, and visit `http://192.168.4.1`. Configure Wi-Fi, the NFC reader, and a dashboard login.
4. Rejoin your home Wi-Fi and open the dashboard at the address shown during setup. Choose **Add to Apple Home** and scan the QR code in **Home → Add Accessory**.

## Use the key

Connect the ESP32 over USB and choose **Security key** in the browser. Enter the FIDO2 PIN when prompted, then tap the enrolled Home Key. On Windows, set the PIN under **Settings → Accounts → Sign-in options → Security Key → Manage**.

The dashboard lists stored passkey slots and shows FIDO2 command results in **Logs**. **Start NFC pairing** is an experimental alternative to the QR code for PN532 readers. Open **Home → Add Accessory** and hold your iPhone near the reader within 30 seconds. iPhone proximity pairing and Google and Microsoft compatibility are unverified.

This project is based on [rednblkx/HomeKey-ESP32](https://github.com/rednblkx/HomeKey-ESP32). See [LICENSE](LICENSE).
