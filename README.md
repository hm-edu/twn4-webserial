# twn4-webserial

Provision MIFARE DESFire tags from the browser. A Next.js app that drives an
[Elatec TWN4](https://www.elatec-rfid.com/) reader over the
[Web Serial API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Serial_API),
speaking the TWN4 **Simple Protocol** directly — no native client, no driver, no
vendor SDK.

> **Proof of concept.** The key material is currently hardcoded in the page
> component. Read [Key material](#key-material) before pointing this at anything
> that matters.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Getting started](#getting-started)
- [Using the app](#using-the-app)
- [Provisioning flow](#provisioning-flow)
- [Key material](#key-material)
- [Module reference](#module-reference)
- [Project layout](#project-layout)
- [Security notes](#security-notes)
- [License](#license)

## How it works

The browser opens a serial port to the reader and exchanges ASCII-framed Simple
Protocol commands with it. Everything runs client-side; there is no backend.

```
┌─────────────────┐   Web Serial    ┌──────────────┐   13.56 MHz   ┌──────────┐
│  Next.js app    │ ─────────────►  │  TWN4 reader │ ────────────► │  DESFire │
│  (page.tsx)     │  ASCII frames   │  (CDC/COM)   │   ISO14443A   │   tag    │
└─────────────────┘                 └──────────────┘               └──────────┘
```

Three modules do the work:

| Module | Responsibility |
| --- | --- |
| [`src/web-serial-simple-protocol.ts`](src/web-serial-simple-protocol.ts) | Serial transport, Simple Protocol framing, DESFire command wrappers |
| [`src/key-crypto.ts`](src/key-crypto.ts) | Key/token spec types and a password-encrypted key store |
| [`src/desfire-template.ts`](src/desfire-template.ts) | Declarative binary layout for DESFire file contents |

## Requirements

**Browser** — Web Serial is required, which means a Chromium-based desktop
browser (Chrome, Edge, Opera) on a
[secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).
`localhost` counts, so `npm run dev` works; anything else needs HTTPS. Firefox and
Safari do not implement Web Serial, and neither does any mobile browser.
`connect()` throws `Web Serial API not supported in this browser.` when the API
is missing.

**Reader** — an Elatec TWN4 in Simple Protocol mode, exposed as a USB CDC serial
device. The transport defaults match the TWN4 factory configuration:

| Option | Default |
| --- | --- |
| `baudRate` | `9600` |
| `mode` | `'ascii'` |
| `useCrc` | `false` |
| `timeoutMs` | `1500` |
| `dataBits` / `stopBits` | `8` / `1` |
| `parity` / `flowControl` | `'none'` / `'none'` |

Override any of them through the `TwN4SimpleProtocol` constructor.

**Tags** — MIFARE DESFire. The app authenticates with 16-byte (2K3DES) keys.

## Getting started

```bash
npm install
npm run dev      # http://localhost:3000
```

Other scripts:

```bash
npm run build    # production build
npm start        # serve the production build
npm run lint     # eslint
```

Plug in the reader, load the page, and click **Connect reader** — the browser
shows a port picker, since `requestPort()` is called without filters. Port access
requires a user gesture, so this cannot be automated away.

## Using the app

| Button | What it does |
| --- | --- |
| **Connect reader** | Opens the serial port and switches the reader to MIFARE-only tag search |
| **Read only** | Identifies the tag on the antenna without writing to it |
| **Read & write default** | Personalizes a factory tag: formats it and installs the PICC master key |
| **Read & add HM app** | The above, plus creates the application, its 4 keys, and its files |
| **Format tag** | Formats the tag and restores the factory all-zero PICC master key |

Progress streams into the activity log below the toolbar. Tag search retries once
per second until a tag is present, so you can click first and present the tag
afterwards.

## Provisioning flow

**Read only** authenticates against application `0x000000` and reports one of
three outcomes: the tag is already personalized, it is still factory-default, or
its PICC master key is unknown.

**Read & write default** does the real work:

1. Search for a tag (`searchTag`), report its UID.
2. `cryptoInit` the reader's crypto environment with the factory all-zero key.
3. Select the PICC-level application `0x000000`.
4. If the tag is factory-default: `desfireFormatTag`, then `desfireChangeKey` to
   install the PICC master key, re-authenticate with it, and apply the key
   settings.
5. If the tag already carries the configured PICC master key, stop — it is
   already personalized.

**Read & add HM app** continues, for each application in the spec that is marked
`personalized` and not yet on the tag:

1. `createApplication` with 4 keys.
2. Select it and authenticate with the factory key.
3. `desfireChangeKey` for each of the 4 application keys, re-authenticating with
   key 0 after each change.
4. Create two standard files — file `0x00`, 16 bytes, access rights `0x2110`, and
   file `0x01`, 64 bytes, access rights `0x3110`.

## Key material

The DESFire keys live inline in the `keyspec` object in
[`src/app/page.tsx`](src/app/page.tsx). Because this is a client component, they
are compiled into the JavaScript bundle and served to every visitor. Treat the
committed keys as public: they are suitable for a bench setup and nothing else.

[`src/key-crypto.ts`](src/key-crypto.ts) already implements the intended
replacement — a `DesfireTokenSpec` sealed with AES-256-GCM under a PBKDF2 key —
but the UI does not use it yet. Wiring it up (or moving key handling behind a
server boundary) is the main outstanding task before this leaves the bench.

To rotate the current keys:

```bash
openssl rand -hex 16
```

Every provisioned tag holds the old PICC master key, so rotation without a
re-keying pass over existing tags leaves those tags unrecognized — the app will
classify them as "neither vanilla nor HM".

## Module reference

### `web-serial-simple-protocol.ts`

`TwN4SimpleProtocol` wraps one serial port. `connect()` prompts for a port and
opens it; `disconnect()` releases the reader and writer; `isConnected` reflects
the current state.

Reader and tag basics:

- `getUsbType()`, `beep()`
- `searchTag(maxIdBytes)` → `{ tagType, uid }`, or throws `NoTagFoundError`
- `setTagTypes()`, `getTagTypes()`, `getSupportedTagTypes()`, `setMifareOnly()`, `setRfOff()`
- `cryptoInit(cryptoEnv, keyType, key)`

DESFire operations:

- Applications — `desfireGetApplicationIds`, `desfireSelectApplication`, `createApplication`, `deleteApplication`
- Authentication — `desfireAuthenticate`, `tryPicc`, `isVanillaToken`
- Keys — `desfireChangeKey`, `desfireGetKeySettings`, `desfireChangeKeySettings`, `desfireSetDefaultKey`
- Files — `desfireCreateStandardFile`, `getFileIds`, `desfireReadData`, `desfireWriteData`
- Card — `desfireGetUid`, `desfireFormatTag`, `desfireDisableFormatCard`, `desfireFreeMemory`

Escape hatches for commands with no wrapper: `sendCommand`, `sendCommandRaw`,
`sendHexCommand`.

Two error types are thrown. `NoTagFoundError` means the antenna field is empty —
the app catches it and retries. `ProtocolError` carries a `StatusCode` from the
Simple Protocol specification, named in `StatusCodeName`. `TagType` holds the
reader's tag-type constants from Appendix A of the spec.

Also exported: `hexToBytes`, `bytesToHex`, `padHexEven`, `numberToBytesBE`,
`numberToBytesLE`, and the CRC helpers `updateCrc`, `computeCrc`, `appendCrc`.

### `key-crypto.ts`

Types describing a token: `DesfireKey`, `DesfireFile`, `DesfireApplication`, and
`DesfireTokenSpec` (one `piccMasterKey` plus a list of applications).

The key store encrypts a whole `DesfireTokenSpec` under a password:

- `encryptKeyStore(spec, password)` / `decryptKeyStore(store, password)`
- `changePassword(store, oldPassword, newPassword)`, `createKeyStore()`
- `saveToLocalStorage` / `loadFromLocalStorage` (key `desfire-key-store`)
- `exportToFile` / `importFromFile` (`desfire-keys.enc.json`)

Parameters: AES-256-GCM, PBKDF2-HMAC-SHA-256 at 600 000 iterations (the OWASP
minimum), a 32-byte salt and 12-byte IV per encryption, and a `version` field for
forward compatibility. Passwords shorter than 8 characters are rejected. A wrong
password surfaces as `Decryption failed: incorrect password or corrupted data`.

Key helpers: `hexToKeyBytes`, `keyBytesToHex`, `validateDesfireKey`.

> `validateDesfireKey` expects one of `DES`, `2K3DES`, `3K3DES`, `AES128`, while
> the `DesfireKey.keyType` field is typed `number | 'AES' | '3DES'`. The two
> vocabularies do not line up — passing a `keyType` straight from a
> `DesfireTokenSpec` into the validator throws `Unknown key type`.

### `desfire-template.ts`

Describes a DESFire file as a list of fixed-length fields, so file layouts stay
plain JSON and can be stored next to the encrypted key store.

A `FieldSpec` maps a dot-notation `path` on a source object (or a constant
`value`, which wins if both are set) into `length` bytes using an `encoding`:
`utf8`, `hex`, `uint8`, `uint16le`, `uint16be`, `uint32le`, `uint32be`. For
`utf8`, `pad` selects the filler — `" "` or `"\0"` (the default). Values longer
than `length` are truncated.

```ts
const userFileTemplate: FileTemplate = {
  name: "user-data",
  fields: [
    { path: "personalData.firstName", length: 16, encoding: "utf8", pad: " " },
    { path: "personalData.lastName",  length: 16, encoding: "utf8", pad: " " },
    { path: "bayzeitId",              length: 16, encoding: "utf8", pad: " " },
  ],
};

const bytes = buildFileContent(user, userFileTemplate); // Uint8Array(48)
```

`templateSize(template)` returns the byte count a template produces, and
`validateTemplate(template)` returns a list of problems (empty means valid).

## Project layout

```
src/
  app/
    page.tsx                     UI, key spec, and provisioning logic
    page.module.css              styles
    layout.tsx                   root layout, fonts, metadata
    globals.css                  resets and theme variables
  web-serial-simple-protocol.ts  transport + DESFire commands
  key-crypto.ts                  key types + encrypted key store
  desfire-template.ts            file layout templates
  css.d.ts                       stylesheet module declaration
```

`css.d.ts` declares `*.css` so TypeScript 6 accepts the side-effect import of
`globals.css`; without it the build fails with TS2882.

## Security notes

- **The bundled keys are public.** See [Key material](#key-material).
- **Formatting is destructive.** *Format tag* erases every application and file
  on the tag. There is no confirmation step.
- **Web Serial grants raw device access.** Only ever open a port for a page you
  trust; a granted port can issue arbitrary commands to the reader.
- **`localStorage` is not a vault.** The key store is encrypted, so the password
  never touches disk — but the ciphertext is readable by any script on the
  origin, and offline guessing is bounded only by password strength.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

