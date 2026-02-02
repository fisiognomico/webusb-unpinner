# WebUSB Unpinner

<img alt="License: AGPL-3.0-or-later" src="https://img.shields.io/badge/License-AGPL3.0--or--later-blue.svg" /> <img alt="Node" src="https://img.shields.io/badge/Node-16%2B-green.svg" />

A browser-based Android HTTPS unpinning and instrumentation framework. **No backend required** — runs entirely in your browser via WebUSB. __WebUSB Unpinner__ enables certificate pinning bypass by dynamically injecting Frida gadgets and patching APKs with the debuggable flag.

## Features

- **Pure Browser-Based**: No server, backend, or command-line tools needed
- **WebUSB Direct Connection**: Connect Android devices directly from your browser
- **APK Patching**: Automatically modifies AndroidManifest.xml to enable the debuggable flag
- **Frida Gadget Injection**: Injects Frida gadgets via JDWP for runtime manipulation
- **Certificate Unpinning**: Includes HTTP Toolkit's certificate unpinning script
- **APK Signing**: Re-signs patched APKs with embedded certificate
- **Live App Management**: Download, uninstall, and reinstall apps directly
- **Debug Mode Support**: Automatic debugging setup for target applications

## Current Status

🟡 **Experimental / Under Development**

### Supported ✅
- APK installation and patching
- Frida gadget injection for already-installed apps
- Manifest modification for debuggable flag

## Requirements

### Browser
- **Chrome** 88+, **Edge** 88+, or **Opera** 74+ (WebUSB support required)
- WebUSB capability is currently only tested on Chrome

### Android Device
- **Android 4.4+** (API level 19+)
- **Developer mode** enabled
- **USB debugging** enabled
- **WebUSB permissions** granted
To know more about enabling developer mode, consult [Android documentation](https://developer.android.com/studio/debug/dev-options).

### Development Machine
- **Node.js** 16+
- **npm** or **yarn**
- [**git**](https://git-scm.com/install/)
  
If you've never used node.js or npm, consult their [website](https://nodejs.org/en/learn/getting-started/introduction-to-nodejs) to learn how to install them on your machine.

## Quick Start

### Option 1: Development (Local Testing)

```bash
# Clone and setup
git clone  https://github.com/fisiognomico/webusb-unpinner
cd webusb-unpinner
npm install

# Start dev server (http://localhost:9000)
npm run dev
```

### Option 2: Production Build

```bash
# Build for production
npm run build

# Output goes to ./dist/
npm install -g serve
serve dist
```

## Usage

### Step 1: Connect Your Device

1. Open the app in your browser (Chrome recommended)
2. Enable **Developer Options** on Android (tap Build Number 7 times)
3. Enable **USB Debugging** in Developer Options
4. Connect device via USB
5. Click **Connect Device** in the app
6. Authorize WebUSB permission and USB debugging on device

### Step 2: Configure Proxy

1. Enter proxy address and port
2. Paste your CA certificate (PEM format)
3. Click **Save Proxy Configuration**

### Step 3: Upload & Install Apps

1. **Drag and drop** APK files or click upload area
2. Click **Upload Selected Files**
3. WebUSB Unpiner will:
   - Extract the APK
   - Modify AndroidManifest.xml (add `debuggable=true`)
   - Sign the patched APK
   - Install on your device

Alternatively, use the drop down menu to monitor an app that is already
installed on your device!

### Step 4: Monitor & Intercept

Once patched, use tools like mitmproxy or HTTP Toolkit to:
- Intercept HTTPS traffic
- Monitor app behavior
- Modify app logic at runtime

You can read our [accompanying blog post](https://reversing.works/posts/2025/12/webusb-unpinner-network-analysis-for-the-masses/) for a more detailed walk through that includes a video demo.

## Architecture

### Workflow

```
User Browser
     ↓
WebUSB Connection
     ↓
Android Device
     ↓
┌─────────────────────────────────────┐
│ WebUSB Unpinner Processing Pipeline │
├─────────────────────────────────────┤
│  1. APK Extraction (JSZip)          │
│  2. Binary XML Modification         │
│  3. APK Re-signing                  │
│  4. ADB Push to Device              │
│  5. JDWP Frida Injection            │
└─────────────────────────────────────┘
```

For a better overview of the internals of the project, please check out the
project documentation:
   - [JDWP Instrumentation](docs/jdwp-instrumentation.md)
   - [APK patching](docs/apk-patch.md)

### Key Components

| Component | Purpose | Library |
|-----------|---------|---------|
| **AdbManager** | ADB operations (push, pull, install) | `@yume-chan/adb` |
| **ApkPatcher** | Binary XML manipulation, manifest patching | `binary-xml-js` |
| **Signer** | APK signing (v2 signature) | `android-package-signer` |
| **FridaInjector** | JDWP protocol, gadget injection | `libjdwp` |
| **State Manager** | Device connection state, UI updates | TypeScript |

### Technology Stack

- **Language**: TypeScript
- **Build**: Webpack, TypeScript Compiler
- **ADB**: @yume-chan/adb ecosystem
- **APK Manipulation**: binary-xml-js, jszip
- **Signing**: android-package-signer
- **Frida Integration**: libjdwp
- **Runtime**: Browser WebUSB API

## Project Structure

```
WebUSB-unpinner/
├── src/
│   ├── index.ts                 # Main entry point & UI logic
│   ├── index.html               # UI template
│   ├── adb-manager.ts           # ADB protocol operations
│   ├── apk-patcher.ts           # Binary XML manipulation
│   ├── signer.ts                # APK v2 signing
│   ├── jdwp.ts                  # Frida gadget injection
│   ├── state.ts                 # State management
│   ├── config.ts                # Configuration & constants
│   └── utils.ts                 # Utility functions
│
├── static/
│   ├── scripts/
│   │   ├── hide-debugger.js     # Hide debuggable flag from apps
│   │   └── httptoolkit-unpinner.js  # Certificate unpinning
│   ├── libgadget.so             # Frida gadget library
│   └── libgadget.config.so      # Frida configuration
│
├── polyfills/
│   └── util.js                  # Node.js util polyfill
│
├── webpack.config.js            # Webpack configuration
├── tsconfig.json                # TypeScript configuration
├── package.json                 # Dependencies & metadata
└── README.md                    # This file
```

## Configuration

### Environment Variables

Set via webpack DefinePlugin or `.env`:

```bash
SERVER_URI=http://localhost:9000/
DEVICE_PATH=/data/local/tmp/
NODE_ENV=development
```

* **SERVER_URI** : prefix for static resources URLs
* **DEVICE_PATH** : local writable folder on Android where scripts will be
  dropped.
* **NODE_ENV** : development or production environment are supported

### Customizing the Certificate

To use your own certificate for APK signing:

1. **Generate a self-signed certificate**:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

2. **Convert to base64**:
   ```bash
   openssl pkcs12 -export -in cert.pem -inkey key.pem -out cert.p12 -name scorbuto
   base64 cert.p12 > cert.b64
   ```

3. **Update `src/const/cert.ts`**:
   ```typescript
   export const signDerCertficate: string = "data:application/x-pkcs12;base64,<your-base64-cert>";
   ```

⚠️ **Security Note**: Never commit certificates or private keys to version control.

## Acknowledgments

- **HTTP Toolkit** - Certificate unpinning script foundation
- **mitmproxy team** - android-unpinner workflow concept
- **yume-chan** - Excellent ADB libraries (@yume-chan/adb ecosystem)
- **android-package-signer** - APK signing implementation
- **libjdwp** - JDWP protocol implementation for Frida

## Troubleshooting

### WebUSB Connection Issues

**Device not appearing**
- Ensure USB debugging is enabled
- Try a different USB cable
- Restart browser and device
- Check Chrome supports your device (older devices may have issues)
- Check in `chrome://device-log/` if your device appear when connected.

**"WebUSB not supported"**
- You must use Chrome, Edge, or Opera (not Firefox)
- Check `chrome://flags` and enable experimental features if needed

### APK Installation Fails

**"APK not found" or installation error**
- Ensure sufficient storage on device (`adb shell df /data`)
- Check APK architecture matches device (ARM/ARM64/x86)
- Verify original APK is valid

**"Signing failed"**
- May indicate memory pressure on large APKs
- Try in incognito mode to free resources
- Certificate generation may be failing (check console)

### Frida Gadget Not Loading

**Frida gadget injection times out**
- Confirm app is debuggable: `adb shell pm dump <package> | grep debuggable`
- Check libgadget files were pushed: `adb shell ls /data/data/<package>/`
- Monitor app startup: `adb logcat | grep -i frida`

**"Breakpoint not hit"**
- App may have started before debugging attached
- Try uninstalling and reinstalling the app
- Check Activity class exists in manifest

### Cannot Intercept Traffic

**Proxy configuration not working**
- Ensure device can reach proxy server
- Check certificate is valid PEM format
- Verify proxy supports CONNECT tunneling

**"Certificate pinning still active"**
- Unpinning script may not apply to your app's pinning method
- Check app logs: `adb logcat | grep -i "cert\|pin\|ssl"`

## Development

### Build Commands

```bash
# Type checking
npm run type-check

# Development build
npm run build:dev

# Production build
npm run build

# Clean build artifacts
npm run clean

# Development server with hot reload
npm run dev
```

### Testing Checklist

Before submitting changes:

```
☐ npm run type-check passes
☐ npm run build:dev succeeds without warnings
☐ Tested in Chrome 88+
☐ WebUSB connection works
☐ APK upload and installation works
☐ No console errors or warnings
☐ Device connection can be established and closed cleanly
```

## Known Limitations

### Current Limitations

1. **WebUSB Browser Support**
   - Chrome/Edge/Opera only (no Firefox)
   - Some older device drivers may not work

2. **Limited Certificate Pinning Support**
   - Works for standard TLS verification
   - Some apps implement custom pinning logic
   - May require custom Frida scripts


### Future Roadmap

- **v0.2.0**: Multiple architecture support.
- **v0.4.0**: Better proxy integration & configuration.
- **v0.5.0**: ADB over TCP support.
- **v1.0.0**: Comprehensive certificate pinning bypass library.

## Security Considerations

### What This Tool Does

 -  Enables legitimate security research
 -  Allows app debugging for developers
 -  Facilitates penetration testing
 -  Provides educational insights into Android internals

### What This Tool Cannot Do

 - Bypass system-level security (SELinux, verified boot)
 - Grant permissions that weren't approved in manifest
 - Modify system apps without physical device access
 - Bypass app runtime integrity checks or anti-hooking techniques.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes following code style guidelines
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under **AGPL-3.0-or-later**. See [LICENSE](LICENSE) file for details.

The HTTP Toolkit unpinning script includes code from HTTP Toolkit (also AGPL-3.0).

## Related Projects

- [HTTP Toolkit](https://httptoolkit.tech/) - Intercepting HTTP debugging proxy
- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [mitmproxy](https://mitmproxy.org/) - Intercepting proxy
- [android-unpinner](https://github.com/mitmproxy/android-unpinner) - Android certificate unpinning

---

**Made with ❤️ by [reversing.works](https://reversing.works/)**

⭐ Star this repo if you find it useful!
