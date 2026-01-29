// Fetched from https://github.com/httptoolkit/frida-interception-and-unpinning/blob/48fd909ed5e016b771cf4d645ce30cbab217e234

// If you like, set to to true to enable extra logging:
const DEBUG_MODE = false;
const IGNORED_NON_HTTP_PORTS = [];
const BLOCK_HTTP3 = true;
const PROXY_SUPPORTS_SOCKS5 = false;

// Base64 character set (plus padding character =) and lookup:
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const BASE64_LOOKUP = new Uint8Array(123);
for (let i = 0; i < BASE64_CHARS.length; i++) {
    BASE64_LOOKUP[BASE64_CHARS.charCodeAt(i)] = i;
}


/**
 * Take a base64 string, and return the raw bytes
 * @param {string} input
 * @returns Uint8Array
 */
function decodeBase64(input) {
    // Calculate the length of the output buffer based on padding:
    let outputLength = Math.floor((input.length * 3) / 4);
    if (input[input.length - 1] === '=') outputLength--;
    if (input[input.length - 2] === '=') outputLength--;

    const output = new Uint8Array(outputLength);
    let outputPos = 0;

    // Process each 4-character block:
    for (let i = 0; i < input.length; i += 4) {
        const a = BASE64_LOOKUP[input.charCodeAt(i)];
        const b = BASE64_LOOKUP[input.charCodeAt(i + 1)];
        const c = BASE64_LOOKUP[input.charCodeAt(i + 2)];
        const d = BASE64_LOOKUP[input.charCodeAt(i + 3)];

        // Assemble into 3 bytes:
        const chunk = (a << 18) | (b << 12) | (c << 6) | d;

        // Add each byte to the output buffer, unless it's padding:
        output[outputPos++] = (chunk >> 16) & 0xff;
        if (input.charCodeAt(i + 2) !== 61) output[outputPos++] = (chunk >> 8) & 0xff;
        if (input.charCodeAt(i + 3) !== 61) output[outputPos++] = chunk & 0xff;
    }

    return output;
}

/**
 * Take a single-certificate PEM string, and return the raw DER bytes
 * @param {string} input
 * @returns Uint8Array
 */
function pemToDer(input) {
    const pemLines = input.split('\n');
    if (
        pemLines[0] !== '-----BEGIN CERTIFICATE-----' ||
        pemLines[pemLines.length- 1] !== '-----END CERTIFICATE-----'
    ) {
        throw new Error(
            'Your certificate should be in PEM format, starting & ending ' +
            'with a BEGIN CERTIFICATE & END CERTIFICATE header/footer'
        );
    }

    const base64Data = pemLines.slice(1, -1).map(l => l.trim()).join('');
    if ([...base64Data].some(c => !BASE64_CHARS.includes(c))) {
        throw new Error(
            'Your certificate should be in PEM format, containing only ' +
            'base64 data between a BEGIN & END CERTIFICATE header/footer'
        );
    }

    return decodeBase64(base64Data);
}

const CERT_DER = pemToDer(CERT_PEM);

// Right now this API is a bit funky - the callback will be called with a Frida Module instance
// if the module is properly detected, but may be called with just { name, path, base, size }
// in some cases (e.g. shared libraries loaded from inside an APK on Android). Works OK right now,
// as it's not widely used but needs improvement in future if we extend this.
function waitForModule(moduleName, callback) {
    if (Array.isArray(moduleName)) {
        moduleName.forEach(module => waitForModule(module, callback));
    }

    try {
        const module = Process.getModuleByName(moduleName)
        module.ensureInitialized();
        callback(module);
        return;
    } catch (e) {
        try {
            const module = Module.load(moduleName);
            callback(module);
            return;
        } catch (e) {}
    }

    MODULE_LOAD_CALLBACKS[moduleName] = callback;
}

const getModuleName = (nameOrPath) => {
    const endOfPath = nameOrPath.lastIndexOf('/');
    return nameOrPath.slice(endOfPath + 1);
};

const MODULE_LOAD_CALLBACKS = {};
new ApiResolver('module').enumerateMatches('exports:linker*!*dlopen*').forEach((dlopen) => {
    Interceptor.attach(dlopen.address, {
        onEnter(args) {
            const moduleArg = args[0].readCString();
            if (moduleArg) {
                this.path = moduleArg;
                this.moduleName = getModuleName(moduleArg);
            }
        },
        onLeave(retval) {
            if (!this.path || !retval || retval.isNull()) return;
            if (!MODULE_LOAD_CALLBACKS[this.moduleName]) return;

            let module = Process.findModuleByName(this.moduleName)
                ?? Process.findModuleByAddress(retval);
            if (!module) {
                // Some modules are loaded in ways that mean Frida can't detect them, and
                // can't look them up by name (notably when loading libraries from inside an
                // APK on Android). To handle this, we can use dlsym to look up an example
                // symbol and find the underlying module details directly, where possible.
                module = getAnonymousModule(this.moduleName, this.path, retval);
                if (!module) return;
            }

            Object.keys(MODULE_LOAD_CALLBACKS).forEach((key) => {
                if (this.moduleName === key) {
                    if (module) {
                        MODULE_LOAD_CALLBACKS[key](module);
                        delete MODULE_LOAD_CALLBACKS[key];
                    }
                }
            });
        }
    });
});

const getAnonymousModule = (name, path, handle) => {
    const dlsymAddr = Module.findGlobalExportByName('dlsym');
    if (!dlsymAddr) {
        console.error(`[!] Cannot find dlsym, cannot get anonymous module info for ${name}`);
        return;
    }

    const dlsym = new NativeFunction(dlsymAddr, 'pointer', ['pointer', 'pointer']);

    // Handle here is the return value from dlopen - but in this scenario, it's just an
    // opaque handle into to 'soinfo' data that other methods can use to get the
    // real pointer to parts of the module, like so:
    const onLoadPointer = dlsym(handle, Memory.allocUtf8String('JNI_OnLoad'));

    // Once we have an actual pointer, we can get the range that holds it:
    const range = Process.getRangeByAddress(onLoadPointer);

    return {
        base: range.base,
        size: range.size,
        name,
        path,
    }
};

(() => {
    const PROXY_HOST_IPv4_BYTES = PROXY_HOST.split('.').map(part => parseInt(part, 10));
    const IPv6_MAPPING_PREFIX_BYTES = [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff];
    const PROXY_HOST_IPv6_BYTES = IPv6_MAPPING_PREFIX_BYTES.concat(PROXY_HOST_IPv4_BYTES);

    // Flags for fcntl():
    const F_GETFL = 3;
    const F_SETFL = 4;
    const O_NONBLOCK = (Process.platform === 'darwin')
        ? 4
        : 2048; // Linux/Android

    let fcntl, send, recv, conn;
    try {
        const systemModule = Process.findModuleByName('libc.so') ?? // Android
                             Process.findModuleByName('libc.so.6') ?? // Linux
                             Process.findModuleByName('libsystem_c.dylib'); // iOS

        if (!systemModule) throw new Error("Could not find libc or libsystem_c");

        fcntl = new NativeFunction(systemModule.getExportByName('fcntl'), 'int', ['int', 'int', 'int']);
        send = new NativeFunction(systemModule.getExportByName('send'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);
        recv = new NativeFunction(systemModule.getExportByName('recv'), 'ssize_t', ['int', 'pointer', 'size_t', 'int']);

        conn = systemModule.getExportByName('connect')
    } catch (e) {
        console.error("Failed to set up native hooks:", e.message);
        console.warn('Could not initialize system functions to to hook raw traffic');
        return;
    }

    Interceptor.attach(conn, {
        onEnter(args) {
            const fd = this.sockFd = args[0].toInt32();
            const sockType = Socket.type(fd);

            const addrPtr = ptr(args[1]);
            const addrLen = args[2].toInt32();
            const addrData = addrPtr.readByteArray(addrLen);

            const isTCP = sockType === 'tcp' || sockType === 'tcp6';
            const isUDP = sockType === 'udp' || sockType === 'udp6';
            const isIPv6 = sockType === 'tcp6' || sockType === 'udp6';

            if (isTCP || isUDP) {
                const portAddrBytes = new DataView(addrData.slice(2, 4));
                const port = portAddrBytes.getUint16(0, false); // Big endian!

                const shouldBeIgnored = IGNORED_NON_HTTP_PORTS.includes(port);
                const shouldBeBlocked = BLOCK_HTTP3 && !shouldBeIgnored && isUDP && port === 443;

                // N.b for now we only support TCP interception - UDP direct should be doable,
                // but SOCKS5 UDP would require a whole different flow. Rarely relevant, especially
                // if you're blocking HTTP/3.
                const shouldBeIntercepted = isTCP && !shouldBeIgnored && !shouldBeBlocked;

                const hostBytes = isIPv6
                    // 16 bytes offset by 8 (2 for family, 2 for port, 4 for flowinfo):
                    ? new Uint8Array(addrData.slice(8, 8 + 16))
                    // 4 bytes, offset by 4 (2 for family, 2 for port)
                    : new Uint8Array(addrData.slice(4, 4 + 4));

                const isIntercepted = port === PROXY_PORT && areArraysEqual(hostBytes,
                    isIPv6
                        ? PROXY_HOST_IPv6_BYTES
                        : PROXY_HOST_IPv4_BYTES
                );

                if (isIntercepted) return;

                if (shouldBeBlocked) {
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo, then write :: (all 0s)
                        for (let i = 0; i < 16; i++) {
                            addrPtr.add(8 + i).writeU8(0);
                        }
                    } else {
                        // Skip 4 bytes: 2 family, 2 port, then write 0.0.0.0
                        addrPtr.add(4).writeU32(0);
                    }

                    console.debug(`Blocking QUIC connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);
                    this.state = 'Blocked';
                } else if (shouldBeIntercepted) {
                    // Otherwise, it's an unintercepted connection that should be captured:
                    this.state = 'intercepting';

                    // For SOCKS, we preserve the original destionation to use in the SOCKS handshake later
                    // and we temporarily set the socket to blocking mode to do the handshake itself.
                    if (PROXY_SUPPORTS_SOCKS5) {
                        this.originalDestination = { host: hostBytes, port, isIPv6 };
                        this.originalFlags = fcntl(this.sockFd, F_GETFL, 0);
                        this.isNonBlocking = (this.originalFlags & O_NONBLOCK) !== 0;
                        if (this.isNonBlocking) {
                            fcntl(this.sockFd, F_SETFL, this.originalFlags & ~O_NONBLOCK);
                        }
                    }

                    console.log(`Manually intercepting ${sockType} connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);

                    // Overwrite the port with the proxy port:
                    portAddrBytes.setUint16(0, PROXY_PORT, false); // Big endian
                    addrPtr.add(2).writeByteArray(portAddrBytes.buffer);

                    // Overwrite the address with the proxy address:
                    if (isIPv6) {
                        // Skip 8 bytes: 2 family, 2 port, 4 flowinfo
                        addrPtr.add(8).writeByteArray(PROXY_HOST_IPv6_BYTES);
                    } else {
                        // Skip 4 bytes: 2 family, 2 port
                        addrPtr.add(4).writeByteArray(PROXY_HOST_IPv4_BYTES);
                    }
                } else {
                    // Explicitly being left alone
                    if (DEBUG_MODE) {
                        console.debug(`Allowing unintercepted ${sockType} connection to port ${port}`);
                    }
                    this.state = 'ignored';
                }
            } else {
                // Should just be unix domain sockets - UDP & TCP are covered above
                if (DEBUG_MODE) console.log(`Ignoring ${sockType} connection`);
                this.state = 'ignored';
            }
        },
        onLeave: function (retval) {
            if (this.state === 'ignored') return;

            if (this.state === 'intercepting' && PROXY_SUPPORTS_SOCKS5) {
                const connectSuccess = retval.toInt32() === 0;

                let handshakeSuccess = false;

                const { host, port, isIPv6 } = this.originalDestination;
                if (connectSuccess) {
                    handshakeSuccess = performSocksHandshake(this.sockFd, host, port, isIPv6);
                } else {
                    console.error(`SOCKS: Failed to connect to proxy at ${PROXY_HOST}:${PROXY_PORT}`);
                }

                if (this.isNonBlocking) {
                    fcntl(this.sockFd, F_SETFL, this.originalFlags);
                }

                if (handshakeSuccess) {
                    const readableHost = getReadableAddress(host, isIPv6);
                    if (DEBUG_MODE) console.debug(`SOCKS redirect successful for fd ${this.sockFd} to ${readableHost}:${port}`);
                    retval.replace(0);
                } else {
                    if (DEBUG_MODE) console.error(`SOCKS redirect FAILED for fd ${this.sockFd}`);
                    retval.replace(-1);
                }
            } else if (DEBUG_MODE) {
                const fd = this.sockFd;
                const sockType = Socket.type(fd);
                const address = Socket.peerAddress(fd);
                console.debug(
                    `${this.state} ${sockType} fd ${fd} to ${JSON.stringify(address)} (${retval.toInt32()})`
                );
            }
        }
    });

    console.log(`== Redirecting ${
        IGNORED_NON_HTTP_PORTS.length === 0
        ? 'all'
        : 'all unrecognized'
    } TCP connections to ${PROXY_HOST}:${PROXY_PORT} ==`);

    const getReadableAddress = (
        /** @type {Uint8Array} */ hostBytes,
        /** @type {boolean} */ isIPv6
    ) => {
        if (!isIPv6) {
            // Return simple a.b.c.d IPv4 format:
            return [...hostBytes].map(x => x.toString()).join('.');
        }

        if (
            hostBytes.slice(0, 10).every(b => b === 0) &&
            hostBytes.slice(10, 12).every(b => b === 255)
        ) {
            // IPv4-mapped IPv6 address - print as IPv4 for readability
            return '::ffff:'+[...hostBytes.slice(12)].map(x => x.toString()).join('.');
        }

        else {
            // Real IPv6:
            return `[${[...hostBytes].map(x => x.toString(16)).join(':')}]`;
        }
    };

    const areArraysEqual = (arrayA, arrayB) => {
        if (arrayA.length !== arrayB.length) return false;
        return arrayA.every((x, i) => arrayB[i] === x);
    };

    function performSocksHandshake(sockfd, targetHostBytes, targetPort, isIPv6) {
        const hello = Memory.alloc(3).writeByteArray([0x05, 0x01, 0x00]);
        if (send(sockfd, hello, 3, 0) < 0) {
            console.error("SOCKS: Failed to send hello");
            return false;
        }

        const response = Memory.alloc(2);
        if (recv(sockfd, response, 2, 0) < 0) {
            console.error("SOCKS: Failed to receive server choice");
            return false;
        }

        if (response.readU8() !== 0x05 || response.add(1).readU8() !== 0x00) {
            console.error("SOCKS: Server rejected auth method");
            return false;
        }

        let req = [0x05, 0x01, 0x00]; // VER, CMD(CONNECT), RSV

        if (isIPv6) {
            req.push(0x04); // ATYP: IPv6
        } else { // IPv4
            req.push(0x01); // ATYP: IPv4
        }

        req.push(...targetHostBytes, (targetPort >> 8) & 0xff, targetPort & 0xff);
        const reqBuf = Memory.alloc(req.length).writeByteArray(req);

        if (send(sockfd, reqBuf, req.length, 0) < 0) {
            console.error("SOCKS: Failed to send connection request");
            return false;
        }

        const replyHeader = Memory.alloc(4);
        if (recv(sockfd, replyHeader, 4, 0) < 0) {
            console.error("SOCKS: Failed to receive reply header");
            return false;
        }

        const replyCode = replyHeader.add(1).readU8();
        if (replyCode !== 0x00) {
            console.error(`SOCKS: Server returned error code ${replyCode}`);
            return false;
        }

        const atyp = replyHeader.add(3).readU8();
        let remainingBytes = 0;
        if (atyp === 0x01) remainingBytes = 4 + 2; // IPv4 + port
        else if (atyp === 0x04) remainingBytes = 16 + 2; // IPv6 + port
        if (remainingBytes > 0) recv(sockfd, Memory.alloc(remainingBytes), remainingBytes, 0);

        return true;
    }


})();

const TARGET_LIBS = [
    { name: 'libboringssl.dylib', hooked: false }, // iOS primary TLS implementation
    { name: 'libsscronet.so', hooked: false }, // Cronet on Android
    { name: 'boringssl', hooked: false }, // Bundled by some apps e.g. TikTok on iOS
    { name: 'libssl.so', hooked: false }, // Native OpenSSL in Android
];

TARGET_LIBS.forEach((targetLib) => {
    waitForModule(targetLib.name, (targetModule) => {
        patchTargetLib(targetModule, targetLib.name);
        targetLib.hooked = true;
    });

    if (
        targetLib.name === 'libboringssl.dylib' &&
        Process.platform === 'darwin' &&
        !targetLib.hooked
    ) {
        // On iOS, we expect this to always work immediately, so print a warning if we
        // ever have to skip this TLS patching process.
        console.log(`\n !!! --- Could not load ${targetLib.name} to hook TLS --- !!!`);
    }
});

// Native TLS hook
function patchTargetLib(targetModule, targetName) {
    // Get the peer certificates from an SSL pointer. Returns a pointer to a STACK_OF(CRYPTO_BUFFER)
    // which requires use of the next few methods below to actually access.
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get0_peer_certificates
    const SSL_get0_peer_certificates = new NativeFunction(
        targetModule.getExportByName('SSL_get0_peer_certificates'),
        'pointer', ['pointer']
    );

    // Stack methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/stack.h.html
    const sk_num = new NativeFunction(
        targetModule.getExportByName('sk_num'),
        'size_t', ['pointer']
    );

    const sk_value = new NativeFunction(
        targetModule.getExportByName('sk_value'),
        'pointer', ['pointer', 'int']
    );

    // Crypto buffer methods:
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/pool.h.html
    const crypto_buffer_len = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_len'),
        'size_t', ['pointer']
    );

    const crypto_buffer_data = new NativeFunction(
        targetModule.getExportByName('CRYPTO_BUFFER_data'),
        'pointer', ['pointer']
    );

    const SSL_VERIFY_OK = 0x0;
    const SSL_VERIFY_INVALID = 0x1;

    // We cache the verification callbacks we create. In general (in testing, 100% of the time) the
    // 'real' callback is always the exact same address, so this is much more efficient than creating
    // a new callback every time.
    const verificationCallbackCache = {};

    const buildVerificationCallback = (realCallbackAddr) => {
        if (!verificationCallbackCache[realCallbackAddr]) {
            const realCallback = (!realCallbackAddr || realCallbackAddr.isNull())
                ? new NativeFunction(realCallbackAddr, 'int', ['pointer','pointer'])
                : () => SSL_VERIFY_INVALID; // Callback can be null - treat as invalid (=our validation only)

            let pendingCheckThreads = new Set();

            const hookedCallback = new NativeCallback(function (ssl, out_alert) {
                let realResult = false; // False = not yet called, 0/1 = call result

                const threadId = Process.getCurrentThreadId();
                const alreadyHaveLock = pendingCheckThreads.has(threadId);

                // We try to have only one thread running these checks at a time, as parallel calls
                // here on the same underlying callback seem to crash in some specific scenarios
                while (pendingCheckThreads.size > 0 && !alreadyHaveLock) {
                    Thread.sleep(0.01);
                }
                pendingCheckThreads.add(threadId);

                if (targetName !== 'libboringssl.dylib') {
                    // Cronet assumes its callback is always called, and crashes if not. iOS's BoringSSL
                    // meanwhile seems to use some negative checks in its callback, and rejects the
                    // connection independently of the return value here if it's called with a bad cert.
                    // End result: we *only sometimes* proactively call the callback.
                    realResult = realCallback(ssl, out_alert);
                }

                // Extremely dumb certificate validation: we accept any chain where the *exact* CA cert
                // we were given is present. No flexibility for non-trivial cert chains, and no
                // validation beyond presence of the expected CA certificate. BoringSSL does do a
                // fair amount of essential validation independent of the certificate comparison
                // though, so some basics may be covered regardless (see tls13_process_certificate_verify).

                // This *intentionally* does not reject certs with the wrong hostname, expired CA
                // or leaf certs, and lots of other issues. This is significantly better than nothing,
                // but it is not production-ready TLS verification for general use in untrusted envs!

                const peerCerts = SSL_get0_peer_certificates(ssl);

                // Loop through every cert in the chain:
                for (let i = 0; i < sk_num(peerCerts); i++) {
                    // For each cert, check if it *exactly* matches our configured CA cert:
                    const cert = sk_value(peerCerts, i);
                    const certDataLength = crypto_buffer_len(cert).toNumber();

                    if (certDataLength !== CERT_DER.byteLength) continue;

                    const certPointer = crypto_buffer_data(cert);
                    const certData = new Uint8Array(certPointer.readByteArray(certDataLength));

                    if (certData.every((byte, j) => CERT_DER[j] === byte)) {
                        if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                        return SSL_VERIFY_OK;
                    }
                }

                // No matched peer - fallback to the provided callback instead:
                if (realResult === false) { // Haven't called it yet
                    realResult = realCallback(ssl, out_alert);
                }

                if (!alreadyHaveLock) pendingCheckThreads.delete(threadId);
                return realResult;
            }, 'int', ['pointer','pointer']);

            verificationCallbackCache[realCallbackAddr] = hookedCallback;
        }

        return verificationCallbackCache[realCallbackAddr];
    };

    const customVerifyAddrs = [
        targetModule.findExportByName("SSL_set_custom_verify"),
        targetModule.findExportByName("SSL_CTX_set_custom_verify")
    ].filter(Boolean);

    customVerifyAddrs.forEach((set_custom_verify_addr) => {
        const set_custom_verify_fn = new NativeFunction(
            set_custom_verify_addr,
            'void', ['pointer', 'int', 'pointer']
        );

        // When this function is called, ignore the provided callback, and
        // configure our callback instead:
        Interceptor.replace(set_custom_verify_fn, new NativeCallback(function(ssl, mode, providedCallbackAddr) {
            set_custom_verify_fn(ssl, mode, buildVerificationCallback(providedCallbackAddr));
        }, 'void', ['pointer', 'int', 'pointer']));
    });

    if (customVerifyAddrs.length) {
        if (DEBUG_MODE) {
            console.log(`[+] Patched ${customVerifyAddrs.length} ${targetName} verification methods`);
        }
        console.log(`== Hooked native TLS lib ${targetName} ==`);
    } else {
        console.log(`\n !!! Hooking native TLS lib ${targetName} failed - no verification methods found`);
    }

    const get_psk_identity_addr = targetModule.findExportByName("SSL_get_psk_identity");
    if (get_psk_identity_addr) {
        // Hooking this is apparently required for some verification paths which check the
        // result is not 0x0. Any return value should work fine though.
        Interceptor.replace(get_psk_identity_addr, new NativeCallback(function(ssl) {
            return "PSK_IDENTITY_PLACEHOLDER";
        }, 'pointer', ['pointer']));
    } else if (customVerifyAddrs.length) {
        console.log(`Patched ${customVerifyAddrs.length} custom_verify methods, but couldn't find get_psk_identity`);
    }
}

// Proxy override
Java.perform(() => {
    // Set default JVM system properties for the proxy address. Notably these are used
    // to initialize WebView configuration.
    Java.use('java.lang.System').setProperty('http.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('http.proxyPort', PROXY_PORT.toString());
    Java.use('java.lang.System').setProperty('https.proxyHost', PROXY_HOST);
    Java.use('java.lang.System').setProperty('https.proxyPort', PROXY_PORT.toString());

    Java.use('java.lang.System').clearProperty('http.nonProxyHosts');
    Java.use('java.lang.System').clearProperty('https.nonProxyHosts');

    // Some Android internals attempt to reset these settings to match the device configuration.
    // We block that directly here:
    const controlledSystemProperties = [
        'http.proxyHost',
        'http.proxyPort',
        'https.proxyHost',
        'https.proxyPort',
        'http.nonProxyHosts',
        'https.nonProxyHosts'
    ];
    Java.use('java.lang.System').clearProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to clear ${property} system property`);
            return this.getProperty(property);
        }
        return this.clearProperty(...arguments);
    }
    Java.use('java.lang.System').setProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) console.log(`Ignoring attempt to override ${property} system property`);
            return this.getProperty(property);
        }
        return this.setProperty(...arguments);
    }

    // Configure the app's proxy directly, via the app connectivity manager service:
    const ConnectivityManager = Java.use('android.net.ConnectivityManager');
    const ProxyInfo = Java.use('android.net.ProxyInfo');
    ConnectivityManager.getDefaultProxy.implementation = () => ProxyInfo.$new(PROXY_HOST, PROXY_PORT, '');
    // (Not clear if this works 100% - implying there are ConnectivityManager subclasses handling this)

    console.log(`== Proxy system configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);

    // Configure the proxy indirectly, by overriding the return value for all ProxySelectors everywhere:
    const Collections = Java.use('java.util.Collections');
    const ProxyType = Java.use('java.net.Proxy$Type');
    const InetSocketAddress = Java.use('java.net.InetSocketAddress');
    const ProxyCls = Java.use('java.net.Proxy'); // 'Proxy' is reserved in JS

    const targetProxy = ProxyCls.$new(
        ProxyType.HTTP.value,
        InetSocketAddress.$new(PROXY_HOST, PROXY_PORT)
    );
    const getTargetProxyList = () => Collections.singletonList(targetProxy);

    const ProxySelector = Java.use('java.net.ProxySelector');

    // Find every implementation of ProxySelector by quickly scanning method signatures, and
    // then checking whether each match actually implements java.net.ProxySelector:
    const proxySelectorClasses = Java.enumerateMethods('*!select(java.net.URI): java.util.List/s')
        .flatMap((matchingLoader) => matchingLoader.classes
            .map((classData) => Java.use(classData.name))
            .filter((Cls) => ProxySelector.class.isAssignableFrom(Cls.class))
        );

    // Replace the 'select' of every implementation, so they all send traffic to us:
    proxySelectorClasses.forEach(ProxySelectorCls => {
        if (DEBUG_MODE) {
            console.log('Rewriting', ProxySelectorCls.toString());
        }
        ProxySelectorCls.select.implementation = () => getTargetProxyList()
    });

    console.log(`== Proxy configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);
});

// Android Certificate injection
Java.perform(() => {
    // First, we build a JVM representation of our certificate:
    const String = Java.use("java.lang.String");
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');

    let cert;
    try {
        const certFactory = CertFactory.getInstance("X.509");
        const certBytes = String.$new(CERT_PEM).getBytes();
        cert = certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
    } catch (e) {
        console.error('Could not parse provided certificate PEM!');
        console.error(e);
        Java.use('java.lang.System').exit(1);
    }

    // Then we hook TrustedCertificateIndex. This is used for caching known trusted certs within Conscrypt -
    // by prepopulating all instances, we ensure that all TrustManagerImpls (and potentially other
    // things) automatically trust our certificate specifically (without disabling validation entirely).
    // This should apply to Android v7+ - previous versions used SSLContext & X509TrustManager.
    [
        'com.android.org.conscrypt.TrustedCertificateIndex',
        'org.conscrypt.TrustedCertificateIndex', // Might be used (com.android is synthetic) - unclear
        'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex' // Used in Apache Harmony version of Conscrypt
    ].forEach((TrustedCertificateIndexClassname, i) => {
        let TrustedCertificateIndex;
        try {
            TrustedCertificateIndex = Java.use(TrustedCertificateIndexClassname);
        } catch (e) {
            if (i === 0) {
                throw new Error(`${TrustedCertificateIndexClassname} not found - could not inject system certificate`);
            } else {
                // Other classnames are optional fallbacks
                if (DEBUG_MODE) {
                    console.log(`[ ] Skipped cert injection for ${TrustedCertificateIndexClassname} (not present)`);
                }
                return;
            }
        }

        TrustedCertificateIndex.$init.overloads.forEach((overload) => {
            overload.implementation = function () {
                this.$init(...arguments);
                // Index our cert as already trusted, right from the start:
                this.index(cert);
            }
        });

        TrustedCertificateIndex.reset.overloads.forEach((overload) => {
            overload.implementation = function () {
                const result = this.reset(...arguments);
                // Index our cert in here again, since the reset removes it:
                this.index(cert);
                return result;
            };
        });

        if (DEBUG_MODE) console.log(`[+] Injected cert into ${TrustedCertificateIndexClassname}`);
    });

    // This effectively adds us to the system certs, and also defeats quite a bit of basic certificate
    // pinning too! It auto-trusts us in any implementation that uses TrustManagerImpl (Conscrypt) as
    // the underlying cert checking component.

    console.log('== System certificate trust injected ==');
});

// Bypass SSL pinning
function buildX509CertificateFromBytes(certBytes) {
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');
    const certFactory = CertFactory.getInstance("X.509");
    return certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
}

function getCustomTrustManagerFactory() {
    // This is the one X509Certificate that we want to trust. No need to trust others (we should capture
    // _all_ TLS traffic) and risky to trust _everything_ (risks interception between device & proxy, or
    // worse: some traffic being unintercepted & sent as HTTPS with TLS effectively disabled over the
    // real web - potentially exposing auth keys, private data and all sorts).
    const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
    const trustedCACert = buildX509CertificateFromBytes(certBytes);

    // Build a custom TrustManagerFactory with a KeyStore that trusts only this certificate:

    const KeyStore = Java.use("java.security.KeyStore");
    const keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null);
    keyStore.setCertificateEntry("ca", trustedCACert);

    const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    const customTrustManagerFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
    );
    customTrustManagerFactory.init(keyStore);

    return customTrustManagerFactory;
}

function getCustomX509TrustManager() {
    const customTrustManagerFactory = getCustomTrustManagerFactory();
    const trustManagers = customTrustManagerFactory.getTrustManagers();

    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

    const x509TrustManager = trustManagers.find((trustManager) => {
        return trustManager.class.isAssignableFrom(X509TrustManager.class);
    });

    // We have to cast it explicitly before Frida will allow us to use the X509 methods:
    return Java.cast(x509TrustManager, X509TrustManager);
}

// Some standard hook replacements for various cases:
const NO_OP = () => {};
const RETURN_TRUE = () => true;
const CHECK_OUR_TRUST_MANAGER_ONLY = () => {
    const trustManager = getCustomX509TrustManager();
    return (certs, authType) => {
        trustManager.checkServerTrusted(certs, authType);
    };
};

const PINNING_FIXES = {
    // --- Native HttpsURLConnection

    'javax.net.ssl.HttpsURLConnection': [
        {
            methodName: 'setDefaultHostnameVerifier',
            replacement: () => NO_OP
        },
        {
            methodName: 'setSSLSocketFactory',
            replacement: () => NO_OP
        },
        {
            methodName: 'setHostnameVerifier',
            replacement: () => NO_OP
        },
    ],

    // --- Native SSLContext

    'javax.net.ssl.SSLContext': [
        {
            methodName: 'init',
            overload: ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'],
            replacement: (targetMethod) => {
                const customTrustManagerFactory = getCustomTrustManagerFactory();

                // When constructor is called, replace the trust managers argument:
                return function (keyManager, _providedTrustManagers, secureRandom) {
                    return targetMethod.call(this,
                        keyManager,
                        customTrustManagerFactory.getTrustManagers(), // Override their trust managers
                        secureRandom
                    );
                }
            }
        }
    ],

    // --- Native Conscrypt CertPinManager

    'com.android.org.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            replacement: () => RETURN_TRUE
        },
        {
            methodName: 'checkChainPinning',
            replacement: () => NO_OP
        }
    ],

    // --- Native pinning configuration loading (used for configuration by many libraries)

    'android.security.net.config.NetworkSecurityConfig': [
        {
            methodName: '$init',
            overload: '*',
            replacement: (targetMethod) => {
                const PinSet = Java.use('android.security.net.config.PinSet');
                const EMPTY_PINSET = PinSet.EMPTY_PINSET.value;
                return function () {
                    // Always ignore the 2nd 'pins' PinSet argument entirely:
                    arguments[2] = EMPTY_PINSET;
                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- Native HostnameVerification override (n.b. Android contains its own vendored OkHttp v2!)

    'com.android.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: [
                'java.lang.String',
                'javax.net.ssl.SSLSession'
            ],
            replacement: (targetMethod) => {
                // Our trust manager - this trusts *only* our extra CA
                const trustManager = getCustomX509TrustManager();

                return function (hostname, sslSession) {
                    try {
                        const certs = sslSession.getPeerCertificates();

                        // https://stackoverflow.com/a/70469741/68051
                        const authType = "RSA";

                        // This throws if the certificate isn't trusted (i.e. if it's
                        // not signed by our extra CA specifically):
                        trustManager.checkServerTrusted(certs, authType);

                        // If the cert is from our CA, great! Skip hostname checks entirely.
                        return true;
                    } catch (e) {} // Ignore errors and fallback to default behaviour

                    // We fallback to ensure that connections with other CAs (e.g. direct
                    // connections allowed past the proxy) validate as normal.
                    return targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    'com.android.okhttp.Address': [
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                'com.android.okhttp.Dns',
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[5] = defaultHostnameVerifier;
                    arguments[6] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        },
        // Almost identical patch, but for Nougat and older. In these versions, the DNS argument
        // isn't passed here, so the arguments to patch changes slightly:
        {
            methodName: '$init',
            overload: [
                'java.lang.String',
                'int',
                // No DNS param
                'javax.net.SocketFactory',
                'javax.net.ssl.SSLSocketFactory',
                'javax.net.ssl.HostnameVerifier',
                'com.android.okhttp.CertificatePinner',
                'com.android.okhttp.Authenticator',
                'java.net.Proxy',
                'java.util.List',
                'java.util.List',
                'java.net.ProxySelector'
            ],
            replacement: (targetMethod) => {
                const defaultHostnameVerifier = Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
                    .INSTANCE.value;
                const defaultCertPinner = Java.use("com.android.okhttp.CertificatePinner")
                    .DEFAULT.value;

                return function () {
                    // Override arguments, to swap any custom check params (widely used
                    // to add stricter rules to TLS verification) with the defaults instead:
                    arguments[4] = defaultHostnameVerifier;
                    arguments[5] = defaultCertPinner;

                    targetMethod.call(this, ...arguments);
                }
            }
        }
    ],

    // --- OkHttp v3

    'okhttp3.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', '[Ljava.security.cert.Certificate;'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check$okhttp',
            replacement: () => NO_OP
        },
    ],

    // --- SquareUp OkHttp (< v3)

    'com.squareup.okhttp.CertificatePinner': [
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.security.cert.Certificate'],
            replacement: () => NO_OP
        },
        {
            methodName: 'check',
            overload: ['java.lang.String', 'java.util.List'],
            replacement: () => NO_OP
        }
    ],

    // --- Trustkit (https://github.com/datatheorem/TrustKit-Android/)

    'com.datatheorem.android.trustkit.pinning.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- Appcelerator (https://github.com/tidev/appcelerator.https)

    'appcelerator.https.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY
        }
    ],

    // --- PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)

    'nl.xservices.plugins.sslCertificateChecker': [
        {
            methodName: 'execute',
            overload: ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'],
            replacement: () => (_action, _args, context) => {
                context.success("CONNECTION_SECURE");
                return true;
            }
            // This trusts _all_ certs, but that's fine - this is used for checks of independent test
            // connections, rather than being a primary mechanism to secure the app's TLS connections.
        }
    ],

    // --- IBM WorkLight

    'com.worklight.wlclient.api.WLClient': [
        {
            methodName: 'pinTrustedCertificatePublicKey',
            getMethod: (WLClientCls) => WLClientCls.getInstance().pinTrustedCertificatePublicKey,
            overload: '*'
        }
    ],

    'com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning': [
        {
            methodName: 'verify',
            overload: '*',
            replacement: () => NO_OP
        }
        // This covers at least 4 commonly used WorkLight patches. Oddly, most sets of hooks seem
        // to return true for 1/4 cases, which must be wrong (overloads must all have the same
        // return type) but also it's very hard to find any modern (since 2017) references to this
        // class anywhere including WorkLight docs, so it may no longer be relevant anyway.
    ],

    'com.worklight.androidgap.plugin.WLCertificatePinningPlugin': [
        {
            methodName: 'execute',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager

    'com.commonsware.cwac.netsecurity.conscrypt.CertPinManager': [
        {
            methodName: 'isChainValid',
            overload: '*',
            replacement: () => RETURN_TRUE
        }
    ],

    // --- Netty

    'io.netty.handler.ssl.util.FingerprintTrustManagerFactory': [
        {
            methodName: 'checkTrusted',
            replacement: () => NO_OP
        }
    ],

    // --- Cordova / PhoneGap Advanced HTTP Plugin (https://github.com/silkimen/cordova-plugin-advanced-http)

    // Modern version:
    'com.silkimen.cordovahttp.CordovaServerTrust': [
        {
            methodName: '$init',
            replacement: (targetMethod) => function () {
                // Ignore any attempts to set trust to 'pinned'. Default settings will trust
                // our cert because of the separate system-certificate injection step.
                if (arguments[0] === 'pinned') {
                    arguments[0] = 'default';
                }

                return targetMethod.call(this, ...arguments);
            }
        }
    ],

    // --- Appmattus Cert Transparency (https://github.com/appmattus/certificatetransparency/)

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyHostnameVerifier': [
        {
            methodName: 'verify',
            replacement: () => RETURN_TRUE
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor': [
        {
            methodName: 'intercept',
            replacement: () => (a) => a.proceed(a.request())
            // This is not called unless the cert passes basic trust checks, so it's safe to blindly accept.
        }
    ],

    'com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager': [
        {
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
            replacement: CHECK_OUR_TRUST_MANAGER_ONLY,
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
            replacement: () => {
                const trustManager = getCustomX509TrustManager();
                return (certs, authType, _hostname) => {
                    // We ignore the hostname - if the certs are good (i.e they're ours), then the
                    // whole chain is good to go.
                    trustManager.checkServerTrusted(certs, authType);
                    return Java.use('java.util.Arrays').asList(certs);
                };
            }
        }
    ]

};

const getJavaClassIfExists = (clsName) => {
    try {
        return Java.use(clsName);
    } catch {
        return undefined;
    }
}

Java.perform(function () {
    if (DEBUG_MODE) console.log('\n    === Disabling all recognized unpinning libraries ===');

    const classesToPatch = Object.keys(PINNING_FIXES);

    classesToPatch.forEach((targetClassName) => {
        const TargetClass = getJavaClassIfExists(targetClassName);
        if (!TargetClass) {
            // We skip patches for any classes that don't seem to be present. This is common
            // as not all libraries we handle are necessarily used.
            if (DEBUG_MODE) console.log(`[ ] ${targetClassName} *`);
            return;
        }

        const patches = PINNING_FIXES[targetClassName];

        let patchApplied = false;

        patches.forEach(({ methodName, getMethod, overload, replacement }) => {
            const namedTargetMethod = getMethod
                ? getMethod(TargetClass)
                : TargetClass[methodName];

            const methodDescription = `${methodName}${
                overload === '*'
                    ? '(*)'
                : overload
                    ? '(' + overload.map((argType) => {
                        // Simplify arg names to just the class name for simpler logs:
                        const argClassName = argType.split('.').slice(-1)[0];
                        if (argType.startsWith('[L')) return `${argClassName}[]`;
                        else return argClassName;
                    }).join(', ') + ')'
                // No overload:
                    : ''
            }`

            let targetMethodImplementations = [];
            try {
                if (namedTargetMethod) {
                    if (!overload) {
                            // No overload specified
                        targetMethodImplementations = [namedTargetMethod];
                    } else if (overload === '*') {
                        // Targetting _all_ overloads
                        targetMethodImplementations = namedTargetMethod.overloads;
                    } else {
                        // Or targetting a specific overload:
                        targetMethodImplementations = [namedTargetMethod.overload(...overload)];
                    }
                }
            } catch (e) {
                // Overload not present
            }


            // We skip patches for any methods that don't seem to be present. This is rarer, but does
            // happen due to methods that only appear in certain library versions or whose signatures
            // have changed over time.
            if (targetMethodImplementations.length === 0) {
                if (DEBUG_MODE) console.log(`[ ] ${targetClassName} ${methodDescription}`);
                return;
            }

            targetMethodImplementations.forEach((targetMethod, i) => {
                const patchName = `${targetClassName} ${methodDescription}${
                    targetMethodImplementations.length > 1 ? ` (${i})` : ''
                }`;

                try {
                    const newImplementation = replacement(targetMethod);
                    if (DEBUG_MODE) {
                        // Log each hooked method as it's called:
                        targetMethod.implementation = function () {
                            console.log(` => ${patchName}`);
                            return newImplementation.apply(this, arguments);
                        }
                    } else {
                        targetMethod.implementation = newImplementation;
                    }

                    if (DEBUG_MODE) console.log(`[+] ${patchName}`);
                    patchApplied = true;
                } catch (e) {
                    // In theory, errors like this should never happen - it means the patch is broken
                    // (e.g. some dynamic patch building fails completely)
                    console.error(`[!] ERROR: ${patchName} failed: ${e}`);
                }
            })
        });

        if (!patchApplied) {
            console.warn(`[!] Matched class ${targetClassName} but could not patch any methods`);
        }
    });

    console.log('== Certificate unpinning completed ==');
});

// Android SSL unpinning fallback
// Capture the full fields or methods from a Frida class reference via JVM reflection:
const getFields = (cls) => getFridaValues(cls, cls.class.getDeclaredFields());
const getMethods = (cls) => getFridaValues(cls, cls.class.getDeclaredMethods());

// Take a Frida class + JVM reflection result, and turn it into a clear list
// of names -> Frida values (field or method references)
const getFridaValues = (cls, values) => values.map((value) =>
    [value.getName(), cls[value.getName()]]
);

Java.perform(function () {
    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script
        const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
        const trustedCACert = buildX509CertificateFromBytes(certBytes); // Ditto

        const isX509TrustManager = (cls, methodName) =>
            methodName === 'checkServerTrusted' &&
            X509TrustManager.class.isAssignableFrom(cls.class);

        // There are two standard methods that X509TM implementations might override. We confirm we're
        // matching the methods we expect by double-checking against the argument types:
        const BASE_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String'
        ];
        const EXTENDED_METHOD_ARGUMENTS = [
            '[Ljava.security.cert.X509Certificate;',
            'java.lang.String',
            'java.lang.String'
        ];

        const isOkHttpCheckMethod = (errorMessage, method) =>
            errorMessage.startsWith("Certificate pinning failure!" + "\n  Peer certificate chain:") &&
            method.argumentTypes.length === 2 &&
            method.argumentTypes[0].className === 'java.lang.String';

        const isAppmattusOkHttpInterceptMethod = (errorMessage, method) => {
            if (errorMessage !== 'Certificate transparency failed') return;

            // Takes a single OkHttp chain argument:
            if (method.argumentTypes.length !== 1) return;

            // The method must take an Interceptor.Chain, for which we need to
            // call chain.proceed(chain.request()) to return a Response type.
            // To do that, we effectively pattern match our way through all the
            // related types to work out what's what:

            const chainType = Java.use(method.argumentTypes[0].className);
            const responseTypeName = method.returnType.className;

            const matchedChain = matchOkHttpChain(chainType, responseTypeName);
            return !!matchedChain;
        };

        const isMetaPinningMethod = (errorMessage, method) =>
            method.argumentTypes.length === 1 &&
            method.argumentTypes[0].className === 'java.util.List' &&
            method.returnType.className === 'void' &&
            errorMessage.includes('pinning error');

        const matchOkHttpChain = (cls, expectedReturnTypeName) => {
            // Find the chain.proceed() method:
            const methods = getMethods(cls);
            const matchingMethods = methods.filter(([_, method]) =>
                method.returnType.className === expectedReturnTypeName
            );
            if (matchingMethods.length !== 1) return;

            const [proceedMethodName, proceedMethod] = matchingMethods[0];
            if (proceedMethod.argumentTypes.length !== 1) return;

            const argumentTypeName = proceedMethod.argumentTypes[0].className;

            // Find the chain.request private field (.request() getter can be
            // optimized out, so we read the field directly):
            const fields = getFields(cls);
            const matchingFields = fields.filter(([_, field]) =>
                field.fieldReturnType?.className === argumentTypeName
            );
            if (matchingFields.length !== 1) return;

            const [requestFieldName] = matchingFields[0];

            return {
                proceedMethodName,
                requestFieldName
            };
        };

        const buildUnhandledErrorPatcher = (errorClassName, originalConstructor) => {
            return function (errorArg) {
                try {
                    console.log('\n !!! --- Unexpected TLS failure --- !!!');

                    // This may be a message, or an cause, or plausibly maybe other types? But
                    // stringifying gives something consistently message-shaped, so that'll do.
                    const errorMessage = errorArg?.toString() ?? '';

                    // Parse the stack trace to work out who threw this error:
                    const stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === errorClassName
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    const errorTypeName = errorClassName.split('.').slice(-1)[0];
                    console.log(`      ${errorTypeName}: ${errorMessage}`);
                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    callingMethod.overloads.forEach((failingMethod) => {
                        if (failingMethod.implementation) {
                            console.warn('      Already patched - but still failing!')
                            return; // Already patched by Frida - skip it
                        }

                        // Try to spot known methods (despite obfuscation) and disable them:
                        if (isOkHttpCheckMethod(errorMessage, failingMethod)) {
                            // See okhttp3.CertificatePinner patches in unpinning script:
                            failingMethod.implementation = () => {
                                if (DEBUG_MODE) console.log(` => Fallback OkHttp patch`);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback OkHttp patch)`);
                        } else if (isAppmattusOkHttpInterceptMethod(errorMessage, failingMethod)) {
                            // See Appmattus CertificateTransparencyInterceptor patch in unpinning script:
                            const chainType = Java.use(failingMethod.argumentTypes[0].className);
                            const responseTypeName = failingMethod.returnType.className;
                            const okHttpChain = matchOkHttpChain(chainType, responseTypeName);
                            failingMethod.implementation = (chain) => {
                                if (DEBUG_MODE) console.log(` => Fallback Appmattus+OkHttp patch`);
                                const proceed = chain[okHttpChain.proceedMethodName].bind(chain);
                                const request = chain[okHttpChain.requestFieldName].value;
                                return proceed(request);
                            };
                            console.log(`      [+] ${className}->${methodName} (fallback Appmattus+OkHttp patch)`);
                        } else if (isX509TrustManager(callingClass, methodName)) {
                            const argumentTypes = failingMethod.argumentTypes.map(t => t.className);
                            const returnType = failingMethod.returnType.className;

                            if (
                                argumentTypes.length === 2 &&
                                argumentTypes.every((t, i) => t === BASE_METHOD_ARGUMENTS[i]) &&
                                returnType === 'void'
                            ) {
                                // For the base method, just check against the default:
                                failingMethod.implementation = (certs, authType) => {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } base method`);

                                    const defaultTrustManager = getCustomX509TrustManager(); // Defined in the unpinning script
                                    defaultTrustManager.checkServerTrusted(certs, authType);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager base patch)`);
                            } else if (
                                argumentTypes.length === 3 &&
                                argumentTypes.every((t, i) => t === EXTENDED_METHOD_ARGUMENTS[i]) &&
                                returnType === 'java.util.List'
                            ) {
                                // For the extended method, we just ignore the hostname, and if the certs are good
                                // (i.e they're ours), then we say the whole chain is good to go:
                                failingMethod.implementation = function (certs, authType, _hostname) {
                                    if (DEBUG_MODE) console.log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } extended method`);

                                    try {
                                        defaultTrustManager.checkServerTrusted(certs, authType);
                                    } catch (e) {
                                        console.error('Default TM threw:', e);
                                    }
                                    return Java.use('java.util.Arrays').asList(certs);
                                };
                                console.log(`      [+] ${className}->${methodName} (fallback X509TrustManager ext patch)`);
                            } else {
                                console.warn(`      [ ] Skipping unrecognized checkServerTrusted signature in class ${
                                    callingClass.class.getName()
                                }`);
                            }
                        } else if (isMetaPinningMethod(errorMessage, failingMethod)) {
                            failingMethod.implementation = function (certs) {
                                if (DEBUG_MODE) console.log(` => Fallback patch for meta proxygen pinning`);
                                for (const cert of certs.toArray()) {
                                    if (cert.equals(trustedCACert)) {
                                        return; // Our own cert - all good
                                    }
                                }

                                if (DEBUG_MODE) {
                                    console.warn(' Meta unpinning fallback found only untrusted certificates');
                                }
                                // Fall back to normal logic, in case of passthrough or similar
                                return failingMethod.call(this, certs);
                            }

                            console.log(`      [+] ${className}->${methodName} (Meta proxygen pinning fallback patch)`);
                        } else {
                            console.error('      [ ] Unrecognized TLS error - this must be patched manually');
                            return;
                            // Later we could try to cover other cases here - automatically recognizing other
                            // OkHttp interceptors for example, or potentially other approaches, but we need
                            // to do so carefully to avoid disabling TLS checks entirely.
                        }
                    });
                } catch (e) {
                    console.log('      [ ] Failed to automatically patch failure');
                    console.warn(e);
                }

                return originalConstructor.call(this, ...arguments);
            }
        };

        // These are the exceptions we watch for and attempt to auto-patch out after they're thrown:
        [
            'javax.net.ssl.SSLPeerUnverifiedException',
            'java.security.cert.CertificateException'
        ].forEach((errorClassName) => {
            const ErrorClass = Java.use(errorClassName);
            ErrorClass.$init.overloads.forEach((overload) => {
                overload.implementation = buildUnhandledErrorPatcher(
                    errorClassName,
                    overload
                );
            });
        })

        console.log('== Unpinning fallback auto-patcher installed ==');
    } catch (err) {
        console.error(err);
        console.error(' !!! --- Unpinning fallback auto-patcher installation failed --- !!!');
    }

});
