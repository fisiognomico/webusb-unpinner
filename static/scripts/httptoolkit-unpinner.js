// ============== NATIVE LOGCAT LOGGING ==============
const LOG_INFO = 4;
const LOG_WARN = 5;
const LOG_ERROR = 6;

let _log_write = null;
let _log_tag = null;

try {
    _log_write = new NativeFunction(
        Module.getExportByName(null, '__android_log_write'),
        'int', ['int', 'pointer', 'pointer']
    );
    _log_tag = Memory.allocUtf8String("UNPIN");
} catch (e) {
    // Fallback - won't reach logcat but at least won't crash
}

function log(msg) {
    if (_log_write && _log_tag) {
        const msgPtr = Memory.allocUtf8String(msg);
        _log_write(LOG_INFO, _log_tag, msgPtr);
    }
}

function logWarn(msg) {
    if (_log_write && _log_tag) {
        const msgPtr = Memory.allocUtf8String(msg);
        _log_write(LOG_WARN, _log_tag, msgPtr);
    }
}

function logErr(msg) {
    if (_log_write && _log_tag) {
        const msgPtr = Memory.allocUtf8String(msg);
        _log_write(LOG_ERROR, _log_tag, msgPtr);
    }
}

// Modified from https://github.com/httptoolkit/frida-interception-and-unpinning/blob/48fd909ed5e016b771cf4d645ce30cbab217e234
// Modified to be compatible with mimtproxy and other SSL proxies that do
// not append their CA to each server response.

// If you like, set to to true to enable extra logging:
const DEBUG_MODE = false;
const IGNORED_NON_HTTP_PORTS = [];
const BLOCK_HTTP3 = true;
const PROXY_SUPPORTS_SOCKS5 = false;

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
        logErr(`[!] Cannot find dlsym, cannot get anonymous module info for ${name}`);
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
        logErr("Failed to set up native hooks:", e.message);
        logWarn('Could not initialize system functions to to hook raw traffic');
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

                    log(`Manually intercepting ${sockType} connection to ${getReadableAddress(hostBytes, isIPv6)}:${port}`);

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
                if (DEBUG_MODE) log(`Ignoring ${sockType} connection`);
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
                    logErr(`SOCKS: Failed to connect to proxy at ${PROXY_HOST}:${PROXY_PORT}`);
                }

                if (this.isNonBlocking) {
                    fcntl(this.sockFd, F_SETFL, this.originalFlags);
                }

                if (handshakeSuccess) {
                    const readableHost = getReadableAddress(host, isIPv6);
                    if (DEBUG_MODE) console.debug(`SOCKS redirect successful for fd ${this.sockFd} to ${readableHost}:${port}`);
                    retval.replace(0);
                } else {
                    if (DEBUG_MODE) logErr(`SOCKS redirect FAILED for fd ${this.sockFd}`);
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

    log(`== Redirecting ${
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
            logErr("SOCKS: Failed to send hello");
            return false;
        }

        const response = Memory.alloc(2);
        if (recv(sockfd, response, 2, 0) < 0) {
            logErr("SOCKS: Failed to receive server choice");
            return false;
        }

        if (response.readU8() !== 0x05 || response.add(1).readU8() !== 0x00) {
            logErr("SOCKS: Server rejected auth method");
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
            logErr("SOCKS: Failed to send connection request");
            return false;
        }

        const replyHeader = Memory.alloc(4);
        if (recv(sockfd, replyHeader, 4, 0) < 0) {
            logErr("SOCKS: Failed to receive reply header");
            return false;
        }

        const replyCode = replyHeader.add(1).readU8();
        if (replyCode !== 0x00) {
            logErr(`SOCKS: Server returned error code ${replyCode}`);
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
        log(`\n !!! --- Could not load ${targetLib.name} to hook TLS --- !!!`);
    }
});

// Native TLS hook - MODIFIED: Always accept certificates without verification
function patchTargetLib(targetModule, targetName) {
    const SSL_VERIFY_OK = 0x0;

    // We cache the verification callbacks we create. In general (in testing, 100% of the time) the
    // 'real' callback is always the exact same address, so this is much more efficient than creating
    // a new callback every time.
    const verificationCallbackCache = {};

    const buildVerificationCallback = (realCallbackAddr) => {
        if (!verificationCallbackCache[realCallbackAddr]) {
            // MODIFIED: Always return SSL_VERIFY_OK - no certificate verification
            const hookedCallback = new NativeCallback(function (ssl, out_alert) {
                if (DEBUG_MODE) {
                    log('[Native TLS] Bypassing certificate verification');
                }
                return SSL_VERIFY_OK;
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
            log(`[+] Patched ${customVerifyAddrs.length} ${targetName} verification methods`);
        }
        log(`== Hooked native TLS lib ${targetName} ==`);
    } else {
        log(`\n !!! Hooking native TLS lib ${targetName} failed - no verification methods found`);
    }

    const get_psk_identity_addr = targetModule.findExportByName("SSL_get_psk_identity");
    if (get_psk_identity_addr) {
        // Hooking this is apparently required for some verification paths which check the
        // result is not 0x0. Any return value should work fine though.
        Interceptor.replace(get_psk_identity_addr, new NativeCallback(function(ssl) {
            return "PSK_IDENTITY_PLACEHOLDER";
        }, 'pointer', ['pointer']));
    } else if (customVerifyAddrs.length) {
        log(`Patched ${customVerifyAddrs.length} custom_verify methods, but couldn't find get_psk_identity`);
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
            if (DEBUG_MODE) log(`Ignoring attempt to clear ${property} system property`);
            return this.getProperty(property);
        }
        return this.clearProperty(...arguments);
    }
    Java.use('java.lang.System').setProperty.implementation = function (property) {
        if (controlledSystemProperties.includes(property)) {
            if (DEBUG_MODE) log(`Ignoring attempt to override ${property} system property`);
            return this.getProperty(property);
        }
        return this.setProperty(...arguments);
    }

    // Configure the app's proxy directly, via the app connectivity manager service:
    const ConnectivityManager = Java.use('android.net.ConnectivityManager');
    const ProxyInfo = Java.use('android.net.ProxyInfo');
    ConnectivityManager.getDefaultProxy.implementation = () => ProxyInfo.$new(PROXY_HOST, PROXY_PORT, '');
    // (Not clear if this works 100% - implying there are ConnectivityManager subclasses handling this)

    log(`== Proxy system configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);

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
            log('Rewriting', ProxySelectorCls.toString());
        }
        ProxySelectorCls.select.implementation = () => getTargetProxyList()
    });

    log(`== Proxy configuration overridden to ${PROXY_HOST}:${PROXY_PORT} ==`);
});

// ============================================================================
// Android Certificate injection - TRUST ALL APPROACH
// Injects the proxy CA certificate AND accepts all certificates
// This is needed for:
// 1. WebView compatibility (needs the CA in TrustedCertificateIndex)
// 2. mitmproxy compatibility (doesn't inject CA into response chain)
// ============================================================================

// Helper function to build X509Certificate from PEM bytes
function buildX509CertificateFromBytes(certBytes) {
    const ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
    const CertFactory = Java.use('java.security.cert.CertificateFactory');
    const certFactory = CertFactory.getInstance("X.509");
    return certFactory.generateCertificate(ByteArrayInputStream.$new(certBytes));
}

Java.perform(() => {
    // Build our trusted CA certificate from CERT_PEM
    let trustedCACert = null;
    try {
        if (typeof CERT_PEM !== 'undefined' && CERT_PEM && CERT_PEM.trim().length > 0) {
            const certBytes = Java.use("java.lang.String").$new(CERT_PEM).getBytes();
            trustedCACert = buildX509CertificateFromBytes(certBytes);
            log('[+] Built X509Certificate from CERT_PEM');
        } else {
            logWarn('[ ] CERT_PEM not defined or empty - certificate injection disabled');
        }
    } catch (e) {
        logWarn(`[ ] Failed to build X509Certificate from CERT_PEM: ${e}`);
    }

    // Hook TrustedCertificateIndex classes
    [
        'com.android.org.conscrypt.TrustedCertificateIndex',
        'org.conscrypt.TrustedCertificateIndex',
        'org.apache.harmony.xnet.provider.jsse.TrustedCertificateIndex'
    ].forEach((TrustedCertificateIndexClassname, i) => {
        let TrustedCertificateIndex;
        try {
            TrustedCertificateIndex = Java.use(TrustedCertificateIndexClassname);
        } catch (e) {
            if (i === 0) {
                // First one is required on modern Android
                logWarn(`${TrustedCertificateIndexClassname} not found - certificate injection may not work`);
            }
            return;
        }

        // Method 1: Inject our CA certificate into the index
        // This is needed for WebView to find our CA when validating
        if (trustedCACert) {
            try {
                // Hook the 'index' method to also add our certificate
                const indexMethod = TrustedCertificateIndex.index;
                if (indexMethod) {
                    indexMethod.implementation = function (cert) {
                        // Call original to add the provided cert
                        this.index(cert);
                        // Also inject our trusted CA
                        try {
                            this.index(trustedCACert);
                        } catch (e) {
                            // May already be indexed, ignore
                        }
                    };
                }
            } catch (e) {
                if (DEBUG_MODE) log(`Could not hook index method: ${e}`);
            }
        }

        // Method 2: Hook findBySubjectAndPublicKey - TRUST ALL
        try {
            TrustedCertificateIndex.findBySubjectAndPublicKey.implementation = function (cert) {
                // Always return the cert itself as trusted
                if (DEBUG_MODE) log('[TrustedCertificateIndex] Trust-all: accepting cert');
                return cert;
            };
        } catch (e) {
            if (DEBUG_MODE) log(`Could not hook findBySubjectAndPublicKey: ${e}`);
        }

        // Method 3: Hook findByIssuerAndSignature - TRUST ALL
        try {
            TrustedCertificateIndex.findByIssuerAndSignature.implementation = function (cert) {
                // Always return the cert itself as trusted
                if (DEBUG_MODE) log('[TrustedCertificateIndex] Trust-all: accepting cert for issuer check');
                return cert;
            };
        } catch (e) {
            if (DEBUG_MODE) log(`Could not hook findByIssuerAndSignature: ${e}`);
        }

        // Method 4: Hook findAllByIssuerAndSignature for WebView which may use this
        try {
            const findAllMethod = TrustedCertificateIndex.findAllByIssuerAndSignature;
            if (findAllMethod) {
                findAllMethod.implementation = function (cert) {
                    const Set = Java.use('java.util.HashSet');
                    const resultSet = Set.$new();
                    
                    // Add our trusted CA if we have one
                    if (trustedCACert) {
                        try {
                            resultSet.add(trustedCACert);
                        } catch (e) {}
                    }
                    
                    // Also add the cert itself (trust-all)
                    try {
                        resultSet.add(cert);
                    } catch (e) {}
                    
                    if (DEBUG_MODE) log('[TrustedCertificateIndex] findAllByIssuerAndSignature returning set');
                    return resultSet;
                };
            }
        } catch (e) {
            if (DEBUG_MODE) log(`Could not hook findAllByIssuerAndSignature: ${e}`);
        }

        if (trustedCACert) {
            log(`[+] Injected cert into ${TrustedCertificateIndexClassname}`);
        } else {
            log(`[+] Patched ${TrustedCertificateIndexClassname} (trust-all mode)`);
        }
    });

    log('== System certificate trust modified (CA injected + trust-all) ==');
});

// Bypass SSL pinning - MODIFIED: Accept all certificates
// Some standard hook replacements for various cases:
const NO_OP = () => {};
const RETURN_TRUE = () => true;

// MODIFIED: Accept all certificates without verification
const TRUST_ALL_CERTS = () => {
    return (_certs, _authType) => {
        // Do nothing - accept all certificates
        if (DEBUG_MODE) {
            log('[TrustManager] Accepting all certificates');
        }
    };
};

// MODIFIED: Return empty list for extended trust manager (accepts all)
const TRUST_ALL_CERTS_EXTENDED = () => {
    return (certs, _authType, _hostname) => {
        if (DEBUG_MODE) {
            log('[TrustManager Extended] Accepting all certificates');
        }
        return Java.use('java.util.Arrays').asList(certs);
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

    // --- Native SSLContext - MODIFIED: Use trust-all trust manager

    'javax.net.ssl.SSLContext': [
        {
            methodName: 'init',
            overload: ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'],
            replacement: (targetMethod) => {
                // Create a TrustManager that trusts all certificates
                const TrustAllManager = Java.registerClass({
                    name: 'com.frida.TrustAllManager',
                    implements: [Java.use('javax.net.ssl.X509TrustManager')],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                });

                return function (keyManager, _providedTrustManagers, secureRandom) {
                    const trustAllArray = Java.array('javax.net.ssl.TrustManager', [TrustAllManager.$new()]);
                    return targetMethod.call(this, keyManager, trustAllArray, secureRandom);
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

    // --- Native HostnameVerification override - MODIFIED: Always return true

    'com.android.okhttp.internal.tls.OkHostnameVerifier': [
        {
            methodName: 'verify',
            overload: [
                'java.lang.String',
                'javax.net.ssl.SSLSession'
            ],
            replacement: () => RETURN_TRUE
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
            replacement: TRUST_ALL_CERTS
        }
    ],

    // --- Appcelerator (https://github.com/tidev/appcelerator.https)

    'appcelerator.https.PinningTrustManager': [
        {
            methodName: 'checkServerTrusted',
            replacement: TRUST_ALL_CERTS
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
            replacement: TRUST_ALL_CERTS,
            methodName: 'checkServerTrusted',
            overload: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
            replacement: TRUST_ALL_CERTS_EXTENDED
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
    if (DEBUG_MODE) log('\n    === Disabling all recognized unpinning libraries ===');

    const classesToPatch = Object.keys(PINNING_FIXES);

    classesToPatch.forEach((targetClassName) => {
        const TargetClass = getJavaClassIfExists(targetClassName);
        if (!TargetClass) {
            // We skip patches for any classes that don't seem to be present. This is common
            // as not all libraries we handle are necessarily used.
            if (DEBUG_MODE) log(`[ ] ${targetClassName} *`);
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
                if (DEBUG_MODE) log(`[ ] ${targetClassName} ${methodDescription}`);
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
                            log(` => ${patchName}`);
                            return newImplementation.apply(this, arguments);
                        }
                    } else {
                        targetMethod.implementation = newImplementation;
                    }

                    if (DEBUG_MODE) log(`[+] ${patchName}`);
                    patchApplied = true;
                } catch (e) {
                    // In theory, errors like this should never happen - it means the patch is broken
                    // (e.g. some dynamic patch building fails completely)
                    logErr(`[!] ERROR: ${patchName} failed: ${e}`);
                }
            })
        });

        if (!patchApplied) {
            logWarn(`[!] Matched class ${targetClassName} but could not patch any methods`);
        }
    });

    log('== Certificate unpinning completed ==');
});

// Android SSL unpinning fallback - MODIFIED: Accept all certificates
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
                    log('\n !!! --- Unexpected TLS failure --- !!!');

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
                    log(`      ${errorTypeName}: ${errorMessage}`);
                    log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    callingMethod.overloads.forEach((failingMethod) => {
                        if (failingMethod.implementation) {
                            logWarn('      Already patched - but still failing!')
                            return; // Already patched by Frida - skip it
                        }

                        // Try to spot known methods (despite obfuscation) and disable them:
                        if (isOkHttpCheckMethod(errorMessage, failingMethod)) {
                            // See okhttp3.CertificatePinner patches in unpinning script:
                            failingMethod.implementation = () => {
                                if (DEBUG_MODE) log(` => Fallback OkHttp patch`);
                            };
                            log(`      [+] ${className}->${methodName} (fallback OkHttp patch)`);
                        } else if (isAppmattusOkHttpInterceptMethod(errorMessage, failingMethod)) {
                            // See Appmattus CertificateTransparencyInterceptor patch in unpinning script:
                            const chainType = Java.use(failingMethod.argumentTypes[0].className);
                            const responseTypeName = failingMethod.returnType.className;
                            const okHttpChain = matchOkHttpChain(chainType, responseTypeName);
                            failingMethod.implementation = (chain) => {
                                if (DEBUG_MODE) log(` => Fallback Appmattus+OkHttp patch`);
                                const proceed = chain[okHttpChain.proceedMethodName].bind(chain);
                                const request = chain[okHttpChain.requestFieldName].value;
                                return proceed(request);
                            };
                            log(`      [+] ${className}->${methodName} (fallback Appmattus+OkHttp patch)`);
                        } else if (isX509TrustManager(callingClass, methodName)) {
                            const argumentTypes = failingMethod.argumentTypes.map(t => t.className);
                            const returnType = failingMethod.returnType.className;

                            if (
                                argumentTypes.length === 2 &&
                                argumentTypes.every((t, i) => t === BASE_METHOD_ARGUMENTS[i]) &&
                                returnType === 'void'
                            ) {
                                // MODIFIED: Just accept everything
                                failingMethod.implementation = (_certs, _authType) => {
                                    if (DEBUG_MODE) log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } base method - accepting all`);
                                };
                                log(`      [+] ${className}->${methodName} (fallback X509TrustManager base patch - trust all)`);
                            } else if (
                                argumentTypes.length === 3 &&
                                argumentTypes.every((t, i) => t === EXTENDED_METHOD_ARGUMENTS[i]) &&
                                returnType === 'java.util.List'
                            ) {
                                // MODIFIED: Accept everything and return the certs
                                failingMethod.implementation = function (certs, _authType, _hostname) {
                                    if (DEBUG_MODE) log(` => Fallback X509TrustManager patch of ${
                                        className
                                    } extended method - accepting all`);
                                    return Java.use('java.util.Arrays').asList(certs);
                                };
                                log(`      [+] ${className}->${methodName} (fallback X509TrustManager ext patch - trust all)`);
                            } else {
                                logWarn(`      [ ] Skipping unrecognized checkServerTrusted signature in class ${
                                    callingClass.class.getName()
                                }`);
                            }
                        } else if (isMetaPinningMethod(errorMessage, failingMethod)) {
                            // MODIFIED: Accept all certificates
                            failingMethod.implementation = function (_certs) {
                                if (DEBUG_MODE) log(` => Fallback patch for meta proxygen pinning - accepting all`);
                                return; // Accept everything
                            }

                            log(`      [+] ${className}->${methodName} (Meta proxygen pinning fallback patch - trust all)`);
                        } else {
                            logErr('      [ ] Unrecognized TLS error - this must be patched manually');
                            return;
                            // Later we could try to cover other cases here - automatically recognizing other
                            // OkHttp interceptors for example, or potentially other approaches, but we need
                            // to do so carefully to avoid disabling TLS checks entirely.
                        }
                    });
                } catch (e) {
                    log('      [ ] Failed to automatically patch failure');
                    logWarn(e);
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

        log('== Unpinning fallback auto-patcher installed ==');
    } catch (err) {
        logErr(err);
        logErr(' !!! --- Unpinning fallback auto-patcher installation failed --- !!!');
    }

});
