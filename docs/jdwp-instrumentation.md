# Internals: JDWP Instrumentation & Frida Gadget Injection

## Overview

JDWP (Java Debug Wire Protocol) is used to inject Frida gadgets into Android apps at runtime. The process exploits the debuggable flag to attach a debugger, then uses the debugger connection to execute arbitrary code and load the Frida gadget library.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Chromium Browser                        │
│                                                             │
│  1. App in debug mode                                       │
│  2. JDWP connection established                             │
│  3. Breakpoint set on Activity.onCreate()                   │
│  4. App starts, hits breakpoint (suspended)                 │
│  5. Execute JDWP commands while suspended                   │
│  6. Load Frida gadget library                               │
│  7. Resume app execution                                    │
└─────────────────────────────────────────────────────────────┘
                            ↓ (WebUSB/ADB)
┌─────────────────────────────────────────────────────────────┐
│                    Android Device                           │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Target App (e.g., com.example.app)                  │   │
│  │                                                      │   │
│  │  1. Started in debug mode (am start -D)              │   │
│  │  2. JDWP listener accepts debugger connection        │   │
│  │  3. Activity.onCreate() breakpoint hit               │   │
│  │  4. Thread suspended (waiting for debugger)          │   │
│  │  5. Receive command: copy /data/local/tmp/* files    │   │
│  │  6. Receive command: load libgadget.so               │   │
│  │  7. Gadget initializes, opens Frida port             │   │
│  │  8. Thread resumed, app continues                    │   │
│  │  9. Frida now injected and running                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Process

### Phase 1: Setup (jdwp.ts → initFridaGadget())

#### 1.1 Create Debug Manager

```typescript
const config: WebUSBConfig = {
  type: "web",
  serverClient: state.connection!,    // ADB connection
  deviceSerial: state.device!.serial!,
  adb: state.client!
};
const debugManager = new DebugManager<WebUSBConfig>(config);
```

**What happens**:
- Debug manager wraps ADB connection
- Prepares to send JDWP commands over ADB

---

#### 1.2 Enable Debug Mode for App

```typescript
const setPackageDebugMode = `am set-debug-app -w ${targetApp}`;
await debugManager.executeCommand(setPackageDebugMode);
```

**Result**: System marks the app as debuggable for this session

```
Before: com.example.app (not debuggable)
After:  com.example.app (debuggable, awaiting debugger)
```

---

#### 1.3 Find Main Activity

```typescript
const findMainActivity = `cmd package resolve-activity --brief ${targetApp}`;
const lines = await debugManager.executeCommand(findMainActivity);
const mainActivity = lines[1].trim();  // e.g., "com.example.app/.MainActivity"
```

**Why needed**: Must know which Activity to start and where to set breakpoint

---

### Phase 2: Start App in Debug Mode

#### 2.1 Start App with Debug Flag

```typescript
const spawnActivity = `am start -n ${mainActivity}`;
await debugManager.executeCommand(spawnActivity);
```

**Result**: App starts and waits for debugger to connect

```
Device: App process created
        JDWP listener starts
        Waits for debugger connection...
```

---

#### 2.2 Wait for App Process

```typescript
const appPid = await debugManager.findAppPid(targetApp);
console.log(`${targetApp} started (PID: ${appPid})`);
```

**Why**: Need process ID to establish JDWP connection

---

### Phase 3: JDWP Connection & Breakpoint

#### 3.1 Establish JDWP Connection

```typescript
const debugSession = await debugManager.startDebugging(targetApp, appPid);
```

**Result**:
```
Browser → ADB → Device
                 ↓
            [JDWP HandShake]
                 ↓
         Connection established
         Debugger can now control app
```

---

#### 3.2 Set Breakpoint on Activity.onCreate()

```typescript
const activityClass = "Landroid/app/Activity;";
const createMethod = "onCreate";
const {requestId, threadId} = await debugSession.client.setBreakpointAndWait(
    activityClass,
    createMethod
);
```

**What this does**:
1. Tells JDWP debugger to pause when ANY Activity.onCreate() is called
2. Our target activity's MainActivity extends Activity
3. onCreate() is called during app startup
4. App suspends at this point

```
Timeline:
  T=0s: App started
  T=0.5s: Activity class loaded, onCreate() called
  T=0.6s: Breakpoint triggered → Thread suspended ⏸️
  T=0.7s: We can now execute commands on suspended thread
  T=2.0s: We resume thread → App continues normally ▶️
```

---

### Phase 4: Execute Commands While Suspended

The key insight: **While the app is paused at the breakpoint, we can execute shell commands with the app's permissions and context.**

```
App paused at breakpoint
        ↓
    We have access to:
        ✓ App's file permissions
        ✓ App's /data/data/<package>/ directory
        ✓ App's process memory and context
        ✓ Ability to execute shell commands as app user
```

#### 4.1 Copy Frida Gadget Files

```typescript
// Check if gadget exists
const exitCode1 = await debugManager.executeJDWP(
    appPid,
    'ls -la /data/local/tmp/libgadget.so'
);

// Copy gadget to app data directory (where app can load it)
const exitCode2 = await debugManager.executeJDWP(
    appPid,
    `cp /data/local/tmp/libgadget.so /data/data/${targetApp}/libgadget.so`
);

// Same for config file
const exitCode3 = await debugManager.executeJDWP(
    appPid,
    `ls /data/local/tmp/libgadget.config.so`
);

const exitCode4 = await debugManager.executeJDWP(
    appPid,
    `cp /data/local/tmp/libgadget.config.so /data/data/${targetApp}/libgadget.config.so`
);
```

**File Layout**:
```
Before:
  /data/local/tmp/
    ├── libgadget.so           ← Uploaded by WebUSB Unpinner
    └── libgadget.config.so    ← Uploaded by WebUSB Unpinner

  /data/data/com.example.app/
    └── (empty)

After:
  /data/local/tmp/            ← Still there
    ├── libgadget.so
    └── libgadget.config.so

  /data/data/com.example.app/  ← Now app can load from here
    ├── libgadget.so
    └── libgadget.config.so
```

---

#### 4.2 Load Frida Gadget Library

```typescript
await debugManager.loadLibraryJDWP(
    appPid,
    `/data/data/${targetApp}/libgadget.so`
);
```

**What happens internally**:
1. JDWP command to call `System.load(path)` in app context
2. Android runtime loads the .so file (native library)
3. .so file's JNI_OnLoad() is called
4. Frida gadget initializes

```
Java code being executed:
    System.load("/data/data/com.example.app/libgadget.so");
    ↓
Android Runtime:
    - Loads .so file
    - Calls JNI_OnLoad() in gadget
    ↓
Frida Gadget:
    - Initializes
    - Reads config from libgadget.config.so
    - Loads scripts from /data/local/tmp/scripts/
```

---

### Phase 5: Resume Execution

```typescript
try {
    // ... all the commands above ...
} finally {
    await debugSession.client.resumeVM();
    console.log('✅ Thread resumed, app continues');
}
```

**Result**: 
- Breakpoint is removed
- Thread resumes execution
- App runs normally (but with Frida gadget loaded)
- Frida is now listening for connections from tools like HTTP Toolkit

---

## Why This Works

### The JDWP Protocol Advantage

JDWP allows a debugger to:
1. **Pause app execution** at any point
2. **Read/write memory** while paused
3. **Execute arbitrary code** in the app's context
4. **Resume** without leaving traces

### Why We Need Breakpoint-Based Injection

**Problem**: Can't just inject Frida into running app
**Solution**: Start app in debug mode, pause it early, inject while paused

```
Timeline of Instrumentation:

T=0ms:   App process created, JDWP listener ready
         ↓
T=1ms:   Debugger connects
         ↓
T=2ms:   MainActivity.onCreate() called
         ↓
T=3ms:   Breakpoint hit → App pauses ⏸️
         ↓
T=10ms:  Copy Frida gadget files
T=20ms:  Load Frida gadget library
T=100ms: Resume app ▶️
         ↓
T=101ms: App continues execution (now with Frida)
         ↓
T=102ms: Frida fully initialized and listening
```

---

## Configuration (libgadget.config.so)

The Frida gadget config file tells it where to find scripts:

```json
{
  "interaction": {
    "type": "script-directory",
    "path": "/data/local/tmp/scripts",
    "on_change": "reload"
  }
}
```

**What this means**:
- Load all .js files from `/data/local/tmp/scripts/`
- If scripts change (new files added), reload them
- Scripts run with Frida's full JavaScript API access

**Example scripts loaded**:
- `hide-debugger.js` - Hide the debuggable flag from the app
- `httptoolkit-unpinner.js` - Certificate unpinning

---

## Error Handling

### What Can Go Wrong

1. **Breakpoint never hit**
   - Activity not found
   - Process crashes before onCreate()
   - Wrong class name

2. **Files not copied**
   - Permission denied on /data/data/
   - /data/local/tmp/ files not present
   - Out of disk space

3. **Gadget fails to load**
   - Wrong architecture (ARM vs ARM64)
   - Corrupted .so file
   - Invalid config file

4. **Frida not initializing**
   - Port already in use
   - Config file not found
   - Bad script syntax

---

## Related Code

- **jdwp.ts**: Main instrumentation logic
- **libjdwp**: Handles low-level JDWP protocol
- **libgadget.so**: Frida gadget binary (compiled, not in repo)
- **libgadget.config.so**: Configuration file
- **static/scripts/**: Frida scripts injected into app

---

## Security Implications

### What Frida Can Access

Once loaded, Frida can:
- ✅ Hook any Java method
- ✅ Inspect/modify object state
- ✅ Call Java methods
- ✅ Hook native functions
- ✅ Modify TLS verification
- ✅ Intercept encryption/decryption

### Why This Requires Debuggable Flag

- Debuggable apps can be debugged → JDWP server starts
- Non-debuggable apps → JDWP server is disabled
- This is an intentional Android security feature
- WebUSB unpinner patches APKs to enable debuggable flag

---

## Limitations & Caveats

1. **Only works before app fully starts**
   - Must inject at onCreate()
   - Some logic runs before onCreate()
   - Can miss early initialization

2. **Frida scripts have limitations**
   - Can't access file system directly
   - Can't make raw network requests (must go through app)
   - Some obfuscated code is hard to hook

3. **App crash behavior**
   - If Frida gadget has error, app crashes on load
   - No way to recover without reinstalling
   - Config errors can break app startup

4. **Multiple app instances**
   - Only the first instance gets instrumented
   - Restarting app starts fresh instance without instrumentation
   - Each instance needs separate injection

## Acknowledgments

The technique outlined in this document has been implemented by [mitmproxy
unpinner](https://github.com/mitmproxy/android-unpinner/blob/main/android_unpinner/jdwplib.py).
