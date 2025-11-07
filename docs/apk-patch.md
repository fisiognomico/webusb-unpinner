# Internals: APK Patching & Binary Manifest Modification

## Overview

APK patching modifies an Android app to enable the `debuggable` flag, allowing us to attach a debugger and inject Frida. The process involves binary manipulation of the AndroidManifest.xml file embedded in the APK.

---

## Why Patch the Manifest?

```
Original App:
  ├── AndroidManifest.xml
  │   └── <application android:debuggable="false">  ← NO debugging
  └── (other files)

Patched App:
  ├── AndroidManifest.xml
  │   └── <application android:debuggable="true">   ← YES debugging allowed
  └── (other files)
```

**Effect**: App can now be debugged via JDWP, allowing gadget injection.

---

## Challenge: Binary XML Format

Android APKs don't store AndroidManifest.xml as plain text. Instead:

```
Plain Text XML (what we want to write):
  <?xml version="1.0" encoding="UTF-8"?>
  <manifest>
    <application android:debuggable="true">
    </application>
  </manifest>

Binary XML (what's actually in the APK):
  [00 08 00 03] [08 00 AC 00]  [00 00 00 00]  ...
  ↑            ↑              ↑
  Header       STRING_POOL    RESOURCE_MAP
  (magic)      chunk          chunk
```

**Problem**: We must modify binary data, not text.

---

## APK File Structure

```
APK (which is a ZIP file)
  │
  ├── AndroidManifest.xml       ← Binary XML file (what we modify)
  ├── classes.dex               ← Compiled Java code
  ├── resources.arsc            ← Resources
  ├── lib/
  │   └── armeabi-v7a/
  │       └── libnative.so       ← Native libraries
  ├── res/
  │   └── (resource directories)
  └── META-INF/
      ├── MANIFEST.MF           ← v1 signatures
      ├── CERT.SF
      └── CERT.RSA
```

**Our workflow**:
1. Extract APK (it's just ZIP)
2. Decompress AndroidManifest.xml
3. Modify binary XML
4. Recompress and put back
5. Re-sign entire APK (old signatures now invalid)

---

## Binary XML Structure

The AndroidManifest.xml contains multiple "chunks":

```
┌─────────────────────────────────────────────────────────┐
│  Binary XML File Header                                 │
│  [Magic: 0x00080003] [File size]                        │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  STRING_POOL Chunk (0x001)                              │
│  ┌─────────────────────────────────────────────────────┐│
│  │ "application", "debuggable", "android", etc.        ││
│  │ (All strings used in the XML)                       ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  RESOURCE_MAP Chunk (0x180)                             │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Maps string indices to Android resource IDs         ││
│  │ [String 0 → 0x0101000f]  (android:debuggable)      ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  START_ELEMENT Chunks (0x102)                           │
│  ┌─────────────────────────────────────────────────────┐│
│  │ <manifest> element                                  ││
│  └─────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────┐│
│  │ <application> element ← THIS ONE WE MODIFY          ││
│  │   Attributes: name, icon, label, ...                ││
│  │   (debuggable attribute NOT present yet)            ││
│  └─────────────────────────────────────────────────────┘│
│  ... more elements ...                                  │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  END_ELEMENT Chunks (0x103)                             │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Marks end of <application>, <manifest>, etc.        ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

---

## Patching Process (Step-by-Step)

### Phase 1: Parse Binary XML

```typescript
const parser = new BinaryXmlParser(manifestBuffer);
const debuggableApk = parser.enableDebuggable();
```

**What happens**:
1. Read file header (magic number, validate)
2. Scan through chunks
3. Locate STRING_POOL, RESOURCE_MAP, START_ELEMENT chunks
4. Parse them into data structures

---

### Phase 2: Add "debuggable" String to STRING_POOL

**Current STRING_POOL**:
```
Index 0: "android"
Index 1: "manifest"
Index 2: "application"
Index 3: "name"
... (other strings)
```

**After modification**:
```
Index 0: "android"
Index 1: "manifest"
Index 2: "application"
Index 3: "name"
... (other strings)
Index N: "debuggable"  ← NEW
```

**Implementation** (apk-patcher.ts):
```typescript
const stringPool = new StringPoolChunk(chunkData);
const debuggableIndex = stringPool.append_str('debuggable');
// debuggableIndex = N (e.g., 42)
```

**Why**:
- AndroidManifest uses indices instead of literal strings
- Need index to reference "debuggable" in attributes
- append_str() handles UTF-8/UTF-16 encoding

**Storage format**:
```
STRING_POOL chunk before:  [header][offsets...][strings...]
                                    ↑            ↑
                                    14 offsets   string data

After adding "debuggable":
STRING_POOL chunk after:   [header][offsets...][old strings...][new string...]
                                    ↑            ↑
                                    15 offsets   includes "debuggable"
```

---

### Phase 3: Add Debuggable to RESOURCE_MAP

**Current RESOURCE_MAP**:
```
Index 0: 0x0101000e  (some resource)
Index 1: 0x0101000f  (some other resource)
... (Android resource IDs for each string that needs one)
```

**After modification**:
```
Index 0: 0x0101000e
Index 1: 0x0101000f
... (existing entries)
Index N: 0x0101000f  ← Resource ID for "debuggable" (index N)
```

**Implementation**:
```typescript
const resourceMap = new ResourceMapChunk(chunkData);
resourceMap.add_debuggable(debuggableIndex);  // debuggableIndex = N
```

**Resource ID Explained**:
- `0x0101000f` is Android's official resource ID for `android:debuggable`
- RESOURCE_MAP must have entry at position N with this ID
- This tells XML parser: "string at index N is a boolean Android attribute"

---

### Phase 4: Find <application> Tag

```typescript
const applicationTagOffset = parser.findApplicationTagOffset();
```

**What this does**:
- Scans through START_ELEMENT chunks
- Finds the one where element name = "application"
- Returns its byte offset in file
- Returns null if not found (error)

**Why**: Need to know where to insert the new attribute

---

### Phase 5: Insert Debuggable Attribute into <application>

**Before**:
```
<application> element:
  - Namespace: 0x0101 (Android namespace)
  - Name: 2 (application string)
  - Attributes (20 bytes each):
    - Attr 1: name="android:label", value="@string/app_name"
    - Attr 2: name="android:icon", value="@drawable/icon"
    - (NO debuggable attribute)
```

**After**:
```
<application> element:
  - Namespace: 0x0101 (Android namespace)
  - Name: 2 (application string)
  - Attributes (20 bytes each):
    - Attr 1: name="android:label", value="@string/app_name"
    - Attr 2: name="android:icon", value="@drawable/icon"
    - Attr 3: name="android:debuggable", value=true  ← NEW (20 bytes)
    (Attributes are sorted by resource ID)
```

**Attribute Structure** (20 bytes):
```
Offset  Size  Field              Value (for debuggable)
────────────────────────────────────────────────────
0       4     namespace_uri_idx  0x0101 (Android namespace)
4       4     name_idx           N (index of "debuggable" string)
8       4     raw_value          0xffffffff (no raw value)
12      2     size               8 (8 bytes for data)
14      1     reserved           0x00
15      1     type               0x12 (BOOL type)
16      4     data               0xffffffff (-1 = TRUE in Android)
```

**Insertion Logic** (apk-patcher.ts):
```typescript
// Attributes must be sorted by resource ID
// Find insertion point such that:
//   resourceID[attr_i-1] < 0x0101000f <= resourceID[attr_i]

const DEBUGGABLE_RESOURCE_ID = 0x0101000f;
let insertPos = HEADER_SIZE;

for (let i = 0; i < attributeCount; i++) {
  const attrOffset = HEADER_SIZE + i * ATTRIBUTE_SIZE;
  const nameStringIndex = getUint32(attrOffset + 4);
  const existingResourceId = resourceMap.get_resource_id(nameStringIndex);

  if (existingResourceId > DEBUGGABLE_RESOURCE_ID) {
    break;  // Insert here
  }

  insertPos += ATTRIBUTE_SIZE;  // Move past this attribute
}

// Insert new attribute at insertPos
insertAttribute(insertPos, newDebugAttribute);
```

**Why sorted?**: Android XML parser expects sorted resource IDs for efficiency.

---

### Phase 6: Reconstruct Binary XML

After modifications, file structure changed:
- STRING_POOL grew (added "debuggable")
- RESOURCE_MAP grew (added entry)
- START_ELEMENT grew (added attribute)
- All offsets need updating

**Reconstruction logic**:
```
1. File header (8 bytes) - stays same

2. STRING_POOL chunk
   - Updated size (grew by ~28 bytes)
   - Updated string count (N → N+1)
   - Updated offsets for new string

3. RESOURCE_MAP chunk
   - Updated size (grew by 4 bytes)
   - New entry at position N

4. START_ELEMENT(<application>) chunk
   - Updated size (grew by 20 bytes)
   - Updated attribute count (M → M+1)
   - New attribute inserted

5. Remaining chunks (unchanged)

6. File header now has NEW total size
```

---

## Full Patching Workflow

```
User selects APK
        ↓
Extract APK (JSZip)
        ↓
Get AndroidManifest.xml (binary)
        ↓
Parse binary XML into chunks
        ↓
Modify:
  ├─ STRING_POOL: add "debuggable" string
  ├─ RESOURCE_MAP: add resource ID entry
  └─ START_ELEMENT: insert attribute
        ↓
Reconstruct binary XML
        ↓
Put modified manifest back in APK
        ↓
Re-sign APK (v2 signature)
        ↓
Install on device
```

---

## Data Structures Used

### Chunk Header
```typescript
{
  type: number,           // 0x001 (STRING_POOL), 0x180 (RESOURCE_MAP), etc.
  headerSize: number,     // Size of header itself (usually 0x08)
  chunkSize: number       // Total chunk size including data
}
```

### String Pool Entry
```typescript
{
  type: 0x001,
  characterCount: number,  // Number of strings
  bytesPerChar: number,    // 1 (UTF-8) or 2 (UTF-16)
  offset: number,          // Where string data starts
  // ... more fields
  strings: string[]        // The actual strings
}
```

### Attribute
```typescript
{
  namespaceUri: number,    // Namespace (0x0101 = Android)
  name: number,            // String index (e.g., 42 for "debuggable")
  rawValue: number,        // Raw value (usually 0xffffffff)
  size: number,            // 8 (standard)
  type: number,            // 0x12 (BOOL)
  data: number             // -1 (TRUE), 0 (FALSE)
}
```

---

## Error Handling

### Potential Issues

1. **Unsupported XML Structure**
   - Some apps use custom XML modifications
   - Binary XML parser can't handle all variants

2. **Buffer Overflows**
   - Malformed offset tables
   - Invalid chunk sizes
   - Circular references in string pool

3. **Encoding Issues**
   - UTF-8 vs UTF-16 mismatch
   - Multi-byte string length encoding (only single-byte supported)
   - Invalid UTF sequences

4. **Missing Elements**
   - <application> tag not found
   - No existing attributes to determine namespace

### Mitigation

```typescript
// Validate before patching
try {
  const parser = new BinaryXmlParser(manifestBuffer);
  const modified = parser.enableDebuggable();

  if (!modified || modified.length === 0) {
    throw new Error('Patching produced empty result');
  }

  return modified;
} catch (error) {
  throw new Error(`Failed to modify manifest: ${error.message}`);
}
```

---

## Re-signing the APK

After modifying manifest, signatures are invalid and must be regenerated:

**WebUSB Unpinner uses APK v2 signing** (android-package-signer):
- Modern signature scheme
- Single signature covers entire ZIP
- More efficient than v1 signing

---

## Size Impact

Typical size changes:

```
Original AndroidManifest.xml: ~4,500 bytes
Additions:
  + "debuggable" string: ~15 bytes
  + String pool entry: ~4 bytes
  + Resource map entry: ~4 bytes
  + Attribute structure: ~20 bytes
  + Offsets & padding: ~10 bytes
Modified AndroidManifest.xml: ~4,553 bytes

APK size increase: ~50 bytes (negligible for most apps)
```

---

## Limitations

### What We Can't Do

1. **Modify system apps**
   - System apps have different signing
   - Can't get write access to /system/app/
   - Require device root or OTA method

2. **Handle all binary XML variants**
   - Some custom XML modifications
   - Some compression methods
   - Obfuscation patterns

3. **Preserve all metadata**
   - V1 signature is dropped (intentionally)
   - Some XML comments/processing instructions ignored
   - Non-standard XML extensions may be lost

---

## Code References

- **apk-patcher.ts**: Main patching logic
  - `BinaryXmlParser`: Parse binary XML
  - `StringPoolChunk`: Handle string pool
  - `ResourceMapChunk`: Handle resource mapping
  - `StartElementChunk`: Handle XML elements

- **signer.ts**: APK signing
  - Uses `android-package-signer` library
  - Implements v2 signature scheme

- **index.ts**: High-level workflow
  - Calls APK patcher
  - Calls signer
  - Passes to device for installation

---

## Debug Aids

To debug patching issues, check:

```bash
# 1. Original manifest
unzip original.apk AndroidManifest.xml
hexdump -C AndroidManifest.xml | head -50

# 2. Is debuggable already present?
grep -a "debuggable" AndroidManifest.xml || echo "Not found"

# 3. aapt2 parsing
aapt2 dump badging base.apk | grep debug

# 4. Check modified APK
unzip patched.apk AndroidManifest.xml
hexdump -C AndroidManifest.xml | head -50
# Compare: offsets should be different, size slightly larger
```

---

## Security Note

The patching process is **non-destructive** to the APK's security model:
- Only adds one attribute (debuggable)
- Doesn't remove encryption or compression
- Doesn't extract/expose internal data
- Just makes the app debuggable (which is the point)

After patching, the app is functionally identical except:
```
Before: Cannot attach debugger
After:  Can attach debugger + inject Frida
```


## Acknowledgments

The technique outlined in this document has been implemented by [frida tools](https://github.com/frida/frida-tools/blob/main/frida_tools/apk.py).
