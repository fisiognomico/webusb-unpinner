/**
 * CHUNK WRAPPER CLASSES - Port of Frida's approach
 * https://github.com/frida/frida-tools/blob/main/frida_tools/apk.py
 * Each chunk wraps its binary data and knows how to modify itself
 */

import BinaryXML from 'binary-xml';

class StringPoolChunk {
  private chunk_data: Uint8Array;
  private view: DataView;
  private strings: string[] = [];

  constructor(data: Uint8Array) {
    this.chunk_data = new Uint8Array(data);
    this.view = new DataView(this.chunk_data.buffer);
    this.parseStrings();
  }

  private parseStrings(): void {
    const headerSize = this.view.getUint16(2, true);
    const stringCount = this.view.getUint32(8, true);
    const stringStart = this.view.getUint32(20, true);
    const flags = this.view.getUint32(16, true);

    const isUtf16 = (flags & 0x100) === 0;
    const poolStart = stringStart;
    const offsetTableStart = headerSize;
    for (let i = 0; i < stringCount; i++) {
      try {
        const offsetTableEntry = offsetTableStart + i * 4;
        const stringOffset = this.view.getUint32(offsetTableEntry, true);
        const strOffset = poolStart + stringOffset;

        let str = '';
        if (isUtf16) {
          const len = this.view.getUint16(strOffset, true);
          const bytes = this.chunk_data.slice(strOffset + 2, strOffset + 2 + len * 2);
          str = new TextDecoder('utf-16le').decode(bytes).replace(/\0+$/, '');
        } else {
          const len = this.view.getUint16(strOffset, true);
          const byteLen = this.view.getUint16(strOffset + 2, true);
          const bytes = this.chunk_data.slice(strOffset + 4, strOffset + 4 + byteLen);
          str = new TextDecoder('utf-8').decode(bytes);
        }
        this.strings.push(str);
      } catch {
        this.strings.push('');
      }
    }
  }

  /**
   * Append a new string to the string pool
   * Supports both UTF-16 and UTF-8 encodings
   * Updates internal chunk_data, size, and count
   * Returns the new string index
   */
  append_str(str: string): number {
    const headerSize = this.view.getUint16(2, true);
    const oldChunkSize = this.view.getUint32(4, true);
    const stringCount = this.view.getUint32(8, true);
    const stringStart = this.view.getUint32(20, true);
    const flags = this.view.getUint32(16, true);
    // console.log(`String pool before: size=${this.get_size()}, count=${stringCount}`);

    const isUtf16 = (flags & 0x100) === 0;

    let lengthPrefix: Uint8Array;
    let encodedString: Uint8Array;
    let nullTerminator: Uint8Array;

    if (isUtf16) {
      // ===== UTF-16LE ENCODING =====
      // Format: 2 bytes length + UTF-16LE string + 2 bytes null terminator

      // Encode string as UTF-16LE
      const utf16Bytes = new Uint8Array(str.length * 2);
      const utf16View = new Uint16Array(utf16Bytes.buffer);
      for (let i = 0; i < str.length; i++) {
        utf16View[i] = str.charCodeAt(i);
      }

      encodedString = utf16Bytes;

      // Write length prefix (character count, little-endian)
      lengthPrefix = new Uint8Array(2);
      new DataView(lengthPrefix.buffer).setUint16(0, str.length, true);

      // 2-byte null terminator for UTF-16
      nullTerminator = new Uint8Array([0, 0]);

    } else {
      // ===== UTF-8 ENCODING =====
      // Format: 1 byte char_count + 1 byte byte_length + UTF-8 string + 1 byte null terminator

      const utf8Bytes = new TextEncoder().encode(str);

      // Check if we need multi-byte encoding (length >= 128)
      // For simplicity, only support single-byte length encoding
      if (str.length >= 128 || utf8Bytes.length >= 128) {
        throw new Error(`UTF-8 multi-byte length encoding not supported (string too long: ${str.length} chars, ${utf8Bytes.length} bytes)`);
      }

      encodedString = utf8Bytes;

      // Write length prefix (2 bytes: char count + byte length)
      lengthPrefix = new Uint8Array(2);
      lengthPrefix[0] = str.length;        // Character count
      lengthPrefix[1] = utf8Bytes.length;  // Byte length

      // 1-byte null terminator for UTF-8
      nullTerminator = new Uint8Array([0]);
    }

    // Build the complete string entry: length_prefix + encoded_string + null_terminator
    const stringEntry = new Uint8Array(
      lengthPrefix.length + encodedString.length + nullTerminator.length
    );

    let pos = 0;
    stringEntry.set(lengthPrefix, pos);
    pos += lengthPrefix.length;
    stringEntry.set(encodedString, pos);
    pos += encodedString.length;
    stringEntry.set(nullTerminator, pos);

    // Add padding to align to 4 bytes
    const paddingNeeded = (4 - (stringEntry.length % 4)) % 4;
    const paddedStringBuffer = new Uint8Array(stringEntry.length + paddingNeeded);
    paddedStringBuffer.set(stringEntry);

    const addedBytes = 4 + paddedStringBuffer.length; // 4 for new offset entry
    const newChunkSize = oldChunkSize + addedBytes;
    const newStringStart = stringStart + 4;

    // Create new buffer
    const newBuffer = new Uint8Array(this.chunk_data.length + addedBytes);
    const newView = new DataView(newBuffer.buffer);

    // Copy header
    newBuffer.set(this.chunk_data.slice(0, headerSize), 0);

    // Copy old offset table
    const oldOffsetTableEnd = headerSize + stringCount * 4;
    newBuffer.set(this.chunk_data.slice(headerSize, oldOffsetTableEnd), headerSize);

    // Copy old string data to new position
    const oldStringDataStart = stringStart;
    const oldStringDataSize = oldChunkSize - stringStart;
    const newStringDataStart = oldOffsetTableEnd + 4;
    newBuffer.set(
      this.chunk_data.slice(oldStringDataStart, oldStringDataStart + oldStringDataSize),
      newStringDataStart
    );

    // Write new offset entry
    const newOffsetValue = (newStringDataStart + oldStringDataSize) - newStringStart;
    newView.setUint32(oldOffsetTableEnd, newOffsetValue, true);

    // Append new string data (with proper length prefix and null terminator)
    newBuffer.set(paddedStringBuffer, newStringDataStart + oldStringDataSize);

    // Update chunk header
    newView.setUint32(4, newChunkSize, true);                    // chunk size
    newView.setUint32(8, stringCount + 1, true);                 // string count
    newView.setUint32(20, newStringStart, true);                 // stringStart offset

    // Update also style offset
    const oldStylesOffset = this.view.getUint32(24, true);
    if (oldStylesOffset !== 0) {
      const newStylesOffset = oldStylesOffset + 4;  // Offset increased by new offset entry
      newView.setUint32(24, newStylesOffset, true);
    }

    // console.log(`Appending "${str}" (${isUtf16 ? 'UTF-16' : 'UTF-8'}), returning string count: ${stringCount}`);
    // console.log(`String pool after: size=${newBuffer.length}, new entry offset=${newOffsetValue}`);

    this.chunk_data = newBuffer;
    this.view = new DataView(this.chunk_data.buffer);
    this.strings.push(str);

    return stringCount;
  }

  get_string(index: number): string {
    return this.strings[index] || '';
  }

  get_chunk_data(): Uint8Array {
    return this.chunk_data;
  }

  get_size(): number {
    return this.view.getUint32(4, true);
  }

  find_string_index(str: string): number {
    return this.strings.indexOf(str);
  }
}

class ResourceMapChunk {
  private chunk_data: Uint8Array;
  private view: DataView;

  constructor(data: Uint8Array) {
    this.chunk_data = new Uint8Array(data);
    this.view = new DataView(this.chunk_data.buffer);
  }

  /**
   * Get the resource ID for a given string index
   * The ResourceMap is an array of resource IDs indexed by position
   * ResourceID at offset (8 + stringIndex * 4)
   */
  get_resource_id(stringIndex: number): number {
    const headerSize = this.view.getUint16(2, true);
    const offset = headerSize + stringIndex * 4;

    if (offset + 4 > this.chunk_data.length) {
      return 0;
    }

    return this.view.getUint32(offset, true);
  }
  /**
   * Add debuggable to resource map
   * Extends the resource map with a valid debuggable entry
   */
  add_debuggable(stringIndex: number): void {
    // The resource map maps string indices to resource IDs
    // For debuggable, we use the standard Android attribute resource ID
    const DEBUGGABLE_RESOURCE_ID = 0x0101000f; // android:debuggable
    // console.log(`Resource map before: size=${this.get_size()}`);
    // console.log(`Adding resource entry at index=${stringIndex}, resourceId=0x${DEBUGGABLE_RESOURCE_ID.toString(16)}`);

    const oldChunkSize = this.view.getUint32(4, true);
    const headerSize = this.view.getUint16(2, true);

    // Each resource entry is 4 bytes (uint32 resource ID)
    const entryCount = (oldChunkSize - headerSize) / 4;
    // const newChunkSize = oldChunkSize + 4;

    // Create new buffer
    const newChunkSize = headerSize + (stringIndex + 1) * 4;
    const newBuffer = new Uint8Array(Math.max(this.chunk_data.length, newChunkSize));
    const newView = new DataView(newBuffer.buffer);

    // Copy entire old buffer
    newBuffer.set(this.chunk_data, 0);

    // Fill in the resource ID at the debuggable string index position
    const resourceIdOffset = headerSize + stringIndex * 4;
    newView.setUint32(resourceIdOffset, DEBUGGABLE_RESOURCE_ID, true);

    // Update chunk size
    newView.setUint32(4, newChunkSize, true);

    // Append new resource ID entry (sorted, so usually at the end)
    // const newEntryPos = headerSize + entryCount * 4;
    // newView.setUint32(newEntryPos, DEBUGGABLE_RESOURCE_ID, true);

    this.chunk_data = newBuffer;
    this.view = new DataView(this.chunk_data.buffer);
    // console.log(`Added resource ID 0x${DEBUGGABLE_RESOURCE_ID.toString(16)} at position ${stringIndex}`);
    // console.log(`Resource map after: size=${newBuffer.length}`);
  }

  get_chunk_data(): Uint8Array {
    return this.chunk_data;
  }

  get_size(): number {
    return this.view.getUint32(4, true);
  }
}

class StartElementChunk {
  private chunk_data: Uint8Array;
  private view: DataView;
  private namespace: number = -1;

  constructor(data: Uint8Array) {
    this.chunk_data = new Uint8Array(data);
    this.view = new DataView(this.chunk_data.buffer);
    this.parseNamespace();
  }

  private parseNamespace(): void {
    // 1. Get the attributes section (everything after the 36-byte header)
    // 2. Get the last 20 bytes (the last attribute, if it exists)
    // 3. Extract the namespace field (first uint32) from that attribute
    // 4. Use that namespace for the new debuggable attribute

    const HEADER_SIZE = 0x24;
    const ATTRIBUTE_SIZE = 20;

    // Extract attributes section (everything after the header)
    const attributesDataLength = this.chunk_data.length - HEADER_SIZE;

    // Check if at least one attribute exists in the chunk
    if (attributesDataLength >= ATTRIBUTE_SIZE) {
      // Get last 20 bytes (last attribute)
      const lastAttrStart = this.chunk_data.length - ATTRIBUTE_SIZE;
      this.namespace = this.view.getUint32(lastAttrStart, true);
    } else {
      this.namespace = -1;
    }
  }

  /**
   * Insert debuggable attribute into this START_ELEMENT
   * Only called when this element is <application>
   */
  insert_debuggable( debuggableStringIndex: number, resourceMap: ResourceMapChunk): void {

    if (this.namespace === -1) {
      throw new Error('Cannot insert debuggable: no existing attributes to extract namespace from');
    }
    const DEBUGGABLE_RESOURCE_ID = 0x0101000f; // android:debuggable
    const HEADER_SIZE = 0x24;
    const ATTRIBUTE_SIZE = 20;
    const oldChunkSize = this.view.getUint32(4, true);
    const attributeCount = this.view.getUint16(28, true);

    // Create new attribute (20 bytes)
    const attributeBuffer = new ArrayBuffer(ATTRIBUTE_SIZE);
    const attrView = new DataView(attributeBuffer);

    attrView.setUint32(0, this.namespace, true);    // namespace
    attrView.setUint32(4, debuggableStringIndex, true);      // name
    attrView.setUint32(8, 0xFFFFFFFF, true);                 // rawValue
    attrView.setUint16(12, 8, true);                         // size
    attrView.setUint8(14, 0);                                // reserved
    attrView.setUint8(15, 0x12);                             // type (BOOL)
    attrView.setInt32(16, -1, true);                         // data (TRUE)

    const newAttributeBytes = new Uint8Array(attributeBuffer);
    // console.log("[insert_debug] New attribute being set: ", Array.from(newAttributeBytes).map(b => b.toString(16).padStart(2, '0')).join(' '));

    // Insert position (end of current attributes)
    // const insertPos = attributeStart + attributeCount * ATTRIBUTE_SIZE;
    // let insertPos = attributeStart;
    let insertPos = HEADER_SIZE;
    for (let i = 0; i < attributeCount; i++) {
      const attrOffset = HEADER_SIZE + i * ATTRIBUTE_SIZE

      // Read the name string from this attribute
      const nameStringIndex = this.view.getUint32(attrOffset + 4, true);

      // Get the resource ID fro this string index
      const existingResourceId = resourceMap.get_resource_id(nameStringIndex);
      if (existingResourceId > DEBUGGABLE_RESOURCE_ID) {
        break;
      }

      insertPos += ATTRIBUTE_SIZE;
      // console.log(`[insert_debug] Iteration ${i}, attrOffset: ${attrOffset}, nameStringIndex: ${nameStringIndex}, existingResourceId: ${existingResourceId}, insertPos: ${insertPos}`);
    }
    // console.log(`Inserting attribute at position ${insertPos}`);
    // console.log(`Attribute nameStringIndex=${debuggableStringIndex}, namespace=${this.namespace}`);

    // Create new buffer
    const newBuffer = new Uint8Array(this.chunk_data.length + ATTRIBUTE_SIZE);
    const newView = new DataView(newBuffer.buffer);

    // Copy before insertion point
    newBuffer.set(this.chunk_data.slice(0, insertPos), 0);

    // Insert new attribute
    newBuffer.set(newAttributeBytes, insertPos);

    // Copy after insertion point
    newBuffer.set(this.chunk_data.slice(insertPos), insertPos + ATTRIBUTE_SIZE);

    // Update attribute count
    newView.setUint16(28, attributeCount + 1, true);

    // Update chunk size
    newView.setUint32(4, oldChunkSize + ATTRIBUTE_SIZE, true);

    this.chunk_data = newBuffer;
    this.view = newView;
  }

  get_name(stringPool: StringPoolChunk): string {
    const nameSi = this.view.getUint32(20, true);
    return stringPool.get_string(nameSi);
  }

  get_chunk_data(): Uint8Array {
    return this.chunk_data;
  }

  get_size(): number {
    return this.view.getUint32(4, true);
  }
}

class BinaryXmlParser {
  private buffer: Uint8Array;
  private view: DataView;
  private stringPoolStart: number = 0;
  private xmlStart: number = 0;
  private strings: string[] = [];

  constructor(manifestBuffer: ArrayBuffer) {
    this.buffer = new Uint8Array(manifestBuffer);
    this.view = new DataView(manifestBuffer);
    this.validate();
    this.parseChunks();
  }

  private validate(): void {
    const magic = this.view.getUint32(0, true);
    if (magic !== 0x00080003) {
      throw new Error(`Invalid binary XML magic: 0x${magic.toString(16)}`);
    }
  }

  private parseChunks(): void {
    let chunkOffset = 8;

    while (chunkOffset < this.buffer.length) {
      const type = this.view.getUint16(chunkOffset, true);
      const headerSize = this.view.getUint16(chunkOffset + 2, true);
      const chunkSize = this.view.getUint32(chunkOffset + 4, true);

      if (chunkSize === 0) break;
      if (chunkOffset + chunkSize > this.buffer.length) break;

      if (type === 0x0001) { // RES_STRING_POOL_TYPE
        this.stringPoolStart = chunkOffset;
        this.parseStringPool(chunkOffset);
      } else if (type === 0x0100) { // RES_XML_TYPE
        // XML elements come AFTER this chunk
        this.xmlStart = chunkOffset + chunkSize;
      }

      chunkOffset += chunkSize;
    }
  }

  private parseStringPool(offset: number): void {
    const headerSize = this.view.getUint16(offset + 2, true);
    const stringCount = this.view.getUint32(offset + 8, true);
    const stringStart = this.view.getUint32(offset + 20, true);
    const flags = this.view.getUint32(offset + 16, true);

    const isUtf16 = (flags & 0x100) === 0;
    const poolStart = offset + stringStart;

    for (let i = 0; i < stringCount && i < 2000; i++) {
      try {
        const stringOffset = this.view.getUint32(offset + headerSize + i * 4, true);
        const strOffset = poolStart + stringOffset;
        const str = isUtf16 ? this.readUtf16String(strOffset) : this.readUtf8String(strOffset);
        this.strings.push(str);
      } catch {
        this.strings.push('');
      }
    }

    // Log key strings
    // console.log(`\n String pool loaded: ${this.strings.length} strings`);
    // console.log('Looking for key strings:');
    // const keysToFind = ['application', 'debuggable', 'android', 'http://schemas.android.com/apk/res/android'];
    // for (const key of keysToFind) {
    //   const index = this.strings.indexOf(key);
    //   if (index >= 0) {
    //     console.log(`"${key}" at index ${index}`);
    //   } else {
    //     console.log(`"${key}" NOT FOUND`);
    //   }
    // }
    // console.log('');
  }

  private readUtf16String(offset: number): string {
    try {
      const len = this.view.getUint16(offset, true);
      if (len === 0) return '';
      const maxBytes = Math.min(len * 2, this.buffer.length - offset - 2);
      const bytes = this.buffer.slice(offset + 2, offset + 2 + maxBytes);
      return new TextDecoder('utf-16le').decode(bytes).replace(/\0+$/, '');
    } catch {
      return '';
    }
  }

  private readUtf8String(offset: number): string {
    try {
      const len = this.view.getUint16(offset, true);
      const byteLen = this.view.getUint16(offset + 2, true);
      if (len === 0) return '';
      const maxBytes = Math.min(byteLen, this.buffer.length - offset - 4);
      const bytes = this.buffer.slice(offset + 4, offset + 4 + maxBytes);
      return new TextDecoder('utf-8').decode(bytes);
    } catch {
      return '';
    }
  }

  private findApplicationTagOffset(): number | null {
    let offset = this.xmlStart;
    const fileEnd = this.buffer.length;
    // console.log(`Starting to scan at offset ${offset}, file length ${fileEnd}`);

    while (offset < fileEnd - 8) {
      const type = this.view.getUint16(offset, true);
      const size = this.view.getUint32(offset + 4, true);

    if (size === 0 || size < 8) {
        // console.log(`  [${offset.toString().padStart(6)}] Invalid size: ${size}, stopping`);
        break;
      }
      if (offset + size > fileEnd) {
        // console.log(`  [${offset.toString().padStart(6)}] Chunk extends beyond file, stopping`);
        break;
      }

      if (type === 0x0102) { // START_ELEMENT
        // console.log(`Found START_ELEMENT at offset: ${offset}`);
        const nameSi = this.view.getUint32(offset + 20, true);
        // console.log(`Example string found: ${this.strings[nameSi]}`);
        if (nameSi < this.strings.length && this.strings[nameSi] === 'application') {
          return offset;
        }
      }

      offset += size;
    }

    return null;
  }

  /**
   * Calculate the total size of the reconstructed binary XML
   *
   * Parameters to consider:
   * 1. File header stays constant (8 bytes)
   * 2. Each chunk's NEW size (not original size)
   *    - StringPool: grew by ~28 bytes (offset entry + string + padding)
   *    - ResourceMap: grew by 4 bytes (new resource ID entry)
   *    - StartElement: grew by 20 bytes (new attribute)
   *    - Other chunks: unchanged
   * 3. Sum of all chunk sizes
   */
  private calculateNewTotalSize(modifiedChunks: Map<number, Uint8Array>): number {
    let totalSize = 8; // File header
    let offset = this.stringPoolStart;

    while (offset < this.buffer.length) {
      const size = this.view.getUint32(offset + 4, true);

      // If this chunk was modified, use its new size
      if (modifiedChunks.has(offset)) {
        const modifiedData = modifiedChunks.get(offset)!;
        const newSize = modifiedData.length;
        totalSize += newSize;
        // console.log(`  Modified chunk at ${offset}: ${size} â†’ ${newSize} (+${newSize - size})`);
      } else {
        // Unmodified chunk, use original size
        totalSize += size;
        // console.log(`  Unmodified chunk at ${offset}: ${size}`);
      }

      offset += size;
    }

    return totalSize;
  }

  private findDebuggableAttribute(appTagOffset: number): number | null {
    const attributeStart = this.view.getUint16(appTagOffset + 24, true);
    const attributeCount = this.view.getUint16(appTagOffset + 28, true);
    const attributeSize = this.view.getUint16(appTagOffset + 26, true);

    const androidNamespace = 'http://schemas.android.com/apk/res/android';
    const androidNsIndex = this.strings.indexOf(androidNamespace);

    for (let i = 0; i < attributeCount; i++) {
      const attrOffset = appTagOffset + attributeStart + i * attributeSize;
      const namespaceSi = this.view.getUint32(attrOffset, true);
      const nameSi = this.view.getUint32(attrOffset + 4, true);

      if (namespaceSi === androidNsIndex && nameSi < this.strings.length) {
        if (this.strings[nameSi] === 'debuggable') {
          return attrOffset;
        }
      }
    }

    return null;
  }

  getPackageNameFromManifest(): string | null {
  try {
    const parser = new BinaryXML(Buffer.from(this.buffer));
    const document = parser.parse();

    // Navigate the parsed XML tree
    let ret: string | null = null;
    document.attributes.forEach((attribute) => {
      if(attribute.name === 'package') {
        ret = attribute.value;
      }
    });
    return ret;
  } catch (error) {
    throw new Error(`Failed to parse manifest: ${error instanceof Error ? error.message : String(error)}`);
  }
}
  /**
   * Extract the package name from the manifest's root <manifest> element
   * @returns The package name string, or null if not found
   */
  /**
   * Main function to enable debuggable flag
   */
  enableDebuggable(): Uint8Array {
    let stringPool: StringPoolChunk | null = null;
    let resourceMap: ResourceMapChunk | null = null;
    let debuggableIndex: number | null = null;
    const modifiedChunks: Map<number, Uint8Array> = new Map(); // offset -> modified data

    // Iterate through ALL chunks (after string pool)
    let offset = this.stringPoolStart;
    while (offset < this.buffer.length) {
      const type = this.view.getUint16(offset, true);
      const size = this.view.getUint32(offset + 4, true);
      const chunkData = this.buffer.slice(offset, offset + size);

      // STRING_POOL
      if (type === 0x0001) {
        stringPool = new StringPoolChunk(chunkData);
        debuggableIndex = stringPool.append_str('debuggable');
        modifiedChunks.set(offset, stringPool.get_chunk_data());
      }

      // RESOURCE_MAP
      if (type === 0x0180) {
        resourceMap = new ResourceMapChunk(chunkData);
        resourceMap.add_debuggable(debuggableIndex!);
        modifiedChunks.set(offset, resourceMap.get_chunk_data());
      }

      // START_ELEMENT
      if (type === 0x0102) {
        const element = new StartElementChunk(chunkData);
        const name = element.get_name(stringPool!);
        if (name === 'application') {
          // const androidNsIndex = stringPool!.find_string_index(
          //   'http://schemas.android.com/apk/res/android'
          // );
          element.insert_debuggable( debuggableIndex!, resourceMap!);
          modifiedChunks.set(offset, element.get_chunk_data());
        }
      }

      offset += size;
  }

    // RECONSTRUCT
    const result = new Uint8Array(this.calculateNewTotalSize(modifiedChunks));
    let pos = 0;

    // File header (needs size update)
    const header = this.buffer.slice(0, 8);
    result.set(header, pos);
    pos += 8;

    // All chunks (use modified versions if they exist)
    offset = this.stringPoolStart;
    while (offset < this.buffer.length) {
      const size = this.view.getUint32(offset + 4, true);

      if (modifiedChunks.has(offset)) {
        const modified = modifiedChunks.get(offset)!;
        result.set(modified, pos);
        pos += modified.length;
      } else {
        result.set(this.buffer.slice(offset, offset + size), pos);
        pos += size;
      }

      offset += size;
    }

    // Update file header size
    const fileView = new DataView(result.buffer);
    fileView.setUint32(4, result.length, true);

    return result;
  }
}

/**
 * Modify AndroidManifest.xml to enable debuggable flag
 * @param manifestBuffer - Binary AndroidManifest.xml as ArrayBuffer
 * @returns Modified manifest as Uint8Array
 * @throws Error if parsing or modification fails
 */
export function enableDebuggableFlag(manifestBuffer: ArrayBuffer): Uint8Array {
  try {
    const parser = new BinaryXmlParser(manifestBuffer);
    const debuggableApk = parser.enableDebuggable();
    return debuggableApk;
  } catch (error) {
    throw new Error(`Failed to modify manifest: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function getPackageName(manifestBuffer: ArrayBuffer): string | null
{
  try {
    const parser = new BinaryXmlParser(manifestBuffer);
    const packageName = parser.getPackageNameFromManifest();
    // console.log(`Got package name: ${packageName}`);
    return packageName;

  } catch (error) {
    throw new Error(`Failed to parse manifest ${error instanceof Error ? error.message : String(error)}`);
  }
}
