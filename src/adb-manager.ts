import { Adb, AdbSync } from "@yume-chan/adb";
import { ReadableStream, TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";
import { config } from "./config";

/**
 * Options for push operations
 */
export interface PushOptions {
  /** Target path on device */
  devicePath?: string;
  /** Callback for progress tracking */
  onProgress?: (loaded: number, total: number) => void;
  /** Timeout in milliseconds (0 = no timeout) */
  timeout?: number;
}

/**
 * Result of a push operation
 */
export interface PushResult {
  success: boolean;
  bytesTransferred?: number;
  error?: Error;
}

export interface ProcessOutput {
    output: string;
    exitCode: number;
}


export interface ApkDescriptor {
  name: string,
  path: string,
  size: number
}

/**
 * Handles streaming file uploads to Android devices via ADB
 *
 * Uses ReadableStream<Uint8Array> to efficiently transfer files
 * without loading entire contents into memory.
 */
export class AdbManager {
  constructor(private adb: Adb) {}

  /**
   * Push a file from a network URL to device
   *
   * @example
   * ```typescript
   * const result = await uploader.pushFromUrl(
   *   "/api/binary",
   *   {
   *     devicePath: "/data/local/tmp/myapp",
   *     onProgress: (loaded, total) => console.log(`${loaded}/${total}`)
   *   }
   * );
   * ```
   */
  async pushFromUrl(
    url: string,
    options: PushOptions = {}
  ): Promise<PushResult> {
    try {
      const response = await fetch(url);

      if (!response.ok) {
        throw new Error(`Fetch failed: ${response.status} ${response.statusText}`);
      }

      if (!response.body) {
        throw new Error("Response has no body");
      }

      const contentLength = response.headers.get("content-length");
      const total = contentLength ? parseInt(contentLength, 10) : 0;

      const stream = this.createProgressStream(
        response.body as ReadableStream<Uint8Array>,
        total,
        options.onProgress
      );

      const bytesTransferred = await this.pushStream(stream, options.devicePath);

      return { success: true, bytesTransferred };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      return { success: false, error: err };
    }
  }

  /**
   * Push a file from a network URL to device if not present already
   *
   * @example
   * ```typescript
   * const result = await uploader.pushFromUrl(
   *   "/api/binary",
   *   {
   *     devicePath: "/data/local/tmp/myapp",
   *     onProgress: (loaded, total) => console.log(`${loaded}/${total}`)
   *   }
   * );
   * ```
   */
  async pushIfNotPresent(
    file: string
  ): Promise<PushResult> {
    try {
      const url = config.backendUrl + 'static/' + file;
      const destination = config.devicePath + file;
      const status = await this.adbRun(["ls", destination]);
      if (status.exitCode === 0) {
        // File already present, no need to push it again
        return { success: true, bytesTransferred: 0};
      } else {
        console.log(`[pushFromUrl] ${file} not present`);
        return this.pushFromUrl(url, {devicePath: destination});
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      throw err;
    }
  }

  /**
   * Push a file from user file input
   *
   * @example
   * ```typescript
   * const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]');
   * const file = fileInput?.files?.[0];
   * if (file) {
   *   const result = await uploader.pushFromFile(file);
   * }
   * ```
   */
  async pushFromFile(
    file: File,
    options: PushOptions = {}
  ): Promise<PushResult> {
    try {
      const stream = this.createProgressStream(
        file.stream() as any,
        file.size,
        options.onProgress
      );

      const bytesTransferred = await this.pushStream(stream, options.devicePath);

      return { success: true, bytesTransferred };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      return { success: false, error: err };
    }
  }

  /**
   * Push data from a Blob
   */
  async pushFromBlob(
    blob: Blob,
    options: PushOptions = {}
  ): Promise<PushResult> {
    try {
      const stream = this.createProgressStream(
        blob.stream() as any,
        blob.size,
        options.onProgress
      );

      const bytesTransferred = await this.pushStream(stream, options.devicePath);

      return { success: true, bytesTransferred };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      return { success: false, error: err };
    }
  }

  /**
   * Push data from a ReadableStream<Uint8Array>
   *
   * This is the low-level method that all other methods use.
   * Use this if you have a custom stream source.
   */
  async pushStream(
    stream: ReadableStream<Uint8Array>,
    devicePath: string = "/data/local/tmp/dist"
  ): Promise<number> {
    const sync = await this.adb.sync();

    try {
      // Write returns void, so we can't directly track bytes
      // but yume-adb handles the streaming internally
      await sync.write({
        filename: devicePath,
        file: stream,
      });

      return 0; // yume-adb doesn't expose bytes transferred
    } finally {
      await sync.dispose();
    }
  }

  /**
   * Push from embedded base64-encoded data
   *
   * Useful when binary is embedded in bundle at build time.
   * Chunks the data to avoid memory spikes.
   *
   * @example
   * ```typescript
   * import { EMBEDDED_BINARY_B64 } from './dist/store';
   *
   * const result = await uploader.pushFromBase64(
   *   EMBEDDED_BINARY_B64,
   *   { devicePath: "/data/local/tmp/dist" }
   * );
   * ```
   */
  async pushFromBase64(
    base64Data: string,
    options: PushOptions = {}
  ): Promise<PushResult> {
    try {
      // Decode base64 to binary string
      const binaryString = atob(base64Data);

      // Create stream that chunks the data
      const stream = this.createBase64Stream(binaryString);

      const bytesTransferred = await this.pushStream(stream, options.devicePath);

      return { success: true, bytesTransferred: bytesTransferred };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      return { success: false, error: err };
    }
  }

  /**
   * Create a ReadableStream that decodes base64 in chunks
   *
   * @param binaryString - Result of atob(base64Data)
   * @param chunkSize - Size of chunks in bytes (default: 64KB)
   */
  private createBase64Stream(
    binaryString: string,
    chunkSize: number = 64 * 1024
  ): ReadableStream<Uint8Array> {
    let offset = 0;

    return new ReadableStream({
      pull(controller) {
        if (offset >= binaryString.length) {
          controller.close();
          return;
        }

        const chunk = binaryString.slice(offset, offset + chunkSize);
        const uint8Array = new Uint8Array(chunk.length);

        for (let i = 0; i < chunk.length; i++) {
          uint8Array[i] = chunk.charCodeAt(i);
        }

        controller.enqueue(uint8Array);
        offset += chunkSize;
      },
    });
  }

  /**
   * Wrap a stream to track progress
   */
  private createProgressStream(
    sourceStream: ReadableStream<Uint8Array>,
    total: number,
    onProgress?: (loaded: number, total: number) => void
  ): ReadableStream<Uint8Array> {
    if (!onProgress || total === 0) {
      return sourceStream;
    }

    let loaded = 0;
    const reader = sourceStream.getReader();

    return new ReadableStream({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();

          if (done) {
            controller.close();
            return;
          }

          loaded += value.length;
          onProgress(loaded, total);
          controller.enqueue(value);
        } catch (error) {
          controller.error(error);
        }
      },

      async cancel(reason) {
        await reader.cancel(reason);
      },
    });
  }

  async adbRun(command: string | readonly string[]): Promise<ProcessOutput> {
    let ret: ProcessOutput = {
    output: "",
    exitCode: 0
    };

    const shell = await this.adb.subprocess.shellProtocol!.spawn(command);
    // Stdout and stderr will generate two Promise, await them together
    await Promise.all([
    shell.stdout.pipeThrough(new TextDecoderStream()).pipeTo( new WritableStream({
        write(chunk) {
         ret.output += chunk;
        },
      }),
    ),
    shell.stderr.pipeThrough(new TextDecoderStream()).pipeTo(
      new WritableStream({
        write(chunk) {
          console.error(["[*] PM LIST ERR ", chunk]);
        },
      }),
    ),
    ]);

    ret.exitCode = await shell.exited;
    return ret;

  }

  async installApk(
    apkData: Uint8Array,
    remotePath: string
  ): Promise<void> {
    try {

        // This might seem naive, but apkData is already in memory
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(apkData);
                controller.close();
            },
        });
        // Push APK data to device
        await this.pushStream(stream, remotePath);
        console.log("Pushed APK to device");

        // Install
        const result = await this.adbRun(`pm install -r ${remotePath}`);
        if (result.exitCode === 0) {
          console.log('APK pushed successfully');
        } else {
          throw new Error(`Installation failed: ${result.output}`);
        }

        // Cleanup
        await this.adbRun(`rm ${remotePath}`);

        return;
    } catch (error) {
        throw new Error(`Failed to install APK: ${error}`);
    }
  }

  async getAPKPaths(packageName: string): Promise<string[]> {
    const adbCommand = ["pm", "path", packageName];
    const result = await this.adbRun(adbCommand);
    if (result.exitCode !== 0) {
      console.error(`Pm path ${packageName} returned error ${result.output}`);
    }
    return result.output
      .split('\n')
      .filter(line => line.startsWith('package:'))
      .map(line => line.substring(8).trim());
  }

  async pullFromDevice(
    remotePath: string,
    progressCallback: (progress: number) => void
  ): Promise<Uint8Array> {
    // Get sync from Adb client
    const sync = await this.adb.sync();

    const chunks: Uint8Array[] = [];
    let receivedBytes = 0;

    // Get file size first
    const stat = await sync.lstat(remotePath);
    const totalSize = stat.size;

    // Read file in chunks
    const readable = sync.read(remotePath);
    const reader = readable.getReader();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      chunks.push(value);
      receivedBytes += value.byteLength;

      // Update progress
      const progress = totalSize > 0 ? receivedBytes / Number(totalSize) : 0;
      progressCallback(progress);
    }

    // Combine chunks
    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.byteLength, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }

    // Close sync
    await sync.dispose();

    return result;
  }

  async installSplitApk(apkFiles: File[]) {

    const APK_UPLOAD_PATH = '/data/local/tmp/split-apks/';

    // Create sync
    const sync = await this.adb.sync();
    try {
      // Create directory
      const mkdir = await this.adbRun(["mkdir", APK_UPLOAD_PATH]);
      if (mkdir.exitCode !== 0) {
        throw new Error(`Failed to create directory ${APK_UPLOAD_PATH}`);
      }


      // Upload files and collect remote paths
      const remotePaths: ApkDescriptor[] = [];
      let totalSize = 0;
      for (const file of apkFiles) {
        const remotePath = `${APK_UPLOAD_PATH}${file.name}`;
        await this.pushFromFile(file);
        remotePaths.push({
          name: file.name,
          path: remotePath,
          size: file.size,
        });
        totalSize += file.size;
      }


      // Create session and write each APK
      const sessionId = await this.createInstallSession(totalSize);
      for (const [idx, apk] of remotePaths.entries()) {
        await this.writeToInstallSession(apk, sessionId, idx);
      }

      // Commit the installation
      await this.commitInstallSession(sessionId);

    } catch (error) {
        console.error('Split installation error: ', error);
        throw error;
    } finally {
        // Clean split directory
        await this.adbRun(["rm", "-rf", APK_UPLOAD_PATH]);
        // Close sync
        await sync.dispose();
    }
  }

  private async createInstallSession(totalSize: number): Promise<number> {
    const adbCommand = ["pm", "install-create", "-S", totalSize.toString()];
    const {output, exitCode} = await this.adbRun(adbCommand);

    const match = output.match(/Success: created install session \[(\d+)\]/);
    if (!match) {
      throw new Error('Failed to parse session ID from output: ' + output);
    }

    return parseInt(match[1], 10);
  }

  private async writeToInstallSession(
    apk: ApkDescriptor,
    sessionId: number,
    idx: number
  ): Promise<void> {

    const adbCommand = ["pm", "install-write", "-S", apk.size.toString(), sessionId.toString(),
      idx.toString(), apk.path];
    const {output, exitCode} = await this.adbRun(adbCommand);

    if (exitCode !== 0 ) {
      throw new Error(`Failed to write ${apk.name} to session (code ${exitCode}): ${output}`);
    }
  }

  private async commitInstallSession(sessionId: number) {

    const adbCommand = ['pm', 'install-commit', sessionId.toString()];
    const {output, exitCode} = await this.adbRun(adbCommand);

    if (exitCode !== 0) {
      throw new Error(`Failed to commit session (code ${exitCode}): ${output}`);
    }
  }


}
