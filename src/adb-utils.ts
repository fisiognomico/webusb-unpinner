import { Adb, AdbSync } from "@yume-chan/adb";
import { ReadableStream, TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";

interface ProcessOutput {
    output: string;
    exitCode: number;
}


export async function adbRun(adbClient: Adb, command: string | readonly string[]) : Promise<ProcessOutput> {
    let ret: ProcessOutput = {
    output: "",
    exitCode: 0
    };

    const shell = await adbClient.subprocess.shellProtocol!.spawn(command);
    // Stdout and stderr will generate two Promise, await them together
    await Promise.all([
    shell.stdout.pipeThrough(new TextDecoderStream()).pipeTo(
      new WritableStream({
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

export async function reinstallApk(
    adb: Adb,
    apkData: Uint8Array,
    apkName: string = 'app.apk'
    // adbConnection: AdbDaemonConnection
): Promise<void> {
    const remotePath = `/data/local/tmp/${apkName}`;

    try {
        // Push APK data to device
        await pushApkToDevice(adb, apkData, remotePath);
        console.log("Pushed APK to device");

        // Uninstall App to avoid issues resigning
        // Install
        await installApkOnDevice(adb, remotePath);
        console.log("Installed APK on device");

        // Cleanup
        await adbRun(adb, `rm ${remotePath}`);

        return;
    } catch (error) {
        throw new Error(`Failed to install APK: ${error}`);
    }
}

export async function pushApkToDevice(
    adb: Adb,
    apkData: Uint8Array,
    remotePath: string
): Promise<void> {
    try {
        // Convert to base64 for safe transmission
        const base64Data = uint8ArrayToBase64(apkData);

        // Create a shell session to receive the data
        const shell = await adb.subprocess.shellProtocol!.spawn(['sh']);

        // Write commands to decode and write file
        const writer = shell.stdin.getWriter();

        // Send base64 data through echo and decode
        const command = `echo "${base64Data}" | base64 -d > ${remotePath}\n`;
        await writer.write(new TextEncoder().encode(command));
        await writer.close();

        // Wait for completion
        // const exitCode = await shell.exited;
        // console.log(`[DEBUG] Pipeline returned exitCode ${exitCode}`);
        // if (exitCode !== 0) {
        //     throw new Error(`Failed to push APK: exit code ${exitCode}`);
        // }

    } catch (error) {
        throw new Error(`Failed to push APK data: ${error}`);
    }
}

export async function installApkOnDevice(adb: Adb, remotePath: string): Promise<void> {
    try {
        const result = await adbRun(adb, `pm install -r ${remotePath}`);

        // Check if installation was successful
        if (result.output.includes('Success') || result.exitCode === 0) {
            console.log('APK installed successfully');
        } else {
            throw new Error(`Installation failed: ${result.output}`);
        }
    } catch (error) {
        throw new Error(`Failed to install APK: ${error}`);
    }
}

function uint8ArrayToBase64(data: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < data.length; i++) {
        binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
}

export async function getPackageInfo(adbClient: Adb, packageName: string) {
  const adbCommand = ["dumpsys", "package", packageName];
  const {output, exitCode} = await adbRun(adbClient, adbCommand);
  if(exitCode !== 0) {
    console.error(`[+] Dumpsys returned ${output}`)
  }

  // Parse version info
  const versionMatch = output.match(/versionName=([^\s]+)/);
  const versionCodeMatch = output.match(/versionCode=(\d+)/);

  return {
    versionName: versionMatch ? versionMatch[1] : 'unknown',
    versionCode: versionCodeMatch ? parseInt(versionCodeMatch[1], 10) : 0
  };
}

export async function getAPKPaths(adbClient: Adb, packageName: string) {
  const adbCommand = ["pm", "path", packageName];
  const {output, exitCode} = await adbRun(adbClient, adbCommand);
  if(exitCode !== 0) {
    console.error(`Pm path ${packageName} returned error ${output}`);
  }

  return output
    .split('\n')
    .filter(line => line.startsWith('package:'))
    .map(line => line.substring(8).trim());
}

// File download with progress
export async function downloadFile(
  sync: AdbSync,
  remotePath: string,
  progressCallback: (progress: number) => void
): Promise<Uint8Array> {
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

  return result;
}


