import { AdbDaemonWebUsbDeviceObserver} from "@yume-chan/adb-daemon-webusb";
import { Adb, AdbSync } from "@yume-chan/adb";
import { ReadableStream, TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";
import { PackageManager } from "@yume-chan/android-bin";
import JSZip from "jszip";
import { saveAs } from 'file-saver';

import {getDeviceState, setDeviceState, connectToDevice, disconnectDevice, initializeCredentials} from "./state";

const statusDiv = document.getElementById('status')!;
const connectBtn = document.getElementById('connectBtn') as HTMLButtonElement;
const uploadSection = document.getElementById('uploadSection')!;
const uploadArea = document.getElementById('uploadArea')!;
const uploadBtn = document.getElementById('uploadBtn') as HTMLButtonElement;
const progressBar = document.getElementById('progressBar') as HTMLDivElement;
const statusText = document.getElementById('statusText')!;
const fileList = document.getElementById('fileList')!;
let fileInput = document.getElementById('fileInput') as HTMLInputElement;
const uninstallSection = document.getElementById('uninstallSection') as HTMLDivElement;
const appList = document.getElementById('appList') as HTMLSelectElement;
const uninstallBtn = document.getElementById('uninstallBtn') as HTMLButtonElement;
const refreshBtn = document.getElementById('refreshBtn') as HTMLButtonElement;
const downloadSection = document.getElementById('downloadSection') as HTMLDivElement;
const downloadProgressBar = document.getElementById('downloadProgressBar') as HTMLDivElement;
const downloadStatus = document.getElementById('downloadStatus') as HTMLParagraphElement;

// Browser compatibility check
if (!navigator.usb) {
  statusDiv.textContent = 'WebUSB not supported. Use Chromium-based browsers.';
  statusDiv.className = 'status disabled';
  connectBtn.disabled = true;
}

// State management
let observer: AdbDaemonWebUsbDeviceObserver | null = null;
let selectedFiles: File[] = [];
const FILE_UPLOAD_PATH = '/sdcard/Downloads/web-uploads/';
const APK_UPLOAD_PATH = '/data/local/tmp/';

interface ProcessOutput {
  output: string;
  exitCode: number;
}

interface ApkDescriptor {
  name: string,
  path: string,
  size: number
}

function updateStatus() {
  const state = getDeviceState();

  if (state.device) {
    if (state.isAuthenticating) {
      statusDiv.textContent = 'Authentication required. Check your device...';
      statusDiv.className = 'status authenticating';
    } else if (state.isConnected) {
      statusDiv.textContent = 'ADB enabled - Device connected';
      statusDiv.className = 'status enabled';
    } else if (state.error) {
      statusDiv.textContent = state.error;
      statusDiv.className = 'status error';
    } else {
      statusDiv.textContent = 'Device detected - Connecting...';
      statusDiv.className = 'status connecting';
    }

    uploadSection.style.display = 'block';
    uninstallSection.style.display = 'block';

    // Load apps only when fully connected
    if (state.isConnected && !state.isAuthenticating) {
      loadInstalledApps();
    }
  } else {
    statusDiv.textContent = 'No ADB device connected';
    statusDiv.className = 'status disabled';
    uploadSection.style.display = 'none';
    uninstallSection.style.display = 'none';
    selectedFiles = [];
    renderFileList();
  }

  // Show error if any
  if (state.error) {
    statusText.textContent = state.error;
    statusText.className = 'status-text error';
  }
}

// Initialize device observer
async function initializeObserver() {
  try {
    observer = await AdbDaemonWebUsbDeviceObserver.create(navigator.usb, {
      filters: [{ vendorId: 0x18d1 }] // Google's vendor ID
    });

    const hasDevices = observer.current.length > 0;
    if(hasDevices) {
      setDeviceState({ device: observer.current[0] });
    }
    updateStatus();

    // Listen for device list changes
    observer.onListChange(devices => {
      const hasDevices = devices.length > 0;
      if (hasDevices) {
        setDeviceState({ device: devices[0]});
      } else {
        disconnectDevice();
      }
      updateStatus();
    });

    observer.onDeviceAdd(devices => {
      console.log('Device connected:', devices);
    });

    observer.onDeviceRemove(devices => {
      console.log('Device disconnected:', devices);
    });

    // TODO store in general state
    return observer;
  } catch (error) {
    console.error('Observer initialization failed:', error);
    setDeviceState({ error: 'Failed to initialize device observer' });
    updateStatus();
    return null;
  }
}

// File selection handling
uploadArea.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  console.log('[DEBUG] File input change event triggered');

  if (!fileInput.files || fileInput.files.length === 0) {
    console.log('[DEBUG] No files selected');
    return;
  }

  // Create a new array from the files
  selectedFiles = [];
  for (let i = 0; i < fileInput.files.length; i++) {
    selectedFiles.push(fileInput.files[i]);
  }

  console.log(`[DEBUG] Selected ${selectedFiles.length} files`);
  renderFileList();
  uploadBtn.disabled = false;

});

// Reset the input only after successful upload
function resetFileInput() {
  // Create a new input element to replace the old one
  const newInput = document.createElement('input');
  newInput.type = 'file';
  newInput.id = 'fileInput';
  newInput.multiple = true;
  newInput.style.display = 'none';

  // Add event listener to the new input
  newInput.addEventListener('change', () => {
    if (!newInput.files || newInput.files.length === 0) return;
    selectedFiles = Array.from(newInput.files);
    renderFileList();
    uploadBtn.disabled = false;
  });

  // Replace the old input with the new one
  const parent = fileInput.parentNode;
  parent?.replaceChild(newInput, fileInput);
  fileInput = newInput as HTMLInputElement;

  // Also reset the selectedFiles array
  selectedFiles = [];
  renderFileList();
  uploadBtn.disabled = true;
}


uploadArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  uploadArea.classList.add('drag-over');
});

uploadArea.addEventListener('dragleave', () => {
  uploadArea.classList.remove('drag-over');
});

uploadArea.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadArea.classList.remove('drag-over');

  if (!e.dataTransfer?.files || e.dataTransfer.files.length === 0) {
    console.log('[DEBUG] No files in drop event');
    return;
  }

  console.log(`[DEBUG] Dropped ${e.dataTransfer.files.length} files`);

  // Create a new array from the dropped files
  selectedFiles = [];
  for (let i = 0; i < e.dataTransfer.files.length; i++) {
    selectedFiles.push(e.dataTransfer.files[i]);
  }

  renderFileList();
  uploadBtn.disabled = false;
});

function renderFileList() {
  fileList.innerHTML = '';

  if (selectedFiles.length === 0) {
    fileList.innerHTML = '<p>No files selected</p>';
    return;
  }

  selectedFiles.forEach((file, index) => {
    const fileItem = document.createElement('div');
    fileItem.className = 'file-item';

    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';
    fileInfo.innerHTML = `
      <div class="file-name">${file.name}</div>
      <div class="file-size">${formatFileSize(file.size)}</div>
    `;

    const removeBtn = document.createElement('button');
    removeBtn.textContent = 'Remove';
    removeBtn.className = 'btn';
    removeBtn.style.backgroundColor = '#dc3545';
    removeBtn.style.padding = '5px 10px';
    removeBtn.style.fontSize = '0.9rem';
    removeBtn.addEventListener('click', () => {
      selectedFiles.splice(index, 1);
      renderFileList();
      uploadBtn.disabled = selectedFiles.length === 0;
    });

    fileItem.appendChild(fileInfo);
    fileItem.appendChild(removeBtn);
    fileList.appendChild(fileItem);
  });
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' bytes';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

// Upload functionality
uploadBtn.addEventListener('click', async () => {
  if (selectedFiles.length === 0) return;

  const state = getDeviceState();
  const client = state.client;
  if(!client) return;


  try {
    // Connect to device if not already connected
    // Get ADB sync client
    const sync = await client.sync();

    // Check if we are installing APKs
    const isApkInstall = selectedFiles.every(file => file.name.toLowerCase().endsWith('.apk'))

    if (isApkInstall) {
      if (selectedFiles.length === 1) {
        await installSingleApk(client, selectedFiles[0]);
      } else {
        await installSplitApk(client, sync, selectedFiles);
      }

      statusText.textContent = 'App installed successfully!';
      statusText.className = 'status-text success';
    } else {
    // Upload all files
      for (const file of selectedFiles) {
        await uploadFile(sync, file);
      }

      statusText.textContent = 'All files uploaded successfully!';
      statusText.className = 'status-text success';
      resetFileInput();
    }

  } catch (error) {
    console.error('Upload error:', error);
    statusText.textContent = `Upload failed: ${error instanceof Error ? error.message : String(error)}`;
    statusText.className = 'status-text error';
  } finally {
    progressBar.style.width = '0%';
  }
});

async function uploadFile(sync: AdbSync, file: File) {
  if (!file || file.size === 0) {
    console.error('[DEBUG] Invalid file reference', file);
    throw new Error('Invalid file reference');
  }

  console.log(`[DEBUG] Starting upload for: ${file.name} (${file.size} bytes)`);

  statusText.textContent = `Uploading: ${file.name}...`;
  statusText.className = 'status-text';
  progressBar.style.width = '0%';

  const filePath = `${FILE_UPLOAD_PATH}${file.name}`;
  const fileSize = file.size;
  let uploaded = 0;

  try {
    // Create readable stream from the file

    const fileStream = file.stream();
    const progressTrackingStream = new ReadableStream<Uint8Array>({
      async start(controller) {
        const reader = fileStream.getReader();
        while(true) {
          const {done, value} = await reader.read();
          if(done) {
            controller.close();
            break;
          }

          // Track uploaded bytes
          uploaded += value.byteLength;
          const progress = Math.round((uploaded / fileSize) * 100);
          progressBar.style.width = `${progress}%`;

          // Pass through the data
          controller.enqueue(value);
        }
      }
    });

    await sync.write({
      filename: filePath,
      file: progressTrackingStream,
    });

    console.log(`File uploaded: ${file.name}`);

    statusText.textContent = `Uploaded: ${file.name}`;
    statusText.className = 'status-text success';
  } catch (error) {
    console.error(`Error uploading ${file.name}:`, error);
    statusText.textContent = `Error uploading ${file.name}: ${
      error instanceof Error ? error.message : String(error)
    }`;
    statusText.className = 'status-text error';
    throw error;
  }
}

async function installSingleApk(client: Adb, apkFile: File) {
  statusText.textContent = `Installing: ${apkFile.name}...`;
  statusText.className = 'status-text';
  let uploaded = 0;

  try {
    const stream = apkFile.stream();
    const apkSize = apkFile.size;
    const pm = new PackageManager(client);

    // Create readable stream from APK
    const progressTrackingStream = new ReadableStream<Uint8Array>({
      async start(controller) {
        const reader = stream.getReader();
        while(true) {
          const {done, value} = await reader.read();
          if(done) {
            controller.close();
            break;
          }

          // Track uploaded bytes
          uploaded += value.byteLength;
          const progress = Math.round((uploaded / apkSize) * 100);
          progressBar.style.width = `${progress}%`;

          // Pass through the data
          controller.enqueue(value);
        }

      }
    });
    // Feed into pm installer
    await pm.installStream(apkSize, progressTrackingStream);
  } catch(error) {
    console.error('Installation error:', error);
    statusText.textContent = `Installation failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
    statusText.className = 'status-text error';
    throw error;
  }
}

async function installSplitApk(client: Adb, sync: AdbSync, apkFiles: File[]) {
  statusText.textContent = 'Starting split APK installation...';
  statusText.className = 'status-text';

  try {
    // Upload files and collect remote paths
    const remotePaths: ApkDescriptor[] = [];
    let totalSize = 0;
    for (const file of apkFiles) {
      const remotePath = `${APK_UPLOAD_PATH}${file.name}`;
      await uploadFile(sync, file);
      remotePaths.push({
        name: file.name,
        path: remotePath,
        size: file.size,
      });
      totalSize += file.size;
    }


    // Create session and write each APK
    const sessionId = await createInstallSession(client, totalSize);
    for (const [idx, apk] of remotePaths.entries()) {
      await writeToInstallSession(client, apk, sessionId, idx);
    }

    // Commit the installation
    await commitInstallSession(client, sessionId);

    statusText.textContent = 'Split APK installed successfully!';
    statusText.className = 'status-text success';
  } catch (error) {
    console.error('Split installation error: ', error);
    statusText.textContent = `Split installation failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
    statusText.className = 'status-text error';
    throw error;
  }
}

async function createInstallSession(client: Adb, totalSize: number): Promise<number> {
  const adbCommand = ["pm", "install-create", "-S", totalSize.toString()];
  const {output, exitCode} = await adbRun(client!, adbCommand);

  const match = output.match(/Success: created install session \[(\d+)\]/);
  if (!match) {
    throw new Error('Failed to parse session ID from output: ' + output);
  }

  return parseInt(match[1], 10);

}

async function writeToInstallSession( client: Adb, apk: ApkDescriptor, sessionId: number, idx: number)
{
  const adbCommand = ["pm", "install-write", "-S", apk.size.toString(), sessionId.toString(),
    idx.toString(), apk.path];
  const {output, exitCode} = await adbRun(client, adbCommand);

  if (exitCode !== 0 ) {
    throw new Error(`Failed to write ${apk.name} to session (code ${exitCode}): ${output}`);
  }
}

async function commitInstallSession(client: Adb, sessionId: number) {
  const adbCommand = ['pm', 'install-commit', sessionId.toString()];
  const {output, exitCode} = await adbRun(client, adbCommand);

  if (exitCode !== 0) {
    throw new Error(`Failed to commit session (code ${exitCode}): ${output}`);
  }
}

/** =============================
 *        REINSTALL APK
 *  =============================
 */

async function loadInstalledApps() {
  let adbClient: Adb | null = null;

  const state = getDeviceState();
  if(state.client) {
    adbClient = state.client;
  } else {
    console.log("[+] Load Installed apps called without connected client");
    return;
  }

  appList.innerHTML = '<option value="" disabled selected>Loading applications...</option>';
  uninstallBtn.disabled = true;
  refreshBtn.disabled = true;

  try {
    // Directly use pm -3 for third-party apps
    const adbCommand = ['pm', 'list', 'packages', '-3'];
    const {output, exitCode}  = await adbRun(adbClient!, adbCommand);

    if (exitCode !== 0) {
      throw new Error('Failed to list applications');
    }
    // Parse package names, pm ouput include package:
    const packages = output.split('\n')
      .filter(line => line.startsWith('package:'))
      .map(line => line.substring(8).trim());

    if (packages.length === 0) {
      appList.innerHTML = '<option value="" disabled>No third-party apps found</option>';
      return;
    }

    // Clear and populate app list
    appList.innerHTML = '';
    packages.forEach(pkg => {
      const option = document.createElement('option');
      option.value = pkg;
      option.textContent = pkg;
      appList.appendChild(option);
    });

    // Enable controls
    uninstallBtn.disabled = false;
    refreshBtn.disabled = false;

  } catch (error) {
    console.error('Error loading applications:', error);
    appList.innerHTML = '<option value="" disabled>Error loading applications</option>';
  }
}

async function uninstallSelectedApp() {
  const packageName = appList.value;
  if (!packageName) return;
  let adbClient: Adb | null = null;

  const state = getDeviceState();
  if(state.client) {
    adbClient = state.client;
  } else {
    console.log("[+] Load Installed apps called without connected client");
    return;
  }

  uninstallBtn.disabled = true;
  refreshBtn.disabled = true;
  statusText.textContent = `Uninstalling ${packageName}...`;
  statusText.className = 'status-text';

  // Show download UI TODO can be purged
  downloadSection.style.display = 'block';
  downloadSection.textContent = `Preparing to download ${packageName}...`;

  await backupApk(adbClient, packageName);

  try {
    const adbCommand = ['pm', 'uninstall', packageName];
    const {output, exitCode} = await adbRun(adbClient!, adbCommand);

    if (exitCode !== 0) {
      throw new Error(`Uninstall failed: ${output}`);
    }

    statusText.textContent = `Uninstalled: ${packageName}`;
    statusText.className = 'status-text success';

    // Refresh app list
    await loadInstalledApps();

    // Hide download section after delay
    setTimeout(() => {
      downloadSection.style.display = 'none';
    }, 3000);

  } catch (error) {
    console.error('Uninstall error:', error);
    statusText.textContent = `Uninstall failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
    statusText.className = 'status-text error';
    uninstallBtn.disabled = false;
    refreshBtn.disabled = false;
  }
}

async function adbRun(adbClient: Adb, command: string | readonly string[]) : Promise<ProcessOutput> {
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
         ret.output = chunk;
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

// APK backup function
async function backupApk(client: Adb, packageName: string) {
  try {
    setDeviceState({isDownloading: true, downloadProgress: 0});

    // Get package info
    const packageInfo = await getPackageInfo(client, packageName);

    // Get APK paths
    const apkPaths = await getAPKPaths(client, packageName);

    // Download APKs
    const state = getDeviceState();
    const sync = await state.client?.sync();
    const apkFiles: {path: string, data: Uint8Array}[] = [];

    for (let i = 0; i < apkPaths.length; i++) {
      const path = apkPaths[i];
      downloadStatus.textContent = `Downloading APK (${i+1}/${apkPaths.length})...`;

      const data = await downloadFile(sync!, path, (progress) => {
        const totalProgress = Math.round(((i + progress) / apkPaths.length) * 100);
        downloadProgressBar.style.width = `${totalProgress}%`;
        setDeviceState({ downloadProgress: totalProgress });
      });
      apkFiles.push({path, data});
    }

    // Create filename with version
    const versionStr = packageInfo.versionName.replace(/[^a-z0-9]/gi, '_');
    const baseFilename = `${packageName}_${versionStr}`;

    if(apkFiles.length === 1) {
      const apkFileType = 'application/vnd.android.package-archive';
      saveAs( new Blob([apkFiles[0].data as BlobPart], {type: apkFileType}));
    } else {
      // Multiple APKs installation
      const zip = new JSZip();

      apkFiles.forEach((file, index) => {
        const filename = file.path.split('/').pop() || `base-${index}.apk`;
        zip.file(filename, file.data);
      });

      // TODO Add package info
      // zip.file('package-info.txt',
      //   `Package: ${packageName}\nVersion: ${packageInfo.versionName}\nVersion Code: ${packageInfo.versionCode}`);

      const content = await zip.generateAsync({type: 'blob'});
      saveAs(content, `${baseFilename}.zip`);

      downloadStatus.textContent = `Downloaded ${apkFiles.length} APK file(s)`;
    }
  } catch (error) {
    throw error;
  } finally {
    setDeviceState({ isDownloading: false, downloadProgress: 0});
  }
}



async function getPackageInfo(adbClient: Adb, packageName: string) {
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

async function getAPKPaths(adbClient: Adb, packageName: string) {
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
async function downloadFile(
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

refreshBtn.addEventListener('click', loadInstalledApps);
uninstallBtn.addEventListener('click', uninstallSelectedApp);
appList.addEventListener('change', () => {
  uninstallBtn.disabled = !appList.value;
});


// Manual device connection trigger
connectBtn.addEventListener('click', async () => {
  try {
    // Must be triggered by user gesture
    await navigator.usb.requestDevice({
      filters: [{ vendorId: 0x18d1 }] // Google's vendor ID
    });
    // Simple solution: only connect to device calls this function
    connectToDevice();
  } catch (error) {
    console.log('Device selection canceled');
  }
});

// Cleanup on page unload
window.addEventListener('beforeunload', async () => {
  if (observer) {
    observer.stop(); // Release resources
  }

  const state = getDeviceState();
  if(state.device) {
    disconnectDevice();
  }
});

// Initialize device credentials
initializeCredentials();
// Initialize device observer
initializeObserver();
// Periodically update UI to reflect state changes
setInterval(updateStatus, 10000);
