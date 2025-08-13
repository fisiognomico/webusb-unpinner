import { AdbDaemonWebUsbDevice, AdbDaemonWebUsbDeviceObserver, AdbDaemonWebUsbDeviceManager } from "@yume-chan/adb-daemon-webusb";
import { Adb, AdbDaemonDevice, AdbSync, AdbDaemonTransport } from "@yume-chan/adb";
import { ReadableStream, TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import { PackageManager } from "@yume-chan/android-bin";

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

// Browser compatibility check
if (!navigator.usb) {
  statusDiv.textContent = 'WebUSB not supported. Use Chromium-based browsers.';
  statusDiv.className = 'status disabled';
  connectBtn.disabled = true;
}

// State management
let observer: AdbDaemonWebUsbDeviceObserver | null = null;
let currentDevice: AdbDaemonWebUsbDevice | null = null;
let adbClient: Adb | null = null;
let selectedFiles: File[] = [];
// Needed by adbClient
const CredentialStore = new AdbWebCredentialStore();
const UPLOAD_PATH = '/sdcard/Downloads/web-uploads/';

// Update UI based on connection state
function updateStatus(devices: readonly AdbDaemonDevice[] = []) {
  if (devices.length > 0) {
    statusDiv.textContent = 'ADB enabled - Device connected';
    statusDiv.className = 'status enabled';
    uploadSection.style.display = 'block';
    uninstallSection.style.display = 'block';
    loadInstalledApps(); // Load apps when device is connected
  } else {
    statusDiv.textContent = 'No ADB device connected';
    statusDiv.className = 'status disabled';
    uploadSection.style.display = 'none';
    uninstallSection.style.display = 'none';
    selectedFiles = [];
    renderFileList();
  }
}

// Initialize device observer
async function initializeObserver() {
  try {
    observer = await AdbDaemonWebUsbDeviceObserver.create(navigator.usb, {
      filters: [{ vendorId: 0x18d1 }] // Google's vendor ID
    });

    updateStatus(observer.current);

    // Listen for device list changes
    observer.onListChange(devices => {
      updateStatus(devices);
      if (devices.length > 0) {
        currentDevice = devices[0];
      } else {
        currentDevice = null;
        adbClient = null;
      }
    });

    observer.onDeviceAdd(devices => {
      console.log('Device connected:', devices);
    });

    observer.onDeviceRemove(devices => {
      console.log('Device disconnected:', devices);
    });
  } catch (error) {
    console.error('Observer initialization failed:', error);
    statusDiv.textContent = 'Failed to initialize device observer';
  }
}

// Connect to device and get ADB client
async function connectToDevice() {
  if (!currentDevice) {
    console.error('No device available to connect');
    return null;
  }

  try {
    if (adbClient) {
      await adbClient.close();
    }

    let adbConnection = await currentDevice.connect();
    let readable = adbConnection.readable;
    let writable = adbConnection.writable;
    adbClient = new Adb(
      await AdbDaemonTransport.authenticate({
        serial: currentDevice.serial,
        connection: {readable, writable},
        credentialStore: CredentialStore,
      })
    );
    console.log('Connected to ADB device');
    return adbClient;
  } catch (error) {
    console.error('Connection error:', error);
    statusText.textContent = 'Failed to connect to device';
    statusText.className = 'status-text error';
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
  if (!currentDevice || selectedFiles.length === 0) return;


  try {
    // Connect to device if not already connected
    const client = adbClient || await connectToDevice();
    if (!client) return;
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

  const filePath = `${UPLOAD_PATH}${file.name}`;
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
  console.log("Client: ", client);
  console.log("Sync status: ", sync);
  console.log("Files: ", apkFiles);
  statusText.textContent = 'Split APK Not Implemented, TODO!';
  statusText.className = 'status-text not implemented';
}

/** =============================
 *        REINSTALL APK
 *  =============================
 */

async function loadInstalledApps() {
  if (!adbClient) return;

  appList.innerHTML = '<option value="" disabled selected>Loading applications...</option>';
  uninstallBtn.disabled = true;
  refreshBtn.disabled = true;

  try {
    // Directly use pm -3 for third-party apps
    const shell = await adbClient.subprocess.shellProtocol!.spawn(['pm', 'list', 'packages', '-3']);
    var output: string = "";
    // Stdout and stderr will generate two Promise, await them together
    await Promise.all([
      shell.stdout.pipeThrough(new TextDecoderStream()).pipeTo(
        new WritableStream({
          write(chunk) {
            output = chunk;
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

    const exitCode = await shell.exited;

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
  if (!packageName || !adbClient) return;

  uninstallBtn.disabled = true;
  refreshBtn.disabled = true;
  statusText.textContent = `Uninstalling ${packageName}...`;
  statusText.className = 'status-text';

  try {
    const shell = await adbClient.subprocess.shellProtocol!.spawn(['pm', 'uninstall', packageName]);
    var output: string = "";
    // TODO uniform in a function ex spawn command
    // Stdout and stderr will generate two Promise, await them together
    await Promise.all([
      shell.stdout.pipeThrough(new TextDecoderStream()).pipeTo(
        new WritableStream({
          write(chunk) {
            output = chunk;
          },
        }),
      ),
      shell.stderr.pipeThrough(new TextDecoderStream()).pipeTo(
        new WritableStream({
          write(chunk) {
            console.log(["[*] PM LIST ERR ", chunk]);
          },
        }),
      ),
    ]);

    const exitCode = await shell.exited;

    if (exitCode !== 0) {
      throw new Error(`Uninstall failed: ${output}`);
    }

    statusText.textContent = `Uninstalled: ${packageName}`;
    statusText.className = 'status-text success';

    // Refresh app list
    await loadInstalledApps();

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
  } catch (error) {
    console.log('Device selection canceled');
  }
});

// Cleanup on page unload
window.addEventListener('beforeunload', async () => {
  if (observer) {
    observer.stop(); // Release resources
  }

  if (adbClient) {
    await adbClient.close();
  }
});

// Initialize device observer
initializeObserver();
