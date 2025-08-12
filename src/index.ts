  import { AdbDaemonWebUsbDevice, AdbDaemonWebUsbDeviceObserver, AdbDaemonWebUsbDeviceManager } from "@yume-chan/adb-daemon-webusb";
import { Adb, AdbDaemonDevice, AdbSync, AdbDaemonTransport } from "@yume-chan/adb";
import { ReadableStream, ReadableWritablePair } from "@yume-chan/stream-extra";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import { PackageManager } from "@yume-chan/android-bin";

const statusDiv = document.getElementById('status')!;
const connectBtn = document.getElementById('connectBtn') as HTMLButtonElement;
const uploadSection = document.getElementById('uploadSection')!;
const uploadArea = document.getElementById('uploadArea')!;
const fileInput = document.getElementById('fileInput') as HTMLInputElement;
const uploadBtn = document.getElementById('uploadBtn') as HTMLButtonElement;
const progressBar = document.getElementById('progressBar') as HTMLDivElement;
const statusText = document.getElementById('statusText')!;
const fileList = document.getElementById('fileList')!;

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
  } else {
    statusDiv.textContent = 'No ADB device connected';
    statusDiv.className = 'status disabled';
    uploadSection.style.display = 'none';
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

    // TODO currentDevice?
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
fileInput.addEventListener('change', handleFileSelect);

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

  if (e.dataTransfer?.files) {
    fileInput.files = e.dataTransfer.files;
    handleFileSelect();
  }
});

function handleFileSelect() {
  if (!fileInput.files || fileInput.files.length === 0) return;

  selectedFiles = Array.from(fileInput.files);
  renderFileList();
  uploadBtn.disabled = false;
}

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
    }

    // Reset selection
    selectedFiles = [];
    renderFileList();
    uploadBtn.disabled = true;
    fileInput.value = '';

  } catch (error) {
    console.error('Upload error:', error);
    statusText.textContent = `Upload failed: ${error instanceof Error ? error.message : String(error)}`;
    statusText.className = 'status-text error';
  } finally {
    progressBar.style.width = '0%';
  }
});

async function uploadFile(sync: AdbSync, file: File) {
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
