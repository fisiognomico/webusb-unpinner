import { AdbDaemonWebUsbDeviceObserver} from "@yume-chan/adb-daemon-webusb";
import { Adb, AdbSync } from "@yume-chan/adb";
import { ReadableStream, TextDecoderStream, WritableStream } from "@yume-chan/stream-extra";
import { PackageManager } from "@yume-chan/android-bin";
import JSZip from "jszip";
import { saveAs } from 'file-saver';

import { getDeviceState, setDeviceState, connectToDevice, disconnectDevice, initializeCredentials, configureDevice } from "./state";
import { signApk } from "./signer";
import { AdbManager } from "./adb-manager";
import { initFridaGadget } from "./jdwp";
import { enableDebuggableFlag } from "./apk-patcher";

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
const APK_UPLOAD_PATH = '/data/local/tmp/';

interface ApkDescriptor {
  name: string,
  path: string,
  size: number
}

interface ApkFile {
    path: string,
    data: Uint8Array
}

async function updateStatus() {
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

    // Configure device an load apps only when fully connected
    if (state.isConnected && !state.isAuthenticating) {
      statusDiv.textContent = 'Configuring device - Please wait...';
      await configureDevice();
      statusDiv.textContent = 'Device configured!';
      await loadInstalledApps();
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
    await updateStatus();

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

    return observer;
  } catch (error) {
    console.error('Observer initialization failed:', error);
    setDeviceState({ error: 'Failed to initialize device observer' });
    await updateStatus();
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

// Install functionality
uploadBtn.addEventListener('click', async () => {
  if (selectedFiles.length === 0) return;

  const state = getDeviceState();
  if(!state.client) return;
  const adbManager = new AdbManager(state.client);

  try {
    // Connect to device if not already connected
    // Get ADB sync client

    // Check if we are installing APKs
    const isApkInstall = selectedFiles.every(file => file.name.toLowerCase().endsWith('.apk'))

    if (isApkInstall) {
        statusText.textContent = `Installing: ${selectedFiles.length} packets...`;
        statusText.className = 'status-text';
        await adbManager.installSplitApk(selectedFiles);

      statusText.textContent = 'App installed successfully!';
      statusText.className = 'status-text success';
    } else {
      statusText.textContent = "File format not recognized, only APKs are supported!"
      statusText.className = 'status-text error';
    }
    resetFileInput();

  } catch (error) {
    console.error('Installation error:', error);
    statusText.textContent = `Installation failed: ${error instanceof Error ? error.message : String(error)}`;
    statusText.className = 'status-text error';
  } finally {
    progressBar.style.width = '0%';
  }
});

async function loadInstalledApps() {
  let adbManager: AdbManager | null = null;

  const state = getDeviceState();
  if(state.client) {
    adbManager = new AdbManager(state.client);
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
    const {output, exitCode}  = await adbManager.adbRun(adbCommand);

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
  const confirmed = confirm(
    `⚠️  WARNING:\n\n` +
    `• App data will be lost\n` +
    `• AndroidManifest will be modified\n` +
    `• Frida gadget will be injected\n` +
    `• App will be reinstalled\n\n` +
    `This cannot be undone. Continue?`
  );
  if(!confirmed) return;

  const packageName = appList.value;
  if (!packageName) return;
  let adbManager: AdbManager | null = null;

  const state = getDeviceState();
  if(state.client) {
    adbManager = new AdbManager(state.client);
  } else {
    console.log("[+] Load Installed apps called without connected client");
    return;
  }

  uninstallBtn.disabled = true;
  refreshBtn.disabled = true;
  statusText.textContent = `Uninstalling ${packageName}...`;
  statusText.className = 'status-text';

  // TODO show a WARNING that this will delete app's data
  downloadSection.style.display = 'block';
  downloadSection.textContent = `Preparing to reinstall ${packageName}...`;

  try {
    const apkFiles = await backupApk(adbManager, packageName);

    // Now I can uninstall the app
    const adbCommand = ['pm', 'uninstall', packageName];
    const {output, exitCode} = await adbManager.adbRun(adbCommand);

    if (exitCode !== 0) {
      throw new Error(`Uninstall failed: ${output}`);
    }
    statusText.textContent = `Uninstalled: ${packageName}`;
    statusText.className = 'status-text success';

    const zip = new JSZip();
    const loaded = await zip.loadAsync(apkFiles[0].data);
    if (!loaded.files['AndroidManifest.xml']) {
      throw new Error('AndroidManifest.xml not found in APK');
    }
    const manifestBuffer = await loaded.files['AndroidManifest.xml'].async('arraybuffer');

    const modifiedManifest = enableDebuggableFlag(manifestBuffer);

    loaded.file('AndroidManifest.xml', modifiedManifest);

    const patchedApk = await loaded.generateAsync({
      type: 'arraybuffer',
      compression: 'DEFLATE'
    });
    console.log(`💾 Patched APK... `);
    const patchedApkArray = new Uint8Array(patchedApk);

    // TODO support SPLIT APKS!
    const resignedApk = await signApk(patchedApkArray, packageName + ".apk");
    statusText.textContent = `Resigned: ${packageName}`;
    statusText.className = 'status-text success';

    // Reinstall resigned APK
    const remotePath = `${APK_UPLOAD_PATH}/app.apk`;
    await  adbManager.installApk(resignedApk, remotePath);
    statusText.textContent = `Reinstalled: ${packageName}`;
    statusText.className = 'status-text success';

    // Now let's try to load Frida Gadget
    await initFridaGadget(state, packageName);
    statusText.textContent = "Loaded frida gadget!";
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

// APK backup function
async function backupApk(adbManager: AdbManager, packageName: string): Promise<ApkFile[]> {
  try {
    setDeviceState({isDownloading: true, downloadProgress: 0});

    // Get APK paths
    const apkPaths = await adbManager.getAPKPaths(packageName);

    // Download APKs
    const apkFiles: ApkFile[] = [];

    for (let i = 0; i < apkPaths.length; i++) {
      const path = apkPaths[i];
      downloadStatus.textContent = `Fetching APK (${i+1}/${apkPaths.length})...`;

      const data = await adbManager.pullFromDevice(path, (progress) => {
        const totalProgress = Math.round(((i + progress) / apkPaths.length) * 100);
        downloadProgressBar.style.width = `${totalProgress}%`;
        setDeviceState({ downloadProgress: totalProgress });
      });
      apkFiles.push({path, data});
    }

    // Create filename with version
    // const versionStr = packageInfo.versionName.replace(/[^a-z0-9]/gi, '_');
    // const baseFilename = `${packageName}_${versionStr}`;
    downloadStatus.textContent = `Fetched ${apkFiles.length} APK file(s)`;
    return apkFiles;


  } catch (error) {
    throw error;
  } finally {
    setDeviceState({ isDownloading: false, downloadProgress: 0});
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
