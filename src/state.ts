import { Adb, AdbDaemonDevice, AdbDaemonConnection, AdbDaemonTransport} from "@yume-chan/adb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
import { AdbManager } from "./adb-manager";
import { config } from "./config";

export interface DeviceState {
  device: AdbDaemonDevice | null;
  client: Adb | null;
  credentials: AdbWebCredentialStore | null;
  connection: AdbDaemonConnection | null;
  isConnected: boolean;
  isAuthenticating: boolean;
  error: string | null;
  isDownloading: boolean;
  deviceReady: boolean;
  downloadProgress: number;
  credentialsReady: boolean;  // NEW: Track if credentials are initialized
}

let deviceState: DeviceState  = {
  device: null,
  client: null,
  credentials: null,
  connection: null,
  isConnected: false,
  isAuthenticating: false,
  error: null,
  isDownloading: false,
  deviceReady: false,
  downloadProgress: 0,
  credentialsReady: false,  // NEW
};

export const getDeviceState = () => ({ ...deviceState });

export const setDeviceState = (updates: Partial<DeviceState>) => {
  deviceState = { ...deviceState, ...updates };
};

/**
 * Ensure credential store is properly initialized
 * AdbWebCredentialStore uses IndexedDB which needs async initialization
 */
async function ensureCredentialsReady(credentials: AdbWebCredentialStore): Promise<boolean> {
  try {
    // Force initialization by attempting to iterate keys
    // This will trigger IndexedDB open if not already done
    const iterator = credentials.iterateKeys();

    // Try to get at least one result to confirm DB is accessible
    const firstResult = await iterator.next();

    // If we got here without error, credentials are ready
    // (firstResult.done being true just means no keys exist yet, which is fine)
    return true;
  } catch (error) {
    console.error('Credential store initialization check failed:', error);
    return false;
  }
}

/**
 * Create and initialize credential store with retry logic
 */
async function createCredentialStore(maxRetries: number = 3): Promise<AdbWebCredentialStore | null> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const credentials = new AdbWebCredentialStore();

      // Wait a small amount for IndexedDB to initialize
      await new Promise(resolve => setTimeout(resolve, 100 * attempt));

      // Verify the store is actually usable
      const isReady = await ensureCredentialsReady(credentials);

      if (isReady) {
        console.log(`Credential store initialized successfully (attempt ${attempt})`);
        return credentials;
      }

      console.warn(`Credential store not ready on attempt ${attempt}, retrying...`);
    } catch (error) {
      console.warn(`Credential store creation failed on attempt ${attempt}:`, error);
    }

    // Exponential backoff between retries
    if (attempt < maxRetries) {
      await new Promise(resolve => setTimeout(resolve, 200 * attempt));
    }
  }

  console.error('Failed to initialize credential store after all retries');
  return null;
}

export const connectToDevice = async(): Promise<Adb | null> => {
  const state = getDeviceState();

  if (!state.device) {
    setDeviceState({error: 'No device available to connect' });
    return null;
  }

  try {
    // Return existing connection if valid
    if (state.client && state.isConnected) {
      return state.client;
    }

    setDeviceState({isAuthenticating: true, error: null});

    // Close existing connection if any
    if (state.client) {
      try {
        await state.client.close();
      } catch (closeError) {
        console.warn('Error closing previous connection:', closeError);
      }
      setDeviceState({ client: null, connection: null, isConnected: false });
    }

    // Ensure credentials are ready before attempting connection
    if (!state.credentials || !state.credentialsReady) {
      console.log('Credentials not ready, initializing...');
      const credentials = await createCredentialStore();

      if (!credentials) {
        throw new Error('Failed to initialize credential store. IndexedDB may be unavailable (private browsing mode?)');
      }

      setDeviceState({ credentials, credentialsReady: true });
    }

    // Double-check credentials after potential re-initialization
    const currentState = getDeviceState();
    if (!currentState.credentials) {
      throw new Error('Credential store is null after initialization');
    }

    // Verify credentials are actually usable before connecting
    const credentialsValid = await ensureCredentialsReady(currentState.credentials);
    if (!credentialsValid) {
      // Reset and retry credential initialization
      console.warn('Credentials invalid, recreating...');
      setDeviceState({ credentials: null, credentialsReady: false });

      const newCredentials = await createCredentialStore();
      if (!newCredentials) {
        throw new Error('Failed to recreate credential store');
      }

      setDeviceState({ credentials: newCredentials, credentialsReady: true });
    }

    const finalState = getDeviceState();

    console.log('Connecting to device...');
    const connection = await state.device.connect();

    console.log('Authenticating...');
    const transport = await AdbDaemonTransport.authenticate({
      serial: state.device.serial,
      connection: connection as AdbDaemonConnection,
      credentialStore: finalState.credentials!,
    });

    const client = new Adb(transport);

    setDeviceState({
      client,
      connection: connection,
      isConnected: true,
      isAuthenticating: false,
      error: null
    });

    console.log('Connected successfully');
    return client;

  } catch (error) {
    console.error('Connection error:', error);

    let errorMessage = 'Connection failed';

    if (error instanceof Error) {
      // Handle specific error cases
      if (error.message.includes('iterateKeys')) {
        errorMessage = 'Credential store error. Try refreshing the page.';
        // Reset credentials state to force re-initialization on next attempt
        setDeviceState({ credentials: null, credentialsReady: false });
      } else if (error.message.includes('authentication')) {
        errorMessage = 'Authentication failed. Check your device for USB debugging prompt.';
      } else if (error.message.includes('IndexedDB')) {
        errorMessage = 'Browser storage unavailable. Disable private browsing mode.';
      } else {
        errorMessage = error.message;
      }
    }

    setDeviceState({
      isConnected: false,
      isAuthenticating: false,
      error: errorMessage,
    });

    return null;
  }
};


export const disconnectDevice = async () => {
  const state = getDeviceState();

  if (state.client) {
    try {
      await state.client.close();
    } catch (error) {
      console.warn('Error during disconnect:', error);
    }
  }

  setDeviceState({
    device: null,
    client: null,
    // Keep credentials for reuse - don't reset them
    // credentials: null,
    // credentialsReady: false,
    connection: null,
    isConnected: false,
    isAuthenticating: false,
    error: null,
    deviceReady: false,
  });
};

/**
 * Initialize credentials asynchronously
 * Call this early in app startup
 */
export const initializeCredentials = async (): Promise<boolean> => {
  const state = getDeviceState();

  if (state.credentials && state.credentialsReady) {
    return true;
  }

  try {
    const credentials = await createCredentialStore();

    if (credentials) {
      setDeviceState({ credentials, credentialsReady: true });
      console.log('Credentials initialized successfully');
      return true;
    }

    console.error('Failed to initialize credentials');
    return false;
  } catch (error) {
    console.error('Error initializing credentials:', error);
    setDeviceState({ error: 'Failed to initialize authentication' });
    return false;
  }
};

export const configureDevice = async ()  => {
  const state = getDeviceState();

  if (state.deviceReady) {
    return;
  }

  if (!state.client) {
    console.error('[configureDevice] No client available');
    return;
  }

  try {
    /* Check presence of the necessary files:
     * Frida Gadget and config
     * Unpinning script + hide debugger
     */
    const adbManager = new AdbManager(state.client);

    // Check if the scripts folder exists
    const scriptFolder = config.devicePath + 'scripts/';
    const folderStatus = await adbManager.adbRun(["ls", scriptFolder]);

    if (folderStatus.exitCode !== 0) {
      console.log(`[configureDevice] creating folder ${scriptFolder}`);
      const mkdirStatus = await adbManager.adbRun(["mkdir", scriptFolder]);

      if (mkdirStatus.exitCode !== 0) {
        throw new Error(`Failed to create directory ${scriptFolder}: ${mkdirStatus.output}`);
      }
    }

    const files = [
      'libgadget.so',
      'libgadget.config.so',
      'scripts/hide-debugger.js',
    ];

    await Promise.all(
      files.map(f => adbManager.pushIfNotPresent(f))
    );

    setDeviceState({ deviceReady: true });
  } catch (error) {
    console.error("Error during device configuration:", error);
    setDeviceState({
      deviceReady: false,
      error: `Device configuration failed: ${error instanceof Error ? error.message : String(error)}`
    });
  }
};
