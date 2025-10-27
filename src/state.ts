import { Adb, AdbDaemonDevice, AdbDaemonConnection, AdbDaemonTransport} from "@yume-chan/adb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";
// import { Consumable, ReadableWritablePair } from "@yume-chan/stream-extra";
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
  isConfigured: boolean;
  downloadProgress: number;
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
  isConfigured: false,
  downloadProgress: 0
};

export const getDeviceState = () => ({ ...deviceState });

export const setDeviceState = (updates: Partial<DeviceState>) => {
  deviceState = { ...deviceState, ...updates };
  // console.log('Device state updated: ', deviceState);
};

export const connectToDevice = async(): Promise<Adb | null> => {


  const state = getDeviceState();
  if (!state.device) {
    setDeviceState({error: 'No device available to connect' });
    return null;
  }

  try {
    if(state.client && state.isConnected) {
      return state.client;
    }

    setDeviceState({isAuthenticating: true, error: null});

    // Close existing connection if any
    if (state.client) {
      await state.client.close();
    }

    const connection = await state.device.connect();

    const transport = await AdbDaemonTransport.authenticate({
      serial: state.device.serial,
      connection: connection as AdbDaemonConnection,
      credentialStore: state.credentials!,
    });
    const client = new Adb(transport);

    setDeviceState({
      client,
      connection: connection,
      isConnected: true,
      isAuthenticating: false,
      error: null
    });

    return client;

  } catch (error) {
    console.error('Connection error: ', error);

    let errorMessage = 'Connection failed';
    if(error instanceof Error) {
      if (error.message.includes('authentication')) {
        errorMessage = 'Authentication failed. Check your device';
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
        await state.client.close();
    }
    setDeviceState({
        device: null,
        client: null,
        credentials: null,
        isConnected: false,
        isAuthenticating: false,
        error: null
    });
};

export const initializeCredentials = () => {
  const state = getDeviceState();
  if(!state.credentials) {
    setDeviceState({ credentials: new AdbWebCredentialStore() });
  }
};

export const configureDevice = async ()  => {
  const state = getDeviceState();
  if(state.isConfigured) {
    return;
  } else {
    try {
      /* Check presence of the necessary files:
       * Frida Gadget and config
       * Unpinning script + hide debugger
       */
      const adbManager = new AdbManager(state.client!);

      // Check if the scripts folder exists
      const scriptFolder = config.devicePath + 'scripts/';
      const folderStatus = await adbManager.adbRun(["ls", scriptFolder]);
      if (folderStatus.exitCode !== 0 ) {
        console.log(`[configureDevice] creating folder ${scriptFolder}`);
        const mkdirStatus = await adbManager.adbRun(["mkdir", scriptFolder]);
        if (mkdirStatus.exitCode !== 0 ) {
          throw new Error(`Failed to create directory ${scriptFolder} : ${mkdirStatus.output}`);
        }
      }
      const files = [
        'libgadget.so',
        'libgadget.config.so',
        'scripts/hide-debugger.js',
        'scripts/httptoolkit-unpinner.js',
      ];

      const results = await Promise.all(
        files.map(f => adbManager.pushIfNotPresent(f))
      );
    } catch (error) {
      console.error("Error during device configuration", error);
    } finally {
      setDeviceState({ isConfigured: true });
    }
  }
};
