import { Adb, AdbDaemonDevice, AdbDaemonTransport, AdbPacketData, AdbPacketInit} from "@yume-chan/adb";
import { Consumable, ReadableWritablePair } from "@yume-chan/stream-extra";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";

export interface DeviceState {
  device: AdbDaemonDevice | null;
  client: Adb | null;
  credentials: AdbWebCredentialStore | null;
  isConnected: boolean;
  isAuthenticating: boolean;
  error: string | null;
  isDownloading: boolean;
  downloadProgress: number;
}

let deviceState: DeviceState  = {
  device: null,
  client: null,
  credentials: null,
  isConnected: false,
  isAuthenticating: false,
  error: null,
  isDownloading: false,
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
      connection: connection as ReadableWritablePair<AdbPacketData, Consumable<AdbPacketInit>>,
      credentialStore: state.credentials!,
    });
    const client = new Adb(transport);

    setDeviceState({
      client,
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
