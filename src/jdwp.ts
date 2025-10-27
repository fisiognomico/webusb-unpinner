import {AdbDaemonWebUsbDeviceManager} from "@yume-chan/adb-daemon-webusb";
import {DebugManager, WebUSBConfig} from "libjdwp";
import {DeviceState} from "./state";

export async function initFridaGadget(state: DeviceState, targetApp: string): Promise<void> {
    const libFridaGadget = "libgadget.so";
    const libFridaConfig = "libgadget.config.so";
    try {
        // Create debug manager
        const config: WebUSBConfig = {
            type: "web",
            serverClient: state.connection!,
            deviceSerial: state.device!.serial!,
            adb: state.client!
        };
        const debugManager = new DebugManager<WebUSBConfig>(config);

        // Set app in debug mode
        const setPackageDebugMode = `am set-debug-app -w ${targetApp}`;
        await debugManager.executeCommand(setPackageDebugMode);

        // Find Main Activity
        const findMainActivity = `cmd package resolve-activity --brief ${targetApp}`;
        const lines = await debugManager.executeCommand(findMainActivity);
        const lastLine = lines[1];
        let mainActivity = "";
        if (lastLine.includes('/')) {
            mainActivity = lastLine.trim();
        } else {
            // Switch to default name
            console.warn(`[+] Issue with cmd parsing ${lines}`);
            mainActivity = `${targetApp}/.MainActivity`;
        }
        console.log(`MainActivity: ${mainActivity}`);

        // Start app and wait for the debugger
        console.log("Starting app (will wait for the debugger)...");
        const spawnActivity = `am start -n ${mainActivity}`;
        await debugManager.executeCommand(spawnActivity);

        // Small delay to ensure app is started
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Wait for the App PID
        console.log("Waiting for the app PID...");
        const appPid = await debugManager.findAppPid(targetApp);
        console.log(`${targetApp} started (PID: ${appPid})`);
        const debugSession = await debugManager.startDebugging(targetApp, appPid);

        // Set breakpoint on Activity.onCreate()
        const activityClass = "Landroid/app/Activity;";
        const createMethod = "onCreate";
        const {requestId, threadId} = await debugSession.client.setBreakpointAndWait(
            activityClass,
            createMethod
        );
        console.log(`Breakpoint hit! Thread ${threadId} is suspended\n`);
        try {
            // Check frida gadget presence
            console.log('Checking gadget presence...');
            const exitCode1 = await debugManager.executeJDWP(
                appPid,
                'ls -la /data/local/tmp/' + libFridaGadget
            );
            console.log(`✅ ls gadget exit code: ${exitCode1}\n`);

            // Copy frida gadget to app data directory
            console.log('Copying frida gadget to app data...');
            const exitCode2 = await debugManager.executeJDWP(
                appPid,
                `cp /data/local/tmp/${libFridaGadget} /data/data/${targetApp}/${libFridaGadget}`
            );
            console.log(`✅ cp gadget exit code: ${exitCode2}\n`);

            // Check  gadget presence
            console.log('Checking gadget config...');
            const exitCode3 = await debugManager.executeJDWP(
                appPid,
                `ls /data/local/tmp/${libFridaConfig}`
            );
            console.log(`✅ ls config exit code: ${exitCode3}\n`);

            // Copy gadget config
            console.log('Copying gadget config...');
            const exitCode4 = await debugManager.executeJDWP(
                appPid,
                `cp /data/local/tmp/${libFridaConfig} /data/data/${targetApp}/${libFridaConfig}`
            );
            console.log(`✅ cp config exit code: ${exitCode4}\n`);


            // Load frida gadget library
            console.log('Loading Frida gadget...');
            await debugManager.loadLibraryJDWP(
                appPid,
                `/data/data/${targetApp}/${libFridaGadget}`
            );
            console.log(`✅ Loaded Frida gadget.`);
        } finally {
            console.log('\n=== Resuming Thread ===');
            await debugSession.client.resumeVM();
            console.log('✅ Thread resumed, app continues\n');
        }
    } catch (error: any) {
        console.error("Error: ", error);
    }
}
