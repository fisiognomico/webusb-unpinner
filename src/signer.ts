import { ApkSignerV2 } from "android-package-signer";
import { derCertficate } from "./config";

export interface CertInstance {
  password: string,
  alias: string,
  creator: string,
  commonName: string,
  organizationName: string,
  organizationUnit: string,
  countryCode: string
}

// At the moment export only the interface with the hardcoded certificate
// details, in the future a widget to configure the certificate details
// would be implemented.
export async function signApk(
  data: Uint8Array,
  baseFilename: string,
  generateKey: boolean = false
): Promise<Uint8Array> {

  const defaultCert: CertInstance = {
    password: "password",
    alias: "alias",
    creator: "scorbuto v0.1.0",
    commonName: "notcommon",
    organizationName: "Internet Widgits Pty Ltd",
    organizationUnit: "OU",
    countryCode: "AU"
  };

  var zipFile = new File([data as BlobPart], baseFilename + ".apk");
  var b64outZip = await signPackageCert(zipFile, defaultCert, generateKey);
  // strip data:application/zip;base64,
  b64outZip = b64outZip.split(",")[1];
  const apkFileType = 'application/vnd.android.package-archive';
  const resignedApk = Uint8Array.from(atob(b64outZip), c => c.charCodeAt(0));
  return resignedApk;
}

async function signPackageCert(
  zipFile: File,
  cert: CertInstance,
  generateKey: boolean
): Promise<string> {
  var b64outZip: string = "";
  const packageSigner = new ApkSignerV2(cert.password, cert.alias);
  let base64Der: string;
  if (generateKey) {
    base64Der = await packageSigner.generateKey({
      commonName: cert.commonName,
      organizationName: cert.organizationName,
      organizationUnit: cert.organizationUnit,
      countryCode: cert.countryCode,
    });
  } else {
    base64Der = derCertficate;
  }

  try {
    b64outZip = await packageSigner.signPackageV2(zipFile, base64Der, cert.creator);
  } catch (error) {
    console.error(error);
  }
  return b64outZip;
}
