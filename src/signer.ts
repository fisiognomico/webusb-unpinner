import { ApkSignerV2 } from "android-package-signer";

export interface CertInstance {
  password: string,
  alias: string,
  creator: string,
  commonName: string,
  organizationName: string,
  organizationUnit: string,
  countryCode: string
}

// At the moment export only the interface with the hgardcoded certificate
// details, in the future a w3idget to configure the certificate details
// would be implemented.
export async function signApk(
  data: Uint8Array, baseFilename: string): Promise<Uint8Array> {

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
  var b64outZip = await signPackageCert(zipFile, defaultCert);
  // strip data:application/zip;base64,
  b64outZip = b64outZip.split(",")[1];
  const apkFileType = 'application/vnd.android.package-archive';
  const resignedApk = Uint8Array.from(atob(b64outZip), c => c.charCodeAt(0));
  return resignedApk;
}

async function signPackageCert(zipFile: File, cert: CertInstance): Promise<string> {
  var b64outZip: string = "";
  const packageSigner = new ApkSignerV2(cert.password, cert.alias);
  // TODO store by default an hardcoded keystore
  const base64Der = await packageSigner.generateKey({
    commonName: cert.commonName,
    organizationName: cert.organizationName,
    organizationUnit: cert.organizationUnit,
    countryCode: cert.countryCode,
  });

  try {
    b64outZip = await packageSigner.signPackageV2(zipFile, base64Der, cert.creator);
  } catch (error) {
    console.error(error);
  }
  return b64outZip;
}
