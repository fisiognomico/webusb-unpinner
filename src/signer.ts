import { ApkSignerV2 } from "@chromeos/android-package-signer";

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
export async function signApk(zipFile: File): Promise<string> {

  const defaultCert: CertInstance = {
    password: "password",
    alias: "alias",
    creator: "scorbuto v0.1.0",
    commonName: "notcommon",
    organizationName: "Internet Widgits Pty Ltd",
    organizationUnit: "OU",
    countryCode: "AU"
  };

  const b64outZip = await signPackageCert(zipFile, defaultCert);
  return b64outZip;
}

async function signPackageCert(zipFile: File, cert: CertInstance): Promise<string> {
  var b64outZip: string = "";
  const packageSigner = new ApkSignerV2(cert.password, cert.alias);
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
