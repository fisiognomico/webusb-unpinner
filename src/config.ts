import { ensureTrailingSlash } from "./utils";
import { signDerCertficate } from "./const/cert";

declare const __SERVER_URI__: string;
declare const __NODE_ENV__: string;
declare const __DEVICE_PATH__: string;

export const config = {
  serverUri: ensureTrailingSlash(__SERVER_URI__),
  nodeEnv: __NODE_ENV__,
  isDev: __NODE_ENV__ === 'development',
  devicePath: ensureTrailingSlash(__DEVICE_PATH__),
  signDerCertficate: signDerCertficate,
  autoConfigUrl: 'static/proxy-config.json',
} as const;

export function validateProxyConfig(proxy: ProxyConfig): boolean {
  // Validate IP address or hostname
  const addressPattern = /^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$/;
  if (!proxy.address || !addressPattern.test(proxy.address)) {
    console.error('Invalid proxy address format');
    return false;
  }

  // Validate port
  if (!proxy.port || proxy.port < 1 || proxy.port > 65535) {
    console.error('Invalid proxy port');
    return false;
  }

  // Validate certificate format (basic PEM check)
  if (!proxy.caCertificate || 
      !proxy.caCertificate.includes('-----BEGIN CERTIFICATE-----') ||
      !proxy.caCertificate.includes('-----END CERTIFICATE-----')) {
    console.error('Invalid certificate format');
    return false;
  }

  return true;
}

// Sanitize configuration for injection into scripts
export function sanitizeProxyConfig(proxy: ProxyConfig): ProxyConfig {
  return {
    address: proxy.address?.replace(/[^a-zA-Z0-9.-]/g, '') || null,
    port: proxy.port,
    caCertificate: proxy.caCertificate?.replace(/\r/g, '') || null
  };
}


export async function loadAutoConfiguration(): Promise<ProxyConfig | null> {
  try {
    const response = await fetch(config.serverUri + config.autoConfigUrl);
    if (!response.ok) {
      console.log('No auto-configuration file found');
      return null;
    }

    const proxyConfig = await response.json() as ProxyConfig;

    // Validate the configuration
    if (!validateProxyConfig(proxyConfig)) {
      console.error('Invalid auto-configuration');
      return null;
    }

    return proxyConfig;
  } catch (error) {
    console.log('Auto-configuration not available:', error);
    return null;
  }
}


export interface ProxyConfig {
  address: string | null;
  port: number | null;
  caCertificate: string | null;
}

export function generateFridaConfigJs(proxy: ProxyConfig): string {
  const sanitized = sanitizeProxyConfig(proxy);

  const certPem = sanitized.caCertificate || '';
  const host = sanitized.address || '127.0.0.1';
  const port = sanitized.port || '8080';

  return `// Automatically generated proxy configuration for Frida scripts
const CERT_PEM = \`${certPem}\`;
const PROXY_HOST = '${host}';
const PROXY_PORT = ${port};
`;

}


