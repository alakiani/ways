// A Device's one config, rendered in the browser so the private key never
// leaves it (ADR 0003). It reaches whichever Bridge the Bridge Address
// answers with (ADR 0011).

export interface DeviceConfig {
  address: string;
  ipv6_placeholder: string;
  dns: string;
  bridge_public_key: string;
  allowed_ips: string[];
  endpoint: { host: string; port: number };
}

export interface ConfigFile {
  name: string; // the file name becomes the tunnel's name; Android allows 15 characters
  text: string;
}

export function configFile(cfg: DeviceConfig, privateKey: string): ConfigFile {
  return {
    name: "ways.conf",
    text:
      "[Interface]\n" +
      `PrivateKey = ${privateKey}\n` +
      `Address = ${cfg.address}, ${cfg.ipv6_placeholder}\n` +
      `DNS = ${cfg.dns}\n` +
      "\n" +
      "[Peer]\n" +
      `PublicKey = ${cfg.bridge_public_key}\n` +
      `AllowedIPs = ${cfg.allowed_ips.join(", ")}\n` +
      `Endpoint = ${cfg.endpoint.host}:${cfg.endpoint.port}\n` +
      // Mobile networks drop idle UDP mappings quickly.
      "PersistentKeepalive = 25\n",
  };
}
