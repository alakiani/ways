import { describe, expect, it } from "vitest";
import { configFile } from "./config";

const cfg = {
  address: "10.77.0.2/32",
  ipv6_placeholder: "fd77::1/128",
  dns: "10.77.0.1",
  bridge_public_key: "BRIDGEKEY=",
  allowed_ips: ["0.0.0.0/0", "::/0"],
  endpoint: { host: "bridge.wayfinder.ir", port: 61873 },
};

describe("config file", () => {
  it("renders one stock WireGuard config for the Bridge Address", () => {
    const f = configFile(cfg, "PRIVATEKEY=");
    expect(f.name).toBe("ways.conf");
    expect(f.text).toBe(
      "[Interface]\n" +
        "PrivateKey = PRIVATEKEY=\n" +
        "Address = 10.77.0.2/32, fd77::1/128\n" +
        "DNS = 10.77.0.1\n" +
        "\n" +
        "[Peer]\n" +
        "PublicKey = BRIDGEKEY=\n" +
        "AllowedIPs = 0.0.0.0/0, ::/0\n" +
        "Endpoint = bridge.wayfinder.ir:61873\n" +
        "PersistentKeepalive = 25\n",
    );
  });

  it("names the tunnel within the Android app's 15 characters", () => {
    expect(configFile(cfg, "K=").name.replace(/\.conf$/, "").length).toBeLessThanOrEqual(15);
  });
});
