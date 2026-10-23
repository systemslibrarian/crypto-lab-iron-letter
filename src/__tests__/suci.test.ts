import { describe, expect, it } from "vitest";
import {
  deriveProfileA,
  fromHex,
  generateHomeNetworkKeys,
  hex,
  openProfileA,
  packMsin,
  sealProfileA,
  sealWithShared,
  unpackMsin,
} from "../crypto/suci";

// ETSI TS 133 501 V19.7.0 (2026-08), Annex C.4.3.1, IMSI Profile A.
const shared = fromHex("028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a");
const ephemeralPublic = fromHex("b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d");

describe("5G SUCI Profile A educational exhibit", () => {
  it("packs the official IMSI-based MSIN with its final F nibble", () => {
    const packed = packMsin("001002086");
    expect(hex(packed)).toBe("00012080f6");
    expect(unpackMsin(packed)).toBe("001002086");
    expect(hex(packMsin("12"))).toBe("21");
    expect(unpackMsin(fromHex("21"))).toBe("12");
    expect(() => unpackMsin(fromHex("fa"))).toThrow();
  });

  it("recomputes official Profile A derived keys, AES-CTR ciphertext and 64-bit MAC", async () => {
    const derived = await deriveProfileA(shared, ephemeralPublic);
    expect(hex(derived.encryptionKey)).toBe("2ba342cabd2b3b1e5e4e890da11b65f6");
    expect(hex(derived.initialCounter)).toBe("e2622cb0cdd08204e721c8ea9b95a7c6");
    expect(hex(derived.macKey)).toBe("d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2");
    const result = await sealWithShared(shared, ephemeralPublic, packMsin("001002086"));
    expect(hex(result.ciphertext)).toBe("cb02352410");
    expect(hex(result.mac)).toBe("cddd9e730ef3fa87");
    expect(hex(result.schemeOutput)).toBe(
      "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
    );
  });

  it("uses a fresh X25519 ephemeral value and lets only the home key deconceal", async () => {
    const home = await generateHomeNetworkKeys();
    const wrongHome = await generateHomeNetworkKeys();
    const first = await sealProfileA(home.publicKey, "001002086");
    const second = await sealProfileA(home.publicKey, "001002086");
    expect(hex(first.schemeOutput)).not.toBe(hex(second.schemeOutput));
    expect(await openProfileA(home.privateKey, first.schemeOutput)).toBe("001002086");
    await expect(openProfileA(wrongHome.privateKey, first.schemeOutput)).rejects.toThrow("MAC mismatch");
  });

  it("rejects a changed encrypted subscriber digit before decryption", async () => {
    const home = await generateHomeNetworkKeys();
    const sealed = await sealProfileA(home.publicKey, "001002086");
    const tampered = sealed.schemeOutput.slice();
    tampered[32] = tampered[32]! ^ 1;
    await expect(openProfileA(home.privateKey, tampered)).rejects.toThrow("MAC mismatch");
  });
});
