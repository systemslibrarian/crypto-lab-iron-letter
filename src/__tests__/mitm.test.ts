import { describe, it, expect } from "vitest";
import { runMitm, TAMPERED_TEXT } from "../crypto/mitm";

const MESSAGE = "Meet me at the north gate at eight. — Alice";

describe("active man-in-the-middle against ECIES", () => {
  it("unauthenticated: Eve substitutes her key and really reads the letter", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: false,
      substitute: true,
      tamper: false,
    });

    expect(run.keySubstituted).toBe(true);
    expect(run.aborted).toBe(false);
    // The attack's payoff: a real AES-GCM open with Eve's private key.
    expect(run.eveRecovered).toBe(MESSAGE);
    // ...and Bob's side looks completely normal.
    expect(run.bobReceived).toBe(MESSAGE);
    expect(run.bobSawAlteredText).toBe(false);
  });

  it("unauthenticated: the two sides derive DIFFERENT secrets", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: false,
      substitute: true,
      tamper: false,
    });

    expect(run.aliceSecret).not.toBeNull();
    expect(run.bobSecret).not.toBeNull();
    expect(run.aliceSecret!.length).toBe(32);
    expect(run.bobSecret!.length).toBe(32);
    expect(run.secretsMatch).toBe(false);
    expect(Array.from(run.aliceSecret!)).not.toEqual(Array.from(run.bobSecret!));
    // Bob cannot open the envelope Alice actually produced — real tag failure.
    expect(run.bobCanOpenAliceEnvelope).toBe(false);
  });

  it("unauthenticated: Eve can put her own words in Bob's hands", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: false,
      substitute: true,
      tamper: true,
    });

    expect(run.eveRecovered).toBe(MESSAGE);
    expect(run.bobReceived).toBe(TAMPERED_TEXT);
    expect(run.bobSawAlteredText).toBe(true);
  });

  it("unauthenticated: the skipped check WOULD have caught it", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: false,
      substitute: true,
      tamper: false,
    });

    expect(run.signatureChecked).toBe(false);
    expect(run.signatureWouldVerify).toBe(false);
    // Control: the check is capable of passing, so `false` above means
    // "Eve's key", not "verification is broken".
    expect(run.genuineKeyVerifies).toBe(true);
  });

  it("authenticated: the SAME attack is defeated before anything is sealed", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: true,
      substitute: true,
      tamper: true,
    });

    expect(run.signatureChecked).toBe(true);
    expect(run.signatureWouldVerify).toBe(false);
    expect(run.genuineKeyVerifies).toBe(true);
    expect(run.aborted).toBe(true);
    expect(run.abortReason).toMatch(/verification/i);
    // The whole point: nothing leaked and nothing was forged.
    expect(run.eveRecovered).toBeNull();
    expect(run.bobReceived).toBeNull();
    expect(run.aliceEnvelopeB64).toBeNull();
    expect(run.bobSawAlteredText).toBe(false);
  });

  it("authenticated with no attacker: the honest exchange still goes through", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: true,
      substitute: false,
      tamper: false,
    });

    expect(run.keySubstituted).toBe(false);
    expect(run.signatureWouldVerify).toBe(true);
    expect(run.aborted).toBe(false);
    expect(run.secretsMatch).toBe(true);
    expect(run.bobCanOpenAliceEnvelope).toBe(true);
    expect(run.bobReceived).toBe(MESSAGE);
    // Eve's key was never in the exchange, so her decrypt attempt fails.
    expect(run.eveRecovered).toBeNull();
  });

  it("unauthenticated with no attacker: secrets converge (the control run)", async () => {
    const run = await runMitm({
      message: MESSAGE,
      authenticated: false,
      substitute: false,
      tamper: false,
    });

    expect(run.secretsMatch).toBe(true);
    expect(run.aliceSecret).toEqual(run.bobSecret);
    expect(run.eveRecovered).toBeNull();
    expect(run.bobReceived).toBe(MESSAGE);
  });
});
