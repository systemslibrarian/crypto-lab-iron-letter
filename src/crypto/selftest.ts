import * as ecies from "./ecies";
import * as rsa from "./rsa";

export interface SelfTestResult {
  ok: boolean;
  message: string;
}

async function runEciesSelfTest() {
  const plaintext = new TextEncoder().encode("iron-letter-self-test-ecies");
  const recipient = await ecies.generateKeypair();
  const envelope = await ecies.seal(recipient.publicKey, plaintext);
  const decrypted = await ecies.open(recipient.privateKey, envelope);
  const decoded = new TextDecoder().decode(decrypted);
  if (decoded !== "iron-letter-self-test-ecies") {
    throw new Error("ECIES self-test round-trip failed.");
  }
}

async function runRsaSelfTest() {
  const plaintext = new TextEncoder().encode("iron-letter-self-test-rsa");
  const recipient = await rsa.generateKeypair(2048);
  const envelope = await rsa.seal(recipient.publicKey, plaintext);
  const decrypted = await rsa.open(recipient.privateKey, envelope);
  const decoded = new TextDecoder().decode(decrypted);
  if (decoded !== "iron-letter-self-test-rsa") {
    throw new Error("RSA self-test round-trip failed.");
  }
}

export async function runStartupSelfTest(): Promise<SelfTestResult> {
  try {
    await runEciesSelfTest();
    await runRsaSelfTest();
    return {
      ok: true,
      message: "WebCrypto self-check passed",
    };
  } catch (error) {
    return {
      ok: false,
      message: error instanceof Error ? error.message : "WebCrypto self-check failed.",
    };
  }
}
