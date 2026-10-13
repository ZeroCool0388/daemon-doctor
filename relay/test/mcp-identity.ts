import vector from "../../testdata/mcp-registration-v1.json";

export const ownerID = vector.mac_id;
export const ownerProof = { secret_hash: vector.secret_hash, public_key: vector.public_key, signature: vector.signature };
const encode = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

export async function identity(secretHash: string) {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey) as ArrayBuffer);
  const prefix = new TextEncoder().encode("daemon-doctor/mcp-identity/v1\n");
  const keyIDBytes = new Uint8Array(prefix.length + raw.length);
  keyIDBytes.set(prefix); keyIDBytes.set(raw, prefix.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", keyIDBytes));
  const id = [...digest.slice(0, 16)].map(b => b.toString(16).padStart(2, "0")).join("");
  const publicKey = encode(raw.buffer);
  const message = new TextEncoder().encode(`daemon-doctor/mcp-link/v1\nmac_id=${id}\npublic_key=${publicKey}\nsecret_hash=${secretHash}`);
  const signature = encode(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message));
  return { id, proof: { secret_hash: secretHash, public_key: publicKey, signature } };
}
