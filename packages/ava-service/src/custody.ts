import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import type { Hex } from "viem";

const OPERATOR = fileURLToPath(new URL("./python/custody_operator.py", import.meta.url));
const BRIDGE = fileURLToPath(new URL("./python/material_custody.py", import.meta.url));
const MAX_WIRE_BYTES = 4 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024;
const HEX32 = /^0x[0-9a-f]{64}$/;

export interface MaterialReceipt {
  resourceId: Hex;
  appId: Hex;
  caseId: Hex;
  policyId: 1;
  materialClass: Hex;
  ciphertextHash: Hex;
  uri: string;
}

export interface MaterialCustody {
  stage(caseId: Hex, materialClass: Hex, payload: Buffer, metadata: Record<string, unknown>): Promise<MaterialReceipt>;
  read(receipt: MaterialReceipt): Promise<{ payload: Buffer; metadata: Record<string, unknown> }>;
}

export type CustodyCredentials = { masterKeyFile: string; credentialProfileFile?: never }
  | { credentialProfileFile: string; masterKeyFile?: never };
export type LocalCustodyOptions = { appId: Hex; vaultPath: string; pythonPath?: string; rootDirectory?: string } & CustodyCredentials;
export type CustodyOperatorRequest = ({ operation: "prepare"; newMasterKeyFile: string;
  expectedReceipts: readonly MaterialReceipt[] } & CustodyCredentials)
  | ({ operation: "export-profile" } & CustodyCredentials)
  | { operation: "install-profile"; activeKeyFile: string; profile: CustodyPortableProfile }
  | { operation: "activate"; generationId: string } | { operation: "inspect" };
export interface CustodyPortableProfile { version: 1; generationId: string; keyIds: string[];
  manifestHash: string; nonce: string; sealedHistory: string }
export interface CustodyStatus { mode: "legacy" | "profile" | "prepared" | "activation_incomplete" | "portable";
  generationId?: string; keyCount?: number; recordCount?: number; expectedReceiptCount?: number;
  candidateGenerationIds?: string[]; profile?: CustodyPortableProfile }

/** Trusted, stopped local operator only. This creates no application read authority. */
export async function runCustodyOperator(options: { vaultPath: string; pythonPath?: string; rootDirectory?: string },
  operation: CustodyOperatorRequest): Promise<CustodyStatus> {
  const result = await callPython(OPERATOR, { ...operation, vaultPath: options.vaultPath },
    options.pythonPath ?? "python3", resolve(options.rootDirectory ?? process.cwd()), 300_000);
  if (!["legacy", "profile", "prepared", "activation_incomplete", "portable"].includes(String(result.mode))) throw custodyError();
  return result as unknown as CustodyStatus;
}

/** Local encrypted material could not be read; this says nothing about its recorded Native effect. */
export class MaterialCustodyUnavailableError extends Error {
  constructor() { super("Draft custody request failed (E_CUSTODY)"); this.name = "DraftCustodyUnavailableError"; }
}

/** Optional Node/Python storage adapter. The application authorizes every access; custody creates no chain authority. */
export class LocalMaterialCustody implements MaterialCustody {
  private readonly appId: Hex;
  private readonly vaultPath: string;
  private readonly credentials: CustodyCredentials;
  private readonly pythonPath: string;
  private readonly rootDirectory: string;

  constructor(options: LocalCustodyOptions) {
    if (!isHex32(options.appId)) throw custodyError();
    this.appId = options.appId;
    this.vaultPath = options.vaultPath;
    const legacy = typeof options.masterKeyFile === "string" && options.masterKeyFile.length > 0;
    const profile = typeof options.credentialProfileFile === "string" && options.credentialProfileFile.length > 0;
    if (legacy === profile || (legacy && options.credentialProfileFile !== undefined)
      || (profile && options.masterKeyFile !== undefined)) throw custodyError();
    this.credentials = legacy ? { masterKeyFile: options.masterKeyFile! }
      : { credentialProfileFile: options.credentialProfileFile! };
    this.pythonPath = options.pythonPath ?? "python3";
    this.rootDirectory = resolve(options.rootDirectory ?? process.cwd());
  }

  async stage(caseId: Hex, materialClass: Hex, payload: Buffer,
              metadata: Record<string, unknown>): Promise<MaterialReceipt> {
    if (!isHex32(caseId) || !isHex32(materialClass) || !Buffer.isBuffer(payload)
        || payload.length > MAX_PLAINTEXT_BYTES || !isRecord(metadata)) throw custodyError();
    const result = await this.call({
      operation: "put", vaultPath: this.vaultPath, ...this.credentials,
      appId: this.appId, caseId, materialClass,
      payloadBase64: payload.toString("base64"), metadata,
    });
    if (!isReceipt(result, this.appId) || result.caseId !== caseId || result.materialClass !== materialClass) throw custodyError();
    return result;
  }

  async read(receipt: MaterialReceipt): Promise<{ payload: Buffer; metadata: Record<string, unknown> }> {
    if (!isReceipt(receipt, this.appId)) throw custodyError();
    const result = await this.call({
      operation: "read", vaultPath: this.vaultPath, ...this.credentials, receipt,
    });
    if (!isRecord(result) || typeof result.payloadBase64 !== "string" || !isRecord(result.metadata)) {
      throw custodyError();
    }
    const payload = decodeCanonicalBase64(result.payloadBase64);
    const metadataBytes = Buffer.from(JSON.stringify(result.metadata), "utf8");
    if (payload.length + metadataBytes.length + 4 > MAX_PLAINTEXT_BYTES) throw custodyError();
    return { payload, metadata: result.metadata };
  }

  async verifyConfiguration(): Promise<CustodyStatus> {
    const result = await this.call({ operation: "check", vaultPath: this.vaultPath, ...this.credentials });
    if (result.mode !== "legacy" && result.mode !== "profile") throw custodyError();
    return result as unknown as CustodyStatus;
  }

  private call(request: Record<string, unknown>): Promise<Record<string, unknown>> {
    return callPython(BRIDGE, request, this.pythonPath, this.rootDirectory);
  }
}

function callPython(bridge: string, request: Record<string, unknown>, pythonPath: string,
  rootDirectory: string, timeoutMs = 30_000): Promise<Record<string, unknown>> {
    let input: Buffer;
    try {
      input = Buffer.from(JSON.stringify(request), "utf8");
    } catch {
      return Promise.reject(custodyError());
    }
    if (input.length > MAX_WIRE_BYTES) return Promise.reject(custodyError());

    return new Promise((resolveResult, rejectResult) => {
      const child = spawn(pythonPath, [bridge], {
        cwd: rootDirectory, stdio: ["pipe", "pipe", "ignore"], shell: false,
        env: { ...process.env, AVA_CUSTODY_ROOT: rootDirectory, PYTHONDONTWRITEBYTECODE: "1" },
      });
      const chunks: Buffer[] = [];
      let received = 0;
      let settled = false;
      const reject = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        rejectResult(custodyError());
      };
      const timer = setTimeout(reject, timeoutMs);
      child.stdout.on("data", (chunk: Buffer) => {
        received += chunk.length;
        if (received > MAX_WIRE_BYTES) return reject();
        chunks.push(chunk);
      });
      child.on("error", reject);
      child.on("close", (code) => {
        clearTimeout(timer);
        if (settled) return;
        if (code !== 0) return reject();
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!isRecord(result)) return reject();
          settled = true;
          resolveResult(result);
        } catch {
          reject();
        }
      });
      child.stdin.on("error", reject);
      child.stdin.end(input);
    });
}

function custodyError(): Error {
  return new MaterialCustodyUnavailableError();
}

function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && HEX32.test(value) && value !== `0x${"0".repeat(64)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isReceipt(value: unknown, appId: Hex): value is MaterialReceipt {
  if (!isRecord(value) || Object.keys(value).sort().join(",") !==
      "appId,caseId,ciphertextHash,materialClass,policyId,resourceId,uri") return false;
  return isHex32(value.resourceId) && value.appId === appId && isHex32(value.caseId)
    && value.policyId === 1 && isHex32(value.materialClass) && isHex32(value.ciphertextHash)
    && value.uri === `ava-private:v1:${value.resourceId.slice(2)}`;
}

function decodeCanonicalBase64(value: string): Buffer {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw custodyError();
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw custodyError();
  return decoded;
}
