import { Identity } from "@semaphore-protocol/identity";
import {
  CredentialPayload,
  DIDDocument,
  IAgentContext,
  IKey,
  TKeyType,
  MinimalImportableKey,
  ManagedKeyInfo,
  DIDDocComponent,
  IResolver,
  RequireOnly,
} from "@veramo/core";
import { hexToBytes, bytesToHex } from "@veramo/utils";
import { VeramoLdSignature } from "@veramo/credential-ld";
import { RequiredAgentMethods } from "@veramo/credential-ld/build/ld-suites";
import {
  AbstractKeyManagementSystem,
  AbstractPrivateKeyStore,
  ManagedPrivateKey,
} from "@veramo/key-manager";
import { Group } from "@semaphore-protocol/group";
import { toString } from "uint8arrays";
import { generateProof, verifyProof } from "@semaphore-protocol/proof";
import path, { join } from "path";
import { fileURLToPath } from "url";

export const SEMAPHORE_KMS = "semaphoreKms";
export const DID_METHOD = "did:web";
export const SEMAPHORE_TYPE = "SemaphoreType2023" as TKeyType;
export const KID = "semaphore-default";

export function getDidKey(identity: Identity) {
  return {
    kid: KID,
    kms: SEMAPHORE_KMS,
    type: SEMAPHORE_TYPE,
    privateKeyHex: identity.toString(),
    publicKeyHex: normalizePublicKey(identity.commitment.toString()),
  };
}

function getDirName() {
  const __filename = fileURLToPath(import.meta.url);
  return path.dirname(__filename);
}

// not sure the reason but the public key sometimes
// has a prefix "0" padding, to avoid the comparsion issue,
// we normalize it
function normalizePublicKey(publicKey: string) {
  return bytesToHex(hexToBytes(publicKey));
}

type MatchProofArg = {
  proof: {
    type: string;
  };
};

type VerifyProofArg = {
  proof: any;
  document: any;
};

type GroupInfo = {
  id: string;
  depth: number;
  members: string[];
};

type SignArgs = {
  keyRef: Pick<IKey, "kid">;
  algorithm?: string;
  data: Uint8Array;
};

export function fetchPublicGroupInfo(groupId: string): Promise<GroupInfo> {
  return Promise.resolve({
    id: groupId,
    depth: 20,
    members: [
      "18247677939749764709615722514754949329375911953462583983649646599131197861128",
    ],
  });
}

class UnsupportedKeyType extends Error {
  constructor(type: string) {
    super(`Unsupported key type: ${type}`);
    this.name = "UnsupportedKeyType";
  }
}

class KeyNotFoundError extends Error {
  constructor(kid: string) {
    super(`Key not found: ${kid}`);
    this.name = "KeyNotFoundError";
  }
}

class PropertyNotFountError extends Error {
  constructor(propertyName: string) {
    super(`property not found: ${propertyName}`);
    this.name = "PropertyNotFountError";
  }
}

export class SemaphoreKeyManagementSystem extends AbstractKeyManagementSystem {
  private readonly keyStore: AbstractPrivateKeyStore;

  constructor(keyStore: AbstractPrivateKeyStore) {
    super();
    this.keyStore = keyStore;
  }

  async importKey(
    args: Exclude<MinimalImportableKey, "kms">
  ): Promise<ManagedKeyInfo> {
    const managedKey = this.asManagedKeyInfo({ alias: args.kid, ...args });
    await this.keyStore.importKey({ alias: managedKey.kid, ...args });

    return managedKey;
  }

  async listKeys(): Promise<ManagedKeyInfo[]> {
    const privateKeys = await this.keyStore.listKeys({});
    const managedKeys = privateKeys.map((key) => this.asManagedKeyInfo(key));
    return managedKeys;
  }
  async createKey(args: {
    type: TKeyType;
    meta?: any;
  }): Promise<ManagedKeyInfo> {
    const { type } = args;
    if (type !== SEMAPHORE_TYPE) {
      throw new UnsupportedKeyType(type);
    }

    const identity = new Identity();
    const key = await this.importKey({
      type,
      privateKeyHex: identity.toString(),
    } as any);

    return key;
  }

  async deleteKey(args: { kid: string }): Promise<boolean> {
    return await this.keyStore.deleteKey({ alias: args.kid });
  }

  async sign({ keyRef, algorithm, data }: SignArgs): Promise<string> {
    let managedKey: ManagedPrivateKey;

    try {
      managedKey = await this.keyStore.getKey({ alias: keyRef.kid });
    } catch (e) {
      throw new KeyNotFoundError(keyRef.kid);
    }

    if (algorithm !== SEMAPHORE_TYPE) {
      throw new UnsupportedKeyType(algorithm || "");
    }

    const identity = new Identity(managedKey.privateKeyHex);

    const payload = JSON.parse(toString(data));
    const { id, depth, members } = payload.group;
    const { challenge } = payload;
    const group = new Group(id, depth, members);
    const artifacts = {
      zkeyFilePath: join(getDirName(), "./assets/semaphore.zkey"),
      wasmFilePath: join(getDirName(), "./assets/semaphore.wasm"),
    };
    const proof = await generateProof(
      identity,
      group,
      challenge,
      challenge,
      artifacts
    );

    return JSON.stringify(proof);
  }

  sharedSecret(args: {
    myKeyRef: Pick<IKey, "kid">;
    theirKey: Pick<IKey, "type" | "publicKeyHex">;
  }): Promise<string> {
    console.log("sharedSecret");
    return Promise.resolve("sharedSecret");
  }

  private asManagedKeyInfo(
    args: RequireOnly<ManagedPrivateKey, "privateKeyHex" | "type">
  ): ManagedKeyInfo {
    const { commitment } = new Identity(args.privateKeyHex);
    const publicKeyHex = normalizePublicKey(commitment.toString());
    const key = {
      type: args.type,
      kid: args.alias || publicKeyHex,
      publicKeyHex: publicKeyHex,
    };

    return key as ManagedKeyInfo;
  }
}

type SemaphoreSignature2023Options = {
  context?: IAgentContext<RequiredAgentMethods>;
  verificationMethod?: string;
};

export class SemaphoreSignature2023 extends VeramoLdSignature {
  context?: IAgentContext<RequiredAgentMethods>;
  issuer?: string;
  verificationMethod?: string;

  constructor(options?: SemaphoreSignature2023Options) {
    super();

    if (options) {
      if (options.context) {
        this.context = options.context;
      }
      if (options.verificationMethod) {
        this.verificationMethod = options.verificationMethod;
      }
    }
  }

  override getSupportedVerificationType(): string {
    return SEMAPHORE_TYPE;
  }
  override getSupportedVeramoKeyType(): TKeyType {
    return SEMAPHORE_TYPE;
  }
  override getSuiteForSigning(
    key: IKey,
    issuerDid: string,
    verificationMethodId: string,
    context: IAgentContext<RequiredAgentMethods>
  ) {
    return new SemaphoreSignature2023({
      verificationMethod: verificationMethodId,
      context,
    });
  }

  override getSuiteForVerification() {
    return new SemaphoreSignature2023({
      verificationMethod: this.verificationMethod,
      context: this.context,
    });
  }

  preDidResolutionModification(
    didUrl: string,
    didDoc: DIDDocComponent | DIDDocument,
    context: IAgentContext<IResolver>
  ): Promise<DIDDocComponent | DIDDocument> {
    return Promise.resolve(didDoc);
  }

  override preSigningCredModification(credential: CredentialPayload): void {
    // do nothing
  }

  ensureSuiteContext() {
    // do nothing
  }

  async createProof(...args: any) {
    if (!this.context) {
      throw new PropertyNotFountError("context");
    }

    if (!this.context.agent) {
      throw new PropertyNotFountError("context.agent");
    }

    const { credentialSubject } = args[0].document;

    const groupInfo = await fetchPublicGroupInfo(credentialSubject.group);
    const timestamp = Date.now();
    const data = {
      challenge: timestamp,
      group: groupInfo,
    };

    const result = await this.context.agent.keyManagerSign({
      keyRef: KID,
      data: JSON.stringify(data),
      algorithm: SEMAPHORE_TYPE,
    });

    const { issuer } = args[0].document;
    this.issuer = issuer;
    const proof = {
      type: SEMAPHORE_TYPE,
      verificationMethod: this.verificationMethod,
      proofPurpose: "assertionMethod",
      created: new Date().toISOString(),
      payload: JSON.parse(result),
    };
    return proof;
  }

  matchProof({ proof }: MatchProofArg) {
    return Promise.resolve(proof.type === this.getSupportedVerificationType());
  }

  async verifyProof(arg: VerifyProofArg) {
    const { proof } = arg;
    const id = proof.verificationMethod;

    const verificationMethod = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2018/v1",
        "https://w3id.org/security/suites/x25519-2019/v1",
      ],
      id,
      type: "Ed25519VerificationKey2018",
      controller: {
        id,
      },
      publicKeyBase58: "BKjPGrrwD35eZj7ni4p89qjAWm8AHFFHMGpQ3KMaJGB5",
    };

    const groupId = arg.document.credentialSubject.group;
    const { depth } = await fetchPublicGroupInfo(groupId);
    const fullProof = arg.proof.payload;
    const verified = await verifyProof(fullProof, depth);

    return { verified, verificationMethod };
  }
}
