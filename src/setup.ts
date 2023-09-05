import { createAgent, IDIDManager, IKeyManager, IResolver } from "@veramo/core";
import {
  ContextDoc,
  CredentialIssuerLD,
  LdDefaultContexts,
  VeramoEd25519Signature2018,
  VeramoLdSignature,
} from "@veramo/credential-ld";
import { CredentialPlugin, ICredentialIssuer } from "@veramo/credential-w3c";
import { DIDManager, MemoryDIDStore } from "@veramo/did-manager";
import { WebDIDProvider } from "@veramo/did-provider-web";
import { getDidKeyResolver, KeyDIDProvider } from "@veramo/did-provider-key";
import { DIDResolverPlugin } from "@veramo/did-resolver";
import {
  KeyManager,
  MemoryKeyStore,
  MemoryPrivateKeyStore,
} from "@veramo/key-manager";
import { Resolver } from "did-resolver";
import {
  DID_METHOD,
  SEMAPHORE_KMS,
  SemaphoreKeyManagementSystem,
  SemaphoreSignature2023,
} from "./Semaphore.js";
import { getResolver as getWebResolver } from "web-did-resolver";
import { Identity } from "@semaphore-protocol/identity";
import { Group } from "@semaphore-protocol/group";

export const MY_CUSTOM_CONTEXT_URI = "https://example.com/custom/context";

const extraContexts: Record<string, ContextDoc> = {};
extraContexts[MY_CUSTOM_CONTEXT_URI] = {
  "@context": {
    group: "https://example.com/custom/context",
  },
};

export function setupIdentity() {
  const identity = new Identity("TOP-SECRET-KEY");
  const members = [identity.commitment];
  const group = new Group(1, 20, members);

  return { identity, group };
}

export function setupAgent() {
  const suites: VeramoLdSignature[] = [
    new SemaphoreSignature2023(),
    // new VeramoEd25519Signature2018(),
  ];

  const agent = createAgent<
    IResolver & IKeyManager & IDIDManager & ICredentialIssuer
  >({
    plugins: [
      new KeyManager({
        store: new MemoryKeyStore(),
        kms: {
          [SEMAPHORE_KMS]: new SemaphoreKeyManagementSystem(
            new MemoryPrivateKeyStore()
          ),
        },
      }),
      new DIDManager({
        providers: {
          // "did:key": new KeyDIDProvider({ defaultKms: "local" }),
          [DID_METHOD]: new WebDIDProvider({
            defaultKms: SEMAPHORE_KMS,
          }) as any,
        },
        store: new MemoryDIDStore(),
        defaultProvider: DID_METHOD,
      }),
      new DIDResolverPlugin({
        resolver: new Resolver({
          ...getDidKeyResolver(),
          ...getWebResolver(),
        }),
      }),
      new CredentialPlugin(),
      new CredentialIssuerLD({
        contextMaps: [LdDefaultContexts, extraContexts],
        suites,
      }),
    ],
  });
  return agent;
}
