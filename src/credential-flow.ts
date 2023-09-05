import {
  CredentialPayload,
  IDIDManager,
  IIdentifier,
  TAgent,
  VerifiableCredential,
} from "@veramo/core";
import { ICredentialIssuer } from "@veramo/credential-w3c";
import { MY_CUSTOM_CONTEXT_URI } from "./setup.js";

/**
 * Create a managed DID using the `defaultProvider` configured in ./setup.ts (did:key)
 * @param agent
 */
export async function createDID(
  agent: TAgent<IDIDManager>
): Promise<IIdentifier> {
  const identifier = await agent.didManagerCreate();
  return identifier;
}

/**
 * Issue a JSON-LD Verifiable Credential using the DID managed by the agent
 *
 * The agent was initialized with a `CredentialIssuer` and `CredentialIssuerLD` plugins (See ./setup.ts) which provide
 * the `createVerifiableCredential` functionality. They internally rely on the `DIDResolver`, `KeyManager`, and
 * `DIDManager` plugins that are used to map the issuer of the `CredentialPayload` to a `VerificationMethod` in the
 * issuer `DID Document` and to a signing key managed by the agent.
 *
 * @param issuer
 * @param agent
 */
export async function createLDCredential(
  issuer: IIdentifier,
  agent: TAgent<ICredentialIssuer>
): Promise<VerifiableCredential> {
  const credential: CredentialPayload = {
    "@context": [MY_CUSTOM_CONTEXT_URI],
    issuer: issuer.did,
    credentialSubject: {
      group: "1",
    },
  };
  const verifiableCredential = await agent.createVerifiableCredential({
    credential,
    proofFormat: "lds", // use LD Signatures as proof
  });

  return verifiableCredential;
}

export async function verifyLDCredential(
  credential: VerifiableCredential,
  agent: TAgent<ICredentialIssuer>
): Promise<boolean> {
  const verified = await agent.verifyCredential({ credential });
  return verified.verified;
}
