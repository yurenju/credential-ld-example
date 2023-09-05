import { createLDCredential, verifyLDCredential } from "./credential-flow.js";
import { setupAgent, setupIdentity } from "./setup.js";
import { DID_METHOD, getDidKey } from "./Semaphore.js";

(async () => {
  const { identity, group } = setupIdentity();
  const agent = setupAgent();

  const issuer = await agent.didManagerImport({
    did: "did:web:yurenju.github.io:did-web",
    provider: DID_METHOD,
    keys: [getDidKey(identity)],
  });

  const credential = await createLDCredential(issuer, agent);
  console.log(`Credential issued`);
  console.dir(credential);
  const verified = await verifyLDCredential(credential, agent);
  console.log(`Credential verified=${JSON.stringify(verified, null, 2)}`);

  return process.exit(0);
})();
