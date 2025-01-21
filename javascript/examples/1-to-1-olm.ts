import initAsync, { Account, Session } from "../dist";
import { server, UserKeys } from "./dummy-server";

function setupOlmAccount(username: string): {
  username: string;
  account: Account;
} {
  const account = new Account();
  const keys: UserKeys = {
    curve25519: account.curve25519_key,
    ed25519: account.ed25519_key,
  };
  server.storeUserKeys(username, keys);
  // we avoid generating all one time keys in one go, to leave buffer for errors / misused keys, etc..
  account.generate_one_time_keys(
    Math.floor(account.max_number_of_one_time_keys / 2)
  );
  const otKeys: Map<string, string> = account.one_time_keys;
  server.storeOtKeys(username, [...otKeys.values()]);
  /** mark as published so they won't be given back again */
  account.mark_keys_as_published()

  return {
    account,
    username,
  };
}

function setupOlmSession(
  account: Account,
  targetUsername: string
): Session | undefined {
  const targetKeys = server.getUserKeys(targetUsername);
  const targetOTKeys = server.claimUserOTKey(targetUsername);
  if (!targetKeys || !targetOTKeys?.length) return undefined;
  

  const session = account.create_outbound_session(
    targetKeys.curve25519,
    targetOTKeys
  );

  return session;
}

async function main() {
  await initAsync();

  /** setup */
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  /** setup account and OT keys for two users */
  const aliceAccount = setupOlmAccount("alice");
  const bobAccount = setupOlmAccount("bob");

  /** alice wants to start a conversation with bob, so alice creates an olm session with bob */
  const aliceSession = setupOlmSession(
    aliceAccount.account,
    bobAccount.username
  );
  if (!aliceSession) {
    console.error("failed to generate alice session");
    return;
  }
  /**
   * alice sends an encrypted message to bob using the session.
   * As long as alice doesn't decrypt any message from bob, the generated
   * encrypted messages will include the keys necessary for bob
   * to create the session on his end
   */
  const messageWithKey = aliceSession?.encrypt(
    textEncoder.encode("Hello bob!!")
  );
  if (!messageWithKey) {
    console.error("failed to encrypt message using session");
    return;
  }

  /**
   * Alice now sends the message to bob and bob receives it
   * and tries to create the corresponding session on his end
   */
  const aliceKeys = server.getUserKeys("alice");
  if (!aliceKeys?.curve25519) {
    console.error("aclice has no keys");
    return;
  }
  const { plaintext: plaintext, session: bobSession } =
    bobAccount.account.create_inbound_session(
      aliceKeys.curve25519,
      messageWithKey
    );
  let decoded = textDecoder.decode(plaintext);
  console.log(`bob received message "${decoded}" from alice`);

  /**
   * because the session has been created from a message with key,
   * if we encrypt messages with it they won't have keys included,
   * bceause it assumes that the partner already has the key
   */
  const messageWithoutKey = bobSession.encrypt(
    textEncoder.encode("Hello alice!!")
  );

  /**
   * bob sends message to alice and she decrypts it, from this point on
   * alice's session will alsonot attach any keys to the messages
   */
  const decryptedMessage = aliceSession.decrypt(messageWithoutKey);
  decoded = textDecoder.decode(decryptedMessage);
  console.log(`Alice received message "${decoded}" from bob`);
}

main().then();
