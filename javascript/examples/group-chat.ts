import initAsync from "../dist";
import { GroupSession, OlmMessage } from "../dist";
import { InboundGroupSession } from "../dist";
import { Account, Session } from "../dist";
import { server, UserKeys } from "./dummy-server";

/**
 * for demonstration purposes we limit the number of users in the chat
 * to the max number of OT keys an account can generate
 */
const NUM_USERS_IN_CHAT = Math.min(
  100,
  new Account().max_number_of_one_time_keys
);

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
  account.generate_one_time_keys(account.max_number_of_one_time_keys);
  const otKeys: Map<string, string> = account.one_time_keys;
  server.storeOtKeys(username, [...otKeys.values()]);
  /** mark as published so they won't be given back again */
  account.mark_keys_as_published();

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

/**
 * Exports the key to the group session, then creates an Olm session for each
 * individual target user and encrypts the group session key using the olm session.
 * @param account sender account
 * @param groupSession the outbound group session used for sending messages
 * @param targets usernames of users with whome we want to share the key to session
 * @returns the encrypted messages
 */
function shareMegolmSessionKey(
  account: Account,
  groupSession: GroupSession,
  targets: string[]
): Map<string, OlmMessage | null> {
  /** we prepare the session to be exported */
  const exportedSession = {
    id: groupSession.session_id,
    key: groupSession.session_key,
    messageIndex: groupSession.message_index,
  };
  const encoded: Uint8Array = new TextEncoder().encode(
    JSON.stringify(exportedSession)
  );

  const encryptedMessages = new Map<string, OlmMessage | null>();
  for (const target of targets) {
    /**
     * ideally here we would re-use any existing olm session with the target user
     * but for the sake of simplicity we're going to create a new one
     */
    const session = setupOlmSession(account, target);
    if (!session) {
      encryptedMessages.set(target, null);
      continue;
    }

    const encryptedMessage = session.encrypt(encoded);
    encryptedMessages.set(target, encryptedMessage);
  }

  return encryptedMessages;
}

function decrypteAndImportGroupSession(
  receiverAccount: Account,
  messageSourceUsername: string,
  encryptedMessage: OlmMessage
): InboundGroupSession | null {
  const sourceUserKeys = server.getUserKeys(messageSourceUsername);
  if (!sourceUserKeys?.curve25519) {
    console.error("aclice has no keys");
    return null;
  }
  const { plaintext: plaintext, session: bobSession } =
    receiverAccount.create_inbound_session(
      sourceUserKeys.curve25519,
      encryptedMessage
    );
  let decodedJSON = new TextDecoder().decode(plaintext);
  const parsed: {
    id: string;
    key: string;
    messageIndex: number;
  } = JSON.parse(decodedJSON);

  const groupSession = new InboundGroupSession(parsed.key);
  return groupSession;
}

async function main() {
  await initAsync();

  /** setup */
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  /** setup all accounts */
  const accounts: {
    username: string;
    account: Account;
  }[] = [];

  for (let i = 0; i < NUM_USERS_IN_CHAT; i++) {
    accounts.push(setupOlmAccount(`User ${i}`));
  }

  /** one of the users want to start a group chat */
  const sender = accounts[Math.floor(Math.random() * accounts.length)];
  const otherUsersInChat = accounts.filter(
    (u) => u.username != sender.username
  );
  const groupSession = new GroupSession();
  const encryptedMessagesForKeySharing = shareMegolmSessionKey(
    sender.account,
    groupSession,
    otherUsersInChat.map((a) => a.username)
  );
  const encryptedMessage = groupSession.encrypt(
    textEncoder.encode("Hello group!!")
  );

  /**
   * now the use shares the ecnrypted message AND the Olm Encrypted messages
   * with the users in the chat with the help of a server,
   * and when they receive them, they decrypt them and import the group session keys,
   * so they can decrypt messages coming from the user
   */
  for (const receiver of otherUsersInChat) {
    const keyShareMessage = encryptedMessagesForKeySharing.get(
      receiver.username
    );
    if (!keyShareMessage) {
      console.error(
        `User "${receiver.username}" didn't receive any key share message`
      );
      continue;
    }
    /**
     * receiver decrypts the key share message and imports the inbound group session
     * the inbound group session can only be used to decrypt messages from the sender,
     * if the receiver also wants to send a message, then they have to create a groupsession
     * and share the key for it with the other, so each user its own groupsession and
     * inbound group session for each user in the chat that sent a message.
     */
    const inboundGroupSession = decrypteAndImportGroupSession(
      receiver.account,
      sender.username,
      keyShareMessage
    );
    if (!inboundGroupSession) {
      console.error(
        `User "${receiver.username}" couldn't  create inboung group session from key share message.`
      );
      continue;
    }

    const decryptedMsg = inboundGroupSession.decrypt(encryptedMessage);
    const decoded = textDecoder.decode(decryptedMsg.plaintext);
    console.log(`User "${receiver.username}" received message "${decoded}"`);
  }
}

main().then();
