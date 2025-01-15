export interface UserKeys {
  /** EC DH */
  curve25519: string;
  /** EC signing */
  ed25519: string;
}

export class DummyServer {
  private userKeyMap: Map<string, UserKeys> = new Map();
  private userOTKeyMap: Map<string, string[]> = new Map();

  public storeUserKeys(user: string, keys: UserKeys) {
    this.userKeyMap.set(user, keys);
  }

  public storeOtKeys(user: string, otKeys: string[]) {
    if (this.userOTKeyMap.has(user)) {
      this.userOTKeyMap.get(user)?.push(...otKeys.slice());
    } else {
      this.userOTKeyMap.set(user, otKeys.slice());
    }
  }

  public getUserKeys(user: string): UserKeys | undefined {
    return this.userKeyMap.get(user);
  }

  public claimUserOTKey(user: string): string | undefined {
    return this.userOTKeyMap.get(user)?.splice(0, 1).at(0);
  }
}

export const server = new DummyServer();
