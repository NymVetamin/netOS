// These indexes describe only the current render's configuration.
export function storageAccessIndex(shares: any[]) {
  const namesByUser = new Map<string, string[]>();
  const usersByShare = new Map<any, Set<string>>();
  for (const share of shares) {
    const users = new Set<string>(share.users || []);
    usersByShare.set(share, users);
    for (const id of users) {
      let names = namesByUser.get(id);
      if (!names) namesByUser.set(id, names = []);
      names.push(share.name);
    }
  }
  return { namesByUser, usersByShare };
}
