/** Keep one person's avatar motion consistent across the picker, profile, and presence bar. */
export function avatarMotionSeed(identity: string): number {
  let hash = 2166136261;
  for (const character of identity) {
    hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
  }
  return (hash >>> 0) / 0xffffffff;
}
