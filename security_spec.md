# Security Specification for CoCode

## 1. Data Invariants
- A file must have a valid `name`, `content`, and `language`.
- A file is owned by the user who created it (via `ownerId`).
- Presence documents must belong to the logged-in user and be linked to an existing file.
- `updatedAt` and `lastSeen` must be server-validated timestamps.

## 2. The Dirty Dozen Payloads

1. **Unauthenticated File Creation**:
   ```json
   { "name": "Hack.js", "content": "alert(1)", "language": "javascript", "ownerId": "anon", "updatedAt": "request.time" }
   ```
   *Expected: Denied*

2. **Owner Spoofing on Creation**:
   ```json
   { "name": "Spoof.js", "content": "...", "language": "javascript", "ownerId": "not-me", "updatedAt": "request.time" }
   ```
   *Expected: Denied (ownerId must match auth.uid)*

3. **Field Poisoning (Massive Name)**:
   ```json
   { "name": "a".repeat(10000), "content": "...", "language": "javascript", "ownerId": "my-id", "updatedAt": "request.time" }
   ```
   *Expected: Denied (size limit on string)*

4. **Invalid Type for Column**:
   ```json
   { "userName": "Alice", "userColor": "#FF0000", "lastSeen": "request.time", "cursor": { "lineNumber": 1, "column": "not-a-number" } }
   ```
   *Expected: Denied (schema check)*

5. **Presence Spoofing (Writing to someone else's presence)**:
   *Path: `/files/fileA/presence/userB` by `userA`*
   ```json
   { "userName": "Impostor", "userColor": "#000", "lastSeen": "request.time" }
   ```
   *Expected: Denied*

6. **Metadata Hijacking (Updating ownerId)**:
   ```json
   { "ownerId": "attacker-id" }
   ```
   *Expected: Denied (ownerId is immutable)*

7. **Temporal Fraud (Backdating updatedAt)**:
   ```json
   { "updatedAt": "2000-01-01T00:00:00Z" }
   ```
   *Expected: Denied (must match request.time)*

8. **Resource Exhaustion (10MB payload in cursor)**:
   ```json
   { "cursor": { "lineNumber": 1, "column": 1, "junk": "..." } }
   ```
   *Expected: Denied (strict key check via validation helper)*

9. **Unauthorized Deletion**:
   *UserB trying to delete UserA's file.*
   *Expected: Denied*

10. **Zombie Presence Creation**:
    *Writing presence for a file that doesn't exist.*
    *Expected: Denied (exists check on parent file)*

11. **Language Type Pollution**:
    ```json
    { "language": true }
    ```
    *Expected: Denied (type safety)*

12. **Anonymous Listing**:
    *Reading all files while logged out.*
    *Expected: Denied*

## 3. Test Runner (Draft)
A comprehensive test suite would use `@firebase/rules-unit-testing` to verify these payloads.
