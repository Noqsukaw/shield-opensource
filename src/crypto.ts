// ============================================================
//  SHIELD — coeur cryptographique cote navigateur
//  Chiffrement 100% client. Le serveur ne recoit que du base64 opaque.
// ============================================================

import sodium from "libsodium-wrappers-sumo";

export interface KdfParams {
  memMiB: number;
  iterations: number;
  parallelism: number;
}

export const KDF_DEFAULT: KdfParams = { memMiB: 64, iterations: 3, parallelism: 4 };

type Bytes = Uint8Array;
const NONCE = 24; // XChaCha20-Poly1305

export async function ready(): Promise<void> {
  await sodium.ready;
}

// --- base64 standard (compatible Buffer.from(s,"base64") cote serveur) ---
const b64 = (b: Bytes): string => sodium.to_base64(b, sodium.base64_variants.ORIGINAL);
const unb64 = (s: string): Bytes => sodium.from_base64(s, sodium.base64_variants.ORIGINAL);

function concat(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// --- primitives ---
const randomKey = (): Bytes => sodium.crypto_aead_xchacha20poly1305_ietf_keygen();

function argon2id(password: Bytes, salt: Bytes, p: KdfParams, outLen = 32): Bytes {
  return sodium.crypto_pwhash(
    outLen,
    password,
    salt,
    p.iterations,
    p.memMiB * 1024 * 1024,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

// Chiffre et renvoie nonce||ciphertext en base64 (format de transport).
function sealB64(plaintext: Bytes, key: Bytes): string {
  const nonce = sodium.randombytes_buf(NONCE);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
  return b64(concat(nonce, ct));
}

function openB64(packed: string, key: Bytes): Bytes {
  const buf = unb64(packed);
  const nonce = buf.subarray(0, NONCE);
  const ct = buf.subarray(NONCE);
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key);
}

const enc = (s: string): Bytes => new TextEncoder().encode(s);
const AUTH_DOMAIN = enc("shield:auth:v1");
const RECOVERY_DOMAIN = enc("shield:recovery:v1");

function deriveMasterKey(password: string, salt: Bytes, p: KdfParams): Bytes {
  return argon2id(enc(password), salt, p, 32);
}

function deriveAuthHash(masterKey: Bytes): Bytes {
  return sodium.crypto_generichash(32, masterKey, AUTH_DOMAIN);
}

function deriveRecoveryAuth(recoveryKey: Bytes): Bytes {
  return sodium.crypto_generichash(32, recoveryKey, RECOVERY_DOMAIN);
}

function formatRecoveryCode(raw: Bytes): string {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (const v of raw) out += A[v % 32];
  return (out.match(/.{1,4}/g) ?? []).join("-");
}

// ------------------------------------------------------------
//  Cle en memoire apres deverrouillage
// ------------------------------------------------------------

export interface UnlockedKeys {
  masterKey: Bytes;
  accountKey: Bytes;
  privateKey: Bytes;
  publicKey: Bytes;
}

// ------------------------------------------------------------
//  Inscription : genere toutes les cles, renvoie le payload serveur
//  (tout en base64 opaque) + la feuille de secours a imprimer.
// ------------------------------------------------------------

export interface RegistrationResult {
  payload: Record<string, unknown>;
  recoveryCode: string;
  keys: UnlockedKeys;
}

export async function buildRegistration(
  email: string,
  displayName: string,
  password: string,
  p: KdfParams = KDF_DEFAULT
): Promise<RegistrationResult> {
  await ready();
  const kdfSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const masterKey = deriveMasterKey(password, kdfSalt, p);
  const authHash = deriveAuthHash(masterKey);

  const accountKey = randomKey();
  const wrappedAccountKey = sealB64(accountKey, masterKey);

  const kp = sodium.crypto_box_keypair();
  const wrappedPrivateKey = sealB64(kp.privateKey, accountKey);

  const recoverySalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const recoveryCode = formatRecoveryCode(sodium.randombytes_buf(20));
  const recoveryKey = argon2id(enc(recoveryCode), recoverySalt, p, 32);
  const wrappedAccountKeyByRecovery = sealB64(accountKey, recoveryKey);
  const recoveryAuthHash = b64(deriveRecoveryAuth(recoveryKey));

  return {
    payload: {
      email,
      displayName,
      kdfSalt: b64(kdfSalt),
      kdfMemMiB: p.memMiB,
      kdfIterations: p.iterations,
      kdfParallelism: p.parallelism,
      authHash: b64(authHash),
      wrappedAccountKey,
      publicKey: b64(kp.publicKey),
      wrappedPrivateKey,
      recoverySalt: b64(recoverySalt),
      wrappedAccountKeyByRecovery,
      recoveryAuthHash
    },
    recoveryCode,
    keys: { masterKey, accountKey, privateKey: kp.privateKey, publicKey: kp.publicKey }
  };
}

// ------------------------------------------------------------
//  Connexion : derive la MasterKey puis l'auth-hash a envoyer
// ------------------------------------------------------------

export async function deriveAuthHashB64(
  password: string,
  kdfSaltB64: string,
  p: KdfParams
): Promise<{ authHashB64: string; masterKey: Bytes }> {
  await ready();
  const masterKey = deriveMasterKey(password, unb64(kdfSaltB64), p);
  return { authHashB64: b64(deriveAuthHash(masterKey)), masterKey };
}

// Deverrouille AccountKey + cle privee a partir de la MasterKey et de la reponse login.
// --- Déverrouillage rapide (quick-unlock) ---
// authHash recalculé depuis la masterKey stockée (étape rapide, pas d'Argon2id mot de passe).
export function authHashFromMasterKey(masterKey: Bytes): string {
  return b64(deriveAuthHash(masterKey));
}
export function bytesToB64(b: Bytes): string {
  return b64(b);
}
export function b64ToBytes(s: string): Bytes {
  return unb64(s);
}
export function newSaltB64(): string {
  return b64(sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES));
}
// Clé d'enrobage dérivée d'un PIN (Argon2id, coût élevé : un PIN est faible).
export function quickKeyFromPin(pin: string, saltB64: string): Bytes {
  return argon2id(sodium.from_string(pin), unb64(saltB64), KDF_DEFAULT, 32);
}
// Clé 32 octets dérivée d'un secret quelconque (sortie PRF biométrique).
export function deriveKeyFromSecret(secret: Bytes): Bytes {
  return sodium.crypto_generichash(32, secret);
}

export function unwrapAccount(
  masterKey: Bytes,
  acc: { wrappedAccountKey: string; wrappedPrivateKey: string; publicKey: string }
): UnlockedKeys {
  const accountKey = openB64(acc.wrappedAccountKey, masterKey);
  const privateKey = openB64(acc.wrappedPrivateKey, accountKey);
  return { masterKey, accountKey, privateKey, publicKey: unb64(acc.publicKey) };
}

// ------------------------------------------------------------
//  Coffres et items (Niveau 1)
// ------------------------------------------------------------

// Cree une nouvelle VaultKey et la renvoie enveloppee par l'AccountKey.
export function wrapNewVaultKey(accountKey: Bytes): { wrappedKey: string; vaultKey: Bytes } {
  const vaultKey = randomKey();
  return { wrappedKey: sealB64(vaultKey, accountKey), vaultKey };
}

export function unwrapVaultKey(wrappedKeyB64: string, accountKey: Bytes): Bytes {
  return openB64(wrappedKeyB64, accountKey);
}

export interface EncItem {
  wrappedItemKey: string;
  ciphertext: string;
  nonce: string;
}

// Chiffre un objet (champs de l'item) avec une ItemKey propre, enveloppee par la VaultKey.
export function encryptItem(data: unknown, vaultKey: Bytes): EncItem {
  const itemKey = randomKey();
  const wrappedItemKey = sealB64(itemKey, vaultKey);
  const nonce = sodium.randombytes_buf(NONCE);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    enc(JSON.stringify(data)),
    null,
    null,
    nonce,
    itemKey
  );
  return { wrappedItemKey, ciphertext: b64(ct), nonce: b64(nonce) };
}

export function decryptItem(rec: EncItem, vaultKey: Bytes): any {
  const itemKey = openB64(rec.wrappedItemKey, vaultKey);
  const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    unb64(rec.ciphertext),
    null,
    unb64(rec.nonce),
    itemKey
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

// Generateur de mot de passe aleatoire (sans caracteres ambigus par defaut).
export function generatePassword(length = 20, symbols = true): string {
  const lower = "abcdefghijkmnpqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const sym = "!@#$%^&*-_=+?";
  const alphabet = lower + upper + digits + (symbols ? sym : "");
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[sodium.randombytes_uniform(alphabet.length)];
  return out;
}

// ------------------------------------------------------------
//  Changement de mot de passe maitre (re-enveloppe l'AccountKey)
// ------------------------------------------------------------

export async function buildPasswordChange(
  currentPassword: string,
  newPassword: string,
  currentKdfSaltB64: string,
  currentParams: KdfParams,
  accountKey: Bytes,
  newParams: KdfParams = KDF_DEFAULT
): Promise<{ payload: Record<string, unknown>; newMasterKey: Bytes; newKdfSaltB64: string }> {
  await ready();
  const currentMaster = deriveMasterKey(currentPassword, unb64(currentKdfSaltB64), currentParams);
  const currentAuthHash = b64(deriveAuthHash(currentMaster));

  const newSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const newMaster = deriveMasterKey(newPassword, newSalt, newParams);
  const newAuthHash = b64(deriveAuthHash(newMaster));
  const wrappedAccountKey = sealB64(accountKey, newMaster);

  return {
    payload: {
      currentAuthHash,
      kdfSalt: b64(newSalt),
      kdfMemMiB: newParams.memMiB,
      kdfIterations: newParams.iterations,
      kdfParallelism: newParams.parallelism,
      authHash: newAuthHash,
      wrappedAccountKey
    },
    newMasterKey: newMaster,
    newKdfSaltB64: b64(newSalt)
  };
}

// ------------------------------------------------------------
//  Récupération par feuille de secours
//  Le code de secours redonne l'AccountKey ; on re-enveloppe avec
//  un nouveau mot de passe maître. L'auth-hash de secours autorise
//  l'opération côté serveur sans jamais lui révéler le code.
// ------------------------------------------------------------

export async function buildRecoveryReset(
  recoveryCode: string,
  recoverySaltB64: string,
  wrappedAccountKeyByRecoveryB64: string,
  recoveryParams: KdfParams,
  newPassword: string,
  newParams: KdfParams = KDF_DEFAULT
): Promise<{ recoveryAuthHash: string; payload: Record<string, unknown> }> {
  await ready();
  const normalized = recoveryCode.trim().toUpperCase().replace(/\s+/g, "");
  const recoveryKey = argon2id(enc(normalized), unb64(recoverySaltB64), recoveryParams, 32);
  // Lève une exception si le code est faux (échec d'ouverture AEAD).
  const accountKey = openB64(wrappedAccountKeyByRecoveryB64, recoveryKey);
  const recoveryAuthHash = b64(deriveRecoveryAuth(recoveryKey));

  const newSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const newMaster = deriveMasterKey(newPassword, newSalt, newParams);
  const newAuthHash = b64(deriveAuthHash(newMaster));
  const wrappedAccountKey = sealB64(accountKey, newMaster);

  return {
    recoveryAuthHash,
    payload: {
      kdfSalt: b64(newSalt),
      kdfMemMiB: newParams.memMiB,
      kdfIterations: newParams.iterations,
      kdfParallelism: newParams.parallelism,
      authHash: newAuthHash,
      wrappedAccountKey
    }
  };
}
//  derivation (AccountKey + code PIN). Le code seul ne suffit pas :
//  meme deverrouille en Courant, ce coffre reste clos sans le PIN.
// ------------------------------------------------------------

function pinWrapKey(accountKey: Bytes, pin: string, salt: Bytes, p: KdfParams): Bytes {
  const pinKey = argon2id(enc(pin), salt, p, 32);
  return sodium.crypto_generichash(32, concat(accountKey, pinKey));
}

export function setupSecondaryVault(
  accountKey: Bytes,
  pin: string,
  p: KdfParams = KDF_DEFAULT
): { wrappedKey: string; secondarySalt: string; vaultKey: Bytes } {
  const vaultKey = randomKey();
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const wrapKey = pinWrapKey(accountKey, pin, salt, p);
  return { wrappedKey: sealB64(vaultKey, wrapKey), secondarySalt: b64(salt), vaultKey };
}

// Leve une exception si le code est faux (echec d'ouverture AEAD).
export function unlockSecondaryVault(
  wrappedKeyB64: string,
  secondarySaltB64: string,
  accountKey: Bytes,
  pin: string,
  p: KdfParams = KDF_DEFAULT
): Bytes {
  const wrapKey = pinWrapKey(accountKey, pin, unb64(secondarySaltB64), p);
  return openB64(wrappedKeyB64, wrapKey);
}

// ------------------------------------------------------------
//  Fichiers chiffres (pieces jointes des fiches)
// ------------------------------------------------------------

// Recupere l'ItemKey (deja enveloppee par la VaultKey) pour chiffrer ses fichiers.
export function itemKeyOf(wrappedItemKeyB64: string, vaultKey: Bytes): Bytes {
  return openB64(wrappedItemKeyB64, vaultKey);
}

// Chiffre des octets bruts (fichier) — renvoie ciphertext binaire + nonce base64.
export function encryptBytes(bytes: Bytes, key: Bytes): { ciphertext: Bytes; nonceB64: string } {
  const nonce = sodium.randombytes_buf(NONCE);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes, null, null, nonce, key);
  return { ciphertext: ct, nonceB64: b64(nonce) };
}

export function decryptBytes(ciphertext: Bytes, nonceB64: string, key: Bytes): Bytes {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, unb64(nonceB64), key);
}

// Metadonnees de fichier (nom + type MIME) chiffrees avec l'ItemKey.
export function sealMetaB64(obj: unknown, key: Bytes): string {
  return sealB64(enc(JSON.stringify(obj)), key);
}
export function openMetaB64(packed: string, key: Bytes): any {
  return JSON.parse(new TextDecoder().decode(openB64(packed, key)));
}

// Re-enveloppe une VaultKey EXISTANTE avec un nouveau code (changement de PIN).
export function rewrapSecondaryVault(
  accountKey: Bytes,
  vaultKey: Bytes,
  pin: string,
  p: KdfParams = KDF_DEFAULT
): { wrappedKey: string; secondarySalt: string } {
  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const wrapKey = pinWrapKey(accountKey, pin, salt, p);
  return { wrappedKey: sealB64(vaultKey, wrapKey), secondarySalt: b64(salt) };
}

// Code de secours du Confidentiel : long code aléatoire (formaté comme la feuille
// de secours). Il enveloppe la MÊME VaultKey via le mécanisme du PIN — donc aucune
// porte dérobée serveur. À garder hors-ligne ; détenir ce code rouvre le Confidentiel.
export function generateRecoveryCode(): string {
  return formatRecoveryCode(sodium.randombytes_buf(20));
}

// Régénère une feuille de secours : un nouveau code aléatoire ré-enveloppe
// l'AccountKey existante et invalide l'ancienne feuille. Le code en clair n'est
// jamais transmis au serveur (zéro-knowledge) — seules les enveloppes opaques le sont.
// Les paramètres KDF doivent être ceux du compte (renvoyés plus tard par /recovery/start).
export async function buildRecoverySheet(
  accountKey: Bytes,
  p: KdfParams = KDF_DEFAULT
): Promise<{ recoveryCode: string; payload: Record<string, unknown> }> {
  await ready();
  const recoverySalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const recoveryCode = formatRecoveryCode(sodium.randombytes_buf(20));
  const recoveryKey = argon2id(enc(recoveryCode), recoverySalt, p, 32);
  const wrappedAccountKeyByRecovery = sealB64(accountKey, recoveryKey);
  const recoveryAuthHash = b64(deriveRecoveryAuth(recoveryKey));
  return {
    recoveryCode,
    payload: {
      recoverySalt: b64(recoverySalt),
      wrappedAccountKeyByRecovery,
      recoveryAuthHash
    }
  };
}

// ---- Transmission : clé de legs et chiffrement du bundle ----

// Clé de legs aléatoire (32 octets), découpée ensuite en fragments SLIP-39.
export function makeLegacyKey(): Bytes {
  return sodium.randombytes_buf(32);
}

// Chiffre le bundle (octets) avec la clé de legs ; renvoie nonce+ct en base64.
export function encryptBundle(plaintext: Bytes, legacyKey: Bytes): string {
  return sealB64(plaintext, legacyKey);
}

// Déchiffre le bundle avec la clé de legs recomposée depuis les fragments.
export function decryptBundle(packed: string, legacyKey: Bytes): Bytes {
  return openB64(packed, legacyKey);
}

// ---- Message privé : sealed-box vers la clé publique du destinataire ----

// Scelle un message vers la clé publique du destinataire (anonyme, sans clé de l'expéditeur).
export function sealTo(recipientPublicKeyB64: string, message: string): string {
  const pk = unb64(recipientPublicKeyB64);
  return b64(sodium.crypto_box_seal(sodium.from_string(message), pk));
}

// Ouvre un message scellé avec la paire de clés du destinataire.
export function openSealed(sealedB64: string, publicKey: Bytes, privateKey: Bytes): string {
  const pt = sodium.crypto_box_seal_open(unb64(sealedB64), publicKey, privateKey);
  return sodium.to_string(pt);
}

