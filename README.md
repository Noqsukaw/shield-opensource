# Liberty Shield — Module de chiffrement (open source)

Ce dépôt publie le **cœur cryptographique côté client** de [Liberty Shield](https://libertyshield.app) et son **décrypteur hors-ligne**. Il est ouvert pour une raison simple : un coffre-fort ne mérite la confiance que si l'on peut vérifier comment il protège vos données. Ici, tout est lisible.

Liberty Shield est un coffre numérique **zero-knowledge** : le chiffrement et le déchiffrement ont lieu **sur votre appareil**, dans le navigateur. Le serveur ne reçoit, ne stocke et ne transmet jamais que des données déjà chiffrées, illisibles pour nous. Nous ne détenons aucune clé et ne connaissons jamais votre mot de passe maître.

## Ce que contient ce dépôt

- `src/crypto.ts` — le module de chiffrement client, dans son intégralité : dérivation de clés, hiérarchie de clés, chiffrement des fiches et des fichiers, feuille de secours, niveaux de sensibilité, et chiffrement du legs de transmission.
- `decryptor.html` — le décrypteur **hors-ligne** que les héritiers utilisent pour recomposer une clé de legs à partir de leurs fragments et ouvrir le coffre transmis, **sans aucune connexion à nos serveurs**.

## Ce qu'il ne contient pas — et pourquoi

Ni infrastructure serveur, ni clés, ni logique métier. Par conception : ces éléments n'ont aucune incidence sur la sécurité de vos secrets, qui repose entièrement sur le chiffrement client publié ici. Ce que vous voyez dans ce dépôt suffit à vérifier que **nous ne pouvons techniquement pas lire vos coffres**.

## Architecture, en bref

- **Chiffrement** : XChaCha20-Poly1305 (AEAD), nonce aléatoire de 24 octets à chaque opération. Toute altération est détectée.
- **Dérivation de clé** : Argon2id (64 Mio de mémoire, 3 itérations), via `libsodium`. Aucune cryptographie « maison ».
- **Hiérarchie de clés** : le mot de passe maître dérive une *MasterKey* qui enveloppe une *AccountKey* aléatoire ; celle-ci enveloppe la clé privée et les clés de coffres ; chaque fiche possède sa propre clé. Compromettre une fiche n'expose jamais le reste.
- **Authentification** : le serveur ne reçoit qu'une empreinte (BLAKE2b avec séparation de domaine), jamais le mot de passe ni la *MasterKey*.
- **Niveaux** : Courant, Confidentiel (mot de passe maître **et** un second code), Sanctuaire (mot de passe maître **et** une phrase). Chaque niveau a son propre verrou.
- **Feuille de secours** : 160 bits d'aléa, à imprimer et garder hors-ligne ; enveloppe l'*AccountKey* pour récupérer un mot de passe maître oublié.
- **Transmission** : une clé de legs aléatoire chiffre le coffre transmis, puis est découpée en fragments **SLIP-39** à seuil (M-sur-N) remis en main propre. La clé n'est jamais stockée ; elle n'existe que recomposée par les héritiers.

Le détail complet du modèle est décrit dans le whitepaper sécurité (voir plus bas).

## Vérifier par soi-même

```bash
npm install
npx tsc --noEmit src/crypto.ts   # vérifie que le module compile
```

Lisez `src/crypto.ts` : chaque fonction est commentée. Vous pouvez confirmer que le mot de passe maître ne quitte jamais l'appareil (seule une empreinte dérivée part au serveur), que les nonces sont tirés aléatoirement, et qu'aucune clé en clair n'est transmise.

## Le décrypteur hors-ligne

`decryptor.html` est un fichier **statique et autonome**. Téléchargez-le, coupez votre connexion, ouvrez-le dans un navigateur : il reconstitue une clé de legs à partir du seuil de fragments SLIP-39 et déchiffre le coffre transmis. Il ne contacte aucun serveur. C'est ce qui garantit que vos héritiers peuvent récupérer un legs **même si Liberty Shield, l'entreprise, n'existe plus**.

## Whitepaper sécurité

Le document de référence (architecture détaillée, modèle de menace, coût d'attaque par niveau, positionnement) est disponible auprès de Liberty Shield.

## Divulgation responsable

Une faille ? Merci de la signaler en privé avant toute divulgation publique : voir [`SECURITY.md`](./SECURITY.md).

## Licence

MIT. Voir [`LICENSE`](./LICENSE).

---

*Liberty Club LLC — Sheridan, Wyoming, USA — contact@libertyclub.finance*
