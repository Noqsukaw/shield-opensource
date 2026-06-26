# Politique de sécurité

La sécurité de Liberty Shield repose sur la cryptographie publiée dans ce dépôt. Nous accueillons toute analyse.

## Signaler une vulnérabilité

Si vous pensez avoir trouvé une faille, **ne la divulguez pas publiquement** dans un premier temps. Écrivez à **contact@libertyclub.finance** avec :

- une description du problème et de son impact ;
- les étapes pour le reproduire ;
- toute suggestion de correction éventuelle.

Nous accusons réception sous quelques jours ouvrés, travaillons à une correction, et créditons publiquement les personnes qui le souhaitent une fois le correctif déployé.

## Périmètre

Ce dépôt couvre le module de chiffrement client (`src/crypto.ts`) et le décrypteur hors-ligne (`decryptor.html`). L'infrastructure serveur n'est pas incluse : par conception, elle ne manipule que des données déjà chiffrées.
