# Architecture et décisions

## 1. Un moteur à nous, Wireshark comme référence

**Décision.** Le moteur (`trame-core`) est écrit en Rust à partir des spécifications (RFC, documents Microsoft pour SMB2). Aucune ligne ne vient du code de Wireshark.

**Pourquoi.**
- **Licence.** Wireshark est sous GPL v2. Traduire son code, à la main ou avec une IA, produirait une œuvre dérivée, elle aussi sous GPL. Un moteur écrit depuis les RFC laisse libre de choisir la licence de Trame, y compris un modèle payant.
- **Contrôle.** Le même moteur tourne en ligne de commande, dans le navigateur (WebAssembly) et, demain, dans l’application de bureau.
- **Fiabilité mesurée.** Wireshark sert de référence de test : `fixtures/make_expected.sh` enregistre ce que `tshark` voit, et `crates/core/tests/parity.rs` exige le même résultat, champ par champ et filtre par filtre. On ne copie pas Wireshark, on se compare à lui.

**Conséquence.** Chaque nouveau protocole doit arriver avec une capture de test et ses références `tshark`.

## 2. Repli sur `sharkd` pour les protocoles non couverts (à faire)

Wireshark décode des milliers de protocoles, Trame quelques dizaines. Pour ne jamais afficher « inconnu », l’application de bureau lancera `sharkd` (le moteur de Wireshark sans interface, piloté en JSON) **dans un processus séparé**, uniquement pour les paquets que Trame ne sait pas lire.

- Dialoguer avec un programme GPL dans un autre processus est en général considéré comme compatible avec une interface sous une autre licence. Si `sharkd` est livré avec l’application, il faut respecter la GPL pour ce composant (fournir son code source).
- **À faire valider par un juriste avant toute commercialisation.**
- Ce repli n’existe pas encore : la version web n’en a pas besoin et l’application de bureau n’est pas commencée.

## 3. Les faits dans le moteur, les phrases dans l’interface

Le moteur produit des **constats** sous la forme d’un type et de paramètres, par exemple `{"kind": "tcp_refused", "params": {"host": "203.0.113.50", "port": 8080, "attempts": 3}}`. Il n’écrit aucune phrase.

Toutes les phrases (débutant et expert) sont rédigées dans `web/app.js`. On peut ainsi traduire l’interface, ajuster le ton ou ajouter un niveau intermédiaire sans toucher au moteur ni à ses tests.

Les noms de champs suivent ceux de Wireshark (`ip.src`, `tcp.analysis.retransmission`, `dns.qry.name`…) : un expert retrouve ses filtres. Les libellés de l’arbre sont en français.

## 4. Deux passes de dissection

1. **Passe 1** : chaque trame est disséquée seule, pour en tirer des faits (adresses, ports, drapeaux TCP, DNS, TLS…).
2. **Analyse** : on suit les flux TCP, on associe les questions et réponses DNS, on regroupe les conversations, on nomme les appareils et on produit les constats. Le résultat, par trame, est un `PacketCtx` (numéros relatifs, notes d’analyse…).
3. **Passe 2** : chaque trame est redisséquée avec son contexte pour produire la ligne affichée et l’arbre. L’arbre n’est pas conservé en mémoire : il est recalculé quand on ouvre un paquet ou qu’on applique un filtre.

**Limites connues** (les plus utiles à lever ensuite) :
- pas de réassemblage TCP : un message TLS ou HTTP réparti sur plusieurs segments n’est décodé que dans son premier segment (Wireshark réassemble) ;
- un filtre redissèque toutes les trames : correct jusqu’à quelques centaines de milliers de paquets, à indexer au-delà ;
- `matches` est pour l’instant une recherche de texte sans tenir compte de la casse, pas une expression régulière.

## 5. WebAssembly sans générateur de liaisons

`crates/wasm` expose une petite API C : `alloc`, `open`, `overview`, `rows`, `frame`, `conversation`, `check_filter`, `index_of`. Les réponses sont en JSON. Pas de `wasm-bindgen` : le binaire fait environ 570 Ko et se charge avec `WebAssembly.instantiate` seul.

## 6. Prochaines étapes, dans l’ordre

1. **Application de bureau (Tauri)** qui reprend `web/` et appelle `trame-core` directement en Rust.
2. **Capture en direct** (libpcap / Npcap) dans l’application de bureau, avec mise à jour incrémentale de l’analyse.
3. **Réassemblage TCP**, puis certificats TLS, en-têtes HTTP sur plusieurs segments, SMB2 complet.
4. **Repli `sharkd`** pour les autres protocoles.
5. **Suivre un flux**, statistiques, export, déchiffrement TLS avec fichier de clés.
6. Nouveaux protocoles, chacun avec sa capture de test et ses références `tshark`.
