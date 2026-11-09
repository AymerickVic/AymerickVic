# Trame

Analyseur de trafic réseau, du débutant à l’expert. Il lit les mêmes captures que Wireshark (`.pcap`, `.pcapng`). En mode **Débutant**, il dit en clair ce qui ne va pas et quoi faire. En mode **Expert**, il donne la liste des paquets, l’arbre de dissection, la vue hexadécimale et des filtres au format Wireshark.

## Ce qui marche aujourd’hui

| Partie | État |
|---|---|
| Lecture pcap / pcapng (Ethernet, IP brut, Linux cooked v1/v2, loopback BSD) | ✅ |
| Dissecteurs : Ethernet, 802.1Q, ARP, IPv4, IPv6, ICMP/ICMPv6, TCP, UDP, DNS, mDNS, TLS (Hello, alertes, SNI, ALPN, versions), QUIC (en-têtes), HTTP/1.x, SMB2 + NetBIOS, DHCP, NTP, SSDP | ✅ |
| Analyse TCP comme Wireshark : numéros relatifs, flux, retransmissions, Dup ACK, segments manquants, fenêtre nulle, RTT initial | ✅ |
| Filtres d’affichage au format Wireshark (`==`, `!=`, `contains`, `in {}`, CIDR, `&&`, `||`, `!`, `&`…) | ✅ |
| Constats automatiques : connexion refusée ou sans réponse, pertes, DNS lent / sans réponse / nom introuvable, TLS dépassé, alerte TLS, mot de passe HTTP en clair, conflit ARP, balayage de ports, ICMP injoignable | ✅ |
| Appareils et noms (DNS, SNI, mDNS, HTTP Host), détection de ce poste et de la box | ✅ |
| Interface web (Débutant + Expert), moteur en WebAssembly, ouverture de fichiers par glisser-déposer | ✅ |
| Ligne de commande `trame` | ✅ |
| Capture en direct, application de bureau | ⏳ prochaine étape |
| Protocoles au-delà de la liste ci-dessus (repli sur `sharkd`) | ⏳ prochaine étape |

## Fidélité à Wireshark

Les tests comparent Trame à `tshark` sur la capture d’exemple (2 905 paquets) :

- 32 champs, paquet par paquet ;
- la colonne Protocole ;
- 35 filtres d’affichage : les paquets retenus doivent être exactement les mêmes.

Résultat actuel : **aucune différence**. Les fichiers de référence sont dans `fixtures/expected/` : la CI n’a donc pas besoin de Wireshark. Un test de robustesse coupe et corrompt aussi des paquets au hasard pour vérifier que rien ne plante sur un fichier malveillant.

## Organisation

```
crates/core   moteur : lecture, dissection, analyse, filtres (Rust, sans dépendance système)
crates/cli    commande `trame`
crates/wasm   le moteur compilé en WebAssembly (API C, réponses JSON)
web/          interface (index.html + app.js), bundle.py pour une page autonome
fixtures/     capture d’exemple, son générateur, et les références tshark
prototype/    la maquette visuelle d’origine
docs/         décisions d’architecture
```

## Commandes

```sh
# Tests (dont la comparaison avec tshark)
cargo test --release

# Ligne de commande
cargo build --release -p trame-cli
./target/release/trame summary fixtures/sample.pcapng
./target/release/trame list fixtures/sample.pcapng -Y "tcp.analysis.flags"
./target/release/trame show fixtures/sample.pcapng 1448
./target/release/trame fields fixtures/sample.pcapng -e ip.src -e dns.qry.name -Y dns

# Interface web
rustup target add wasm32-unknown-unknown
cargo build --profile wasm --target wasm32-unknown-unknown -p trame-wasm
cp target/wasm32-unknown-unknown/wasm/trame_wasm.wasm web/trame.wasm
cp fixtures/sample.pcapng web/
python3 -m http.server -d web 8000           # puis http://localhost:8000
python3 web/bundle.py                        # ou une page unique : dist/trame.html

# Régénérer la capture d’exemple et les références (scapy + tshark)
python3 fixtures/make_sample.py && fixtures/make_expected.sh
```

Les décisions techniques (moteur maison, rôle de Wireshark, licence) sont expliquées dans [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
