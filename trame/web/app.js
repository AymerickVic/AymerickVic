/* Trame interface. Talks to the Rust engine compiled to WebAssembly (trame.wasm).
   The engine returns facts (kinds and parameters); every sentence a person reads is written here. */
(() => {
'use strict';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const nf = (n, d = 0) => Number(n).toLocaleString('fr-FR', {minimumFractionDigits: d, maximumFractionDigits: d});
const fmtBytes = b => b < 1000 ? b + ' o' : b < 1e6 ? nf(b / 1000, b < 1e4 ? 1 : 0) + ' Ko' : nf(b / 1e6, 1) + ' Mo';
const fmtDur = s => s < 1 ? nf(s * 1000, 0) + ' ms' : nf(s, s < 10 ? 1 : 0) + ' s';
const fmtDelta = s => s < 0.0005 ? '+0' : s < 1 ? '+' + nf(s * 1000, s < 0.1 ? 1 : 0) + ' ms' : '+' + nf(s, 2) + ' s';
const plural = (n, one, many) => n + ' ' + (n > 1 ? many : one);

/* ------------------------------------------------------------------ engine */
const Engine = {
  ex: null,
  async init() {
    let bytes;
    if (window.TRAME_WASM_B64) bytes = Uint8Array.from(atob(window.TRAME_WASM_B64), c => c.charCodeAt(0));
    else bytes = new Uint8Array(await (await fetch('trame.wasm')).arrayBuffer());
    const {instance} = await WebAssembly.instantiate(bytes, {});
    this.ex = instance.exports;
  },
  put(u8) {
    const p = this.ex.alloc(u8.length);
    new Uint8Array(this.ex.memory.buffer, p, u8.length).set(u8);
    return p;
  },
  str(s) { const u = new TextEncoder().encode(s); return [this.put(u), u.length]; },
  read(code) {
    const json = new TextDecoder().decode(new Uint8Array(this.ex.memory.buffer, this.ex.out_ptr(), this.ex.out_len()));
    const v = JSON.parse(json);
    if (code < 0) throw new Error(v.error);
    return v;
  },
  open(u8) { return this.read(this.ex.open(this.put(u8), u8.length)); },
  overview() { return this.read(this.ex.overview()); },
  rows(filter, offset, limit) { const [p, l] = this.str(filter); return this.read(this.ex.rows(p, l, offset, limit)); },
  check(filter) { const [p, l] = this.str(filter); try { this.read(this.ex.check_filter(p, l)); return null; } catch (e) { return e.message; } },
  indexOf(filter, frame) { const [p, l] = this.str(filter); return this.read(this.ex.index_of(p, l, frame)).index; },
  frame(n) { return this.read(this.ex.frame(n)); },
  conv(id, max = 40) { return this.read(this.ex.conversation(id, max)); },
};

/* ------------------------------------------------------------------ state */
const st = {
  mode: 'b', ov: null, fileName: '', sample: false,
  open: null, seqOpen: false, ev: 0, convCache: new Map(),
  filter: '', matched: 0, pages: new Map(), sel: null, frame: null, field: null, expanded: new Set(['frame', 'eth', 'ip', 'ipv6', 'tcp', 'udp']),
  tab: 'finds',
};
try { const m = localStorage.getItem('trame-mode'); if (m === 'e' || m === 'b') st.mode = m; } catch (e) {}
const B = () => st.mode === 'b';

/* ------------------------------------------------------------------ naming */
const hostByIp = ip => st.ov.hosts.find(h => h.ip === ip);
const PORT_NAMES = {20:'FTP',21:'FTP',22:'SSH',23:'Telnet',25:'e-mail (SMTP)',53:'DNS',80:'web (HTTP)',110:'e-mail (POP3)',123:'heure (NTP)',139:'partage Windows',143:'e-mail (IMAP)',443:'web sécurisé (HTTPS)',445:'partage de fichiers (SMB)',554:'flux vidéo (RTSP)',631:'impression (IPP)',993:'e-mail (IMAPS)',1883:'MQTT',3306:'MySQL',3389:'bureau à distance',5353:'annonces locales',5432:'PostgreSQL',8080:'web alternatif',8443:'web sécurisé alternatif'};
function name(ip) {
  if (ip === '224.0.0.251' || ip === 'ff02::fb') return 'Tout le réseau local';
  if (ip === '255.255.255.255') return 'Tout le réseau local';
  const h = hostByIp(ip);
  if (!h) return ip;
  if (h.role === 'self') return 'Ce poste';
  if (h.role === 'gateway') return 'Box internet';
  if (h.names.length) return h.names[0].replace(/\.$/, '');
  if (h.scope === 'local') {
    if (h.services.includes(445) || h.services.includes(139)) return 'NAS';
    if (h.services.includes(631) || h.services.includes(9100)) return 'Imprimante';
    if (h.services.includes(554)) return 'Caméra';
    if (h.services.includes(80) || h.services.includes(443)) return 'Appareil web (.' + ip.split('.').pop() + ')';
  }
  if (st.ov.convs.some(c => c.app === 'DNS' && c.b.ip === ip)) return 'Serveur DNS (' + ip + ')';
  return ip;
}
const APP_B = {TLS:'connexion sécurisée', QUIC:'connexion sécurisée (QUIC)', DNS:'recherche d’adresses', mDNS:'annonces locales', SMB2:'partage de fichiers', SMB:'partage de fichiers ancien', HTTP:'web non chiffré', ARP:'voisinage', DHCP:'attribution d’adresse', NTP:'mise à l’heure', SSDP:'découverte d’appareils', ICMP:'messages réseau', TCP:'connexion', UDP:'échange', OTHER:'échange'};
function convTitle(c) {
  const a = name(c.a.ip), b = name(c.b.ip);
  switch (c.app) {
    case 'TLS': return `Connexion sécurisée à ${b}`;
    case 'QUIC': return `Connexion sécurisée (QUIC) à ${b}`;
    case 'DNS': return `Recherche d’adresses auprès de ${b}`;
    case 'mDNS': return `${a} s’annonce sur le réseau`;
    case 'SMB2': case 'SMB': return `Partage de fichiers avec ${b}`;
    case 'HTTP': return `Page web non chiffrée sur ${b}`;
    case 'ARP': return `${a} cherche ${b}`;
    case 'DHCP': return `${a} demande une adresse`;
    case 'NTP': return `Mise à l’heure auprès de ${b}`;
    default: return `${a} et ${b}`;
  }
}
function convOne(c) {
  const parts = [`${fmtBytes(c.bytes)}, ${plural(c.packets, 'paquet', 'paquets')}`];
  if (c.dns_queries) parts.push(plural(c.dns_queries, 'question', 'questions'));
  if (c.rtt) parts.push(`réponse en ${fmtDur(c.rtt)}`);
  return parts.join(' · ');
}

/* ------------------------------------------------------------------ findings wording */
const portTxt = p => PORT_NAMES[p] ? ` (${PORT_NAMES[p]})` : '';
const FIND = {
  tcp_refused: p => ({
    tB: 'Connexion refusée', tE: `TCP RST sur :${p.port}`,
    one: `${name(p.host)} refuse les connexions sur la porte ${p.port} : le service attendu ne tourne pas.`,
    sub: `${name(p.host)} · ${plural(p.attempts, 'tentative', 'tentatives')}`, subE: `${p.attempts} SYN → RST/ACK en ${nf(p.reply_ms, 1)} ms`,
    sum: `Ce poste a essayé ${p.attempts > 1 ? p.attempts + ' fois' : ''} de joindre ${name(p.host)} sur la porte ${p.port}${portTxt(p.port)}. La machine répond bien, en ${nf(p.reply_ms, 0)} ms, mais refuse la connexion${p.attempts > 1 ? ' à chaque fois' : ''} : aucun programme n’écoute sur cette porte.`.replace('essayé  de', 'essayé de'),
    todo: ['Vérifie que le service est bien démarré sur cette machine.', `Vérifie le numéro de port dans ta configuration : ${p.port} est-il le bon ?`, 'Si un pare-feu protège la machine, il est peut-être réglé pour refuser cette porte.'],
    sumE: `${p.attempts} SYN vers ${p.host}:${p.port}, chacun suivi d’un RST/ACK en ${nf(p.reply_ms, 1)} ms. L’hôte est joignable et sa pile TCP répond : port fermé, pas filtré (un filtrage DROP donnerait des SYN retransmis sans réponse).`,
  }),
  tcp_no_answer: p => ({
    tB: 'Aucune réponse', tE: `SYN sans réponse vers :${p.port}`,
    one: `${name(p.host)} ne répond pas sur la porte ${p.port}.`,
    sub: `${name(p.host)} · ${plural(p.attempts, 'essai', 'essais')}`, subE: `${p.attempts} SYN, aucune réponse`,
    sum: `Ce poste a essayé de joindre ${name(p.host)} sur la porte ${p.port}${portTxt(p.port)}, sans aucune réponse. La machine est peut-être éteinte, l’adresse fausse, ou un pare-feu bloque silencieusement.`,
    todo: ['Vérifie que la machine est allumée et connectée.', 'Vérifie l’adresse et le numéro de port utilisés.', 'Un pare-feu peut bloquer cette porte sans prévenir.'],
    sumE: `${p.attempts} SYN vers ${p.host}:${p.port} sans SYN/ACK ni RST : filtrage DROP, route manquante ou hôte éteint.`,
  }),
  tcp_loss: p => {
    const local = isLocal(p.from) && isLocal(p.to);
    return {
      tB: 'Des morceaux se perdent', tE: `${p.retrans} retransmissions ${p.app}`,
      one: `L’échange avec ${name(isSelf(p.from) ? p.to : p.from)} a ralenti : des morceaux se sont perdus en route.`,
      sub: `${name(p.from)} → ${name(p.to)} · ${p.retrans} renvois`, subE: `${nf(p.pct, 2)} % · ${nf(p.start, 2)} → ${nf(p.end, 2)} s`,
      sum: `Pendant cet échange (${APP_B[p.app] || p.app}), ${p.retrans} morceaux envoyés par ${name(p.from)} se sont perdus et ont dû être renvoyés, sur ${nf(p.packets)}. ${local ? 'Sur un réseau local, on devrait être proche de zéro.' : 'Au-delà de 1 %, la vitesse chute nettement.'} Chaque perte fait ralentir l’envoi pendant un moment.`,
      todo: local
        ? ['Si un des appareils est en Wi-Fi, refais l’essai en câble pour comparer.', 'Essaie un autre câble ou un autre port sur la box ou le switch.', 'Regarde si les pertes reviennent toujours au même moment : un autre appareil sature peut-être le réseau.']
        : ['Refais l’essai à un autre moment pour voir si les pertes se répètent.', 'Si tu es en Wi-Fi, rapproche-toi de la box ou passe en câble.', 'Si ça persiste, ta connexion internet ou le serveur distant peut être en cause.'],
      sumE: `${p.retrans} retransmissions (${nf(p.pct, 2)} % des segments de données) de ${p.from} vers ${p.to}, entre ${nf(p.start, 3)} et ${nf(p.end, 3)} s. ${p.dup_acks} Dup ACK, ${p.lost} trou(s) de séquence observés côté récepteur : pertes réelles en aval de l’émetteur, pas un délai applicatif.`,
    };
  },
  tcp_zero_window: p => ({
    tB: 'Un appareil est débordé', tE: `${p.count} ZeroWindow`,
    one: `${name(p.b)} ou ${name(p.a)} n’arrive plus à suivre et demande de faire une pause.`,
    sub: `${name(p.a)} ⇄ ${name(p.b)}`, subE: `${p.count} annonces de fenêtre nulle`,
    sum: `À ${p.count} reprises, un des deux appareils a annoncé qu’il ne pouvait plus rien recevoir pour l’instant. L’autre a dû attendre. C’est souvent un appareil lent, un disque plein ou un programme qui ne lit pas assez vite.`,
    todo: ['Regarde si l’appareil qui reçoit est très chargé (processeur, disque).'],
    sumE: `${p.count} segments avec fenêtre de réception nulle entre ${p.a} et ${p.b} : le récepteur ne consomme pas son tampon assez vite.`,
  }),
  dns_slow: p => ({
    tB: 'Réponse DNS lente', tE: `DNS ${nf(p.ms)} ms`,
    one: `Trouver l’adresse de ${p.name} a pris ${nf(p.ms)} ms au lieu de ${nf(p.median_ms)} ms d’habitude.`,
    sub: `${p.name} · ${nf(p.ms)} ms`, subE: `${p.name}, médiane ${nf(p.median_ms)} ms`,
    sum: `Avant de contacter un site, ce poste demande son adresse à un annuaire, le DNS. Ici, la réponse pour ${p.name} a mis ${nf(p.ms)} ms, environ ${Math.max(2, Math.round(p.ms / Math.max(1, p.median_ms)))} fois plus que d’habitude sur ce réseau. Le site a donc démarré avec ce retard.`,
    todo: ['Une lenteur isolée n’est pas grave : l’annuaire n’avait sans doute pas la réponse en mémoire.', 'Si ça se répète souvent, essaie un autre serveur DNS dans les réglages de la box.'],
    sumE: `${p.name} : ${nf(p.ms)} ms, médiane ${nf(p.median_ms)} ms sur ${p.answered} réponses. Probablement un cache froid côté résolveur et une récursion lente.`,
  }),
  dns_unanswered: p => ({
    tB: 'Questions DNS sans réponse', tE: `${p.count} requêtes DNS sans réponse`,
    one: `${plural(p.count, 'recherche d’adresse est restée', 'recherches d’adresse sont restées')} sans réponse.`,
    sub: p.names.slice(0, 2).join(', '), subE: p.names.slice(0, 3).join(', '),
    sum: `Ce poste a demandé l’adresse de ${p.names.slice(0, 3).join(', ')} et n’a jamais eu de réponse. Les sites concernés n’ont pas pu s’ouvrir.`,
    todo: ['Vérifie que la box ou le serveur DNS répond.', 'Essaie un autre serveur DNS dans les réglages réseau.'],
    sumE: `${p.count} requêtes sans réponse après 2 s : perte UDP, résolveur injoignable ou filtrage du port 53.`,
  }),
  dns_servfail: p => ({
    tB: 'L’annuaire DNS a échoué', tE: 'DNS SERVFAIL',
    one: `L’annuaire n’a pas su répondre pour ${p.names[0]}.`,
    sub: p.names.slice(0, 2).join(', '), subE: p.names.slice(0, 3).join(', '),
    sum: `Le serveur DNS a répondu qu’il avait échoué pour ${p.names.join(', ')}. Le problème vient de l’annuaire ou du domaine, pas de ce poste.`,
    todo: ['Réessaie plus tard, ou change de serveur DNS.'], sumE: `RCODE 2 (Server failure) pour ${p.names.join(', ')}.`,
  }),
  dns_nxdomain: p => {
    const wpad = p.names.some(n => /^wpad\./i.test(n));
    return {
      tB: 'Nom introuvable', tE: 'DNS NXDOMAIN',
      one: `${p.names.slice(0, 2).join(', ')} n’existe pas.${wpad ? ' C’est normal ici.' : ''}`,
      sub: p.names.slice(0, 2).join(', '), subE: p.names.slice(0, 3).join(', '),
      sum: `Ce poste a demandé l’adresse de ${p.names.join(', ')}, et l’annuaire a répondu que ce nom n’existe pas. ${wpad ? 'wpad sert à trouver automatiquement un proxy sous Windows : si tu n’utilises pas de proxy, cette recherche sans réponse est normale.' : 'C’est souvent une faute de frappe, ou un service qui a changé de nom.'}`,
      todo: wpad ? [] : ['Vérifie l’orthographe du nom dans la configuration qui l’utilise.'],
      sumE: `RCODE 3 (No such name) pour ${p.names.join(', ')}.`,
    };
  },
  tls_old: p => ({
    tB: 'Chiffrement dépassé', tE: `${p.version} négocié`,
    one: `${p.host} utilise ${p.version}, une protection périmée. Le problème vient du site.`,
    sub: `${p.host} · ${p.version}`, subE: `${p.host}, version < TLS 1.2`,
    sum: `Ce poste a proposé un chiffrement moderne, mais ${p.host} a répondu avec ${p.version.replace('TLSv1', 'TLS 1.0').replace('TLS 1.0.1', 'TLS 1.1')}, une version abandonnée par les navigateurs depuis 2020 car elle a des failles connues. La connexion a été coupée. Ton ordinateur n’est pas en cause.`,
    todo: ['Préviens le responsable du site : son serveur doit être mis à jour.', 'Ne désactive pas la protection de ton navigateur pour y accéder.'],
    sumE: `Le serveur impose ${p.version} malgré supported_versions 1.3/1.2 côté client. Le client émet ensuite une alerte fatale protocol_version.`,
  }),
  tls_alert: p => ({
    tB: 'Connexion sécurisée interrompue', tE: `TLS Alert ${p.desc}`,
    one: `La connexion chiffrée avec ${p.host} a été coupée (${p.desc}).`,
    sub: `${p.host} · ${p.desc}`, subE: `Alerte fatale ${p.code} (${p.desc})`,
    sum: `L’un des deux côtés a arrêté la connexion sécurisée avec ${p.host}, en signalant « ${p.desc} ». Souvent : certificat invalide ou expiré, ou désaccord sur le chiffrement.`,
    todo: ['Vérifie la date et l’heure de ce poste.', 'Si le site est le tien, vérifie son certificat.'], sumE: `Alerte TLS fatale ${p.code} (${p.desc}).`,
  }),
  http_basic_auth: p => ({
    tB: 'Mot de passe envoyé en clair', tE: 'HTTP Basic en clair',
    one: `Le mot de passe de ${name(p.host)} circule sans chiffrement${p.weak_password ? ', et c’est un mot de passe par défaut' : ''}.`,
    sub: `${name(p.host)} · identifiant « ${p.user} »`, subE: `${p.host}, utilisateur ${p.user}`,
    sum: `Ce poste s’est connecté à ${name(p.host)} avec l’identifiant « ${p.user} ». La connexion n’est pas chiffrée : n’importe quel appareil du réseau peut lire ce mot de passe.${p.weak_password ? ' En plus, c’est un mot de passe par défaut, facile à deviner.' : ''}`,
    todo: ['Change le mot de passe de cet appareil' + (p.weak_password ? ', en choisissant un mot de passe unique.' : '.'), 'Active HTTPS dans ses réglages s’il le propose.', 'Mets l’appareil à jour, ou isole-le sur un réseau invité.'],
    sumE: `Authorization: Basic vers ${p.host}, utilisateur ${p.user}${p.weak_password ? ', mot de passe faible' : ''}. Identifiants encodés en base64, lisibles par toute personne qui capture le trafic.`,
  }),
  http_cleartext: p => ({
    tB: 'Site non chiffré', tE: 'HTTP en clair',
    one: `${p.host} est consulté sans chiffrement.`, sub: p.host, subE: p.host,
    sum: `Les échanges avec ${p.host} ne sont pas chiffrés : ce que tu y envoies peut être lu sur le réseau.`,
    todo: ['Préfère l’adresse en https:// si le site la propose.'], sumE: `HTTP/1.x en clair vers ${p.host}.`,
  }),
  arp_conflict: p => ({
    tB: 'Deux appareils pour la même adresse', tE: `Conflit ARP sur ${p.ip}`,
    one: `Plusieurs appareils prétendent être ${p.ip}. Ça peut être une erreur de réglage ou une tentative d’interception.`,
    sub: `${p.ip} · ${p.macs.length} adresses matérielles`, subE: p.macs.join(', '),
    sum: `L’adresse ${p.ip} est annoncée par ${p.macs.length} appareils différents (${p.macs.join(', ')}). Soit deux appareils ont la même adresse par erreur, soit quelqu’un se fait passer pour un autre afin d’intercepter le trafic.`,
    todo: ['Si c’est l’adresse de la box, déconnecte les appareils inconnus et préviens la personne qui gère le réseau.', 'Sinon, vérifie qu’aucun appareil n’a d’adresse fixe en double.'],
    sumE: `Réponses ARP pour ${p.ip} depuis ${p.macs.join(', ')} : conflit d’adresse ou ARP spoofing.`,
  }),
  port_scan: p => ({
    tB: 'Balayage de ports', tE: `Scan de ${p.ports} ports`,
    one: `${name(p.src)} a testé ${p.ports} portes de ${name(p.dst)} : quelqu’un cherche des services ouverts.`,
    sub: `${name(p.src)} → ${name(p.dst)}`, subE: `${p.src} → ${p.dst}, ${p.ports} ports`,
    sum: `${name(p.src)} a tenté d’ouvrir des connexions sur ${p.ports} portes différentes de ${name(p.dst)} en peu de temps. C’est le comportement d’un outil de balayage : normal si c’est toi qui le lances, inquiétant sinon.`,
    todo: ['Si tu ne reconnais pas cet appareil, isole-le du réseau.'], sumE: `SYN vers ${p.ports} ports distincts de ${p.dst} depuis ${p.src}.`,
  }),
  icmp_unreachable: p => ({
    tB: 'Destination injoignable', tE: `${p.count} ICMP unreachable`,
    one: `Le réseau a signalé ${plural(p.count, 'fois', 'fois')} qu’une destination était injoignable.`,
    sub: p.from.map(name).join(', '), subE: p.from.join(', '),
    sum: `Des équipements du réseau ont prévenu que certains envois n’ont pas pu arriver à destination.`,
    todo: ['Regarde dans le mode Expert quelles destinations sont concernées.'], sumE: `${p.count} messages ICMP Destination Unreachable depuis ${p.from.join(', ')}.`,
  }),
};
const isLocal = ip => { const h = hostByIp(ip); return h ? h.scope === 'local' : false; };
const isSelf = ip => { const h = hostByIp(ip); return h && h.role === 'self'; };
function words(f) { return (FIND[f.kind] || (p => ({tB: f.kind, tE: f.kind, one: '', sub: '', subE: '', sum: JSON.stringify(p), todo: [], sumE: JSON.stringify(p)})))(f.params); }

/* ------------------------------------------------------------------ small renderers */
const GROUP_VAR = g => `var(--g-${g})`;
const GROUP_NAME = {secure:'Chiffré', dns:'Annuaire (DNS)', file:'Partage de fichiers', web:'Web non chiffré', tcp:'Autre TCP', udp:'Autre UDP', local:'Réseau local', icmp:'Messages réseau', other:'Autre'};
const GROUP_NAME_E = {secure:'TLS / QUIC', dns:'DNS', file:'SMB / NBSS', web:'HTTP', tcp:'TCP', udp:'UDP', local:'ARP, mDNS, DHCP…', icmp:'ICMP', other:'Autre'};
const wire = g => `<span class="wire" style="--c:${GROUP_VAR(g)}"></span>`;
function glyph(sev, size = 11) {
  if (sev === 'crit') return `<svg class="glyph" width="${size}" height="${size}" viewBox="0 0 10 10" aria-label="Problème important"><path d="M5 .5 9.5 5 5 9.5 .5 5z" style="fill:var(--crit)"/></svg>`;
  if (sev === 'warn') return `<svg class="glyph" width="${size}" height="${size}" viewBox="0 0 10 10" aria-label="À surveiller"><path d="M5 .8 9.6 9.2H.4z" style="fill:var(--warn)"/></svg>`;
  if (sev === 'info') return `<svg class="glyph" width="${size}" height="${size}" viewBox="0 0 10 10" aria-label="Information"><circle cx="5" cy="5" r="4" style="fill:var(--ink3)"/><path d="M5 4.2v3M5 2.5v.4" style="stroke:var(--panel);stroke-width:1.2"/></svg>`;
  return `<svg class="glyph" width="${size}" height="${size}" viewBox="0 0 10 10" aria-label="Normal"><circle cx="5" cy="5" r="3.6" style="fill:none;stroke:var(--ink3);stroke-width:1.4"/></svg>`;
}
const chev = `<svg class="chev" width="12" height="12" viewBox="0 0 10 10" aria-hidden="true"><path d="M3 1.5 6.5 5 3 8.5" style="fill:none;stroke:var(--ink2);stroke-width:1.6"/></svg>`;
function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toast.h); toast.h = setTimeout(() => { t.hidden = true; }, 4200);
}

/* ------------------------------------------------------------------ sequence diagram */
const EV_B = (e, c) => {
  const d = e.detail || {}, n = e.count || 1;
  switch (e.kind) {
    case 'syn': return 'Bonjour, on peut parler ?';
    case 'synack': return 'Oui, je t’écoute';
    case 'ack': return 'C’est parti';
    case 'rst': return 'Refusé : personne n’écoute ici';
    case 'fin': return 'J’ai fini, au revoir';
    case 'data': return n > 1 ? `${nf(n)} morceaux de données (${fmtBytes(e.bytes)})` : `Données (${fmtBytes(e.bytes)})`;
    case 'lost': return 'Des morceaux se sont perdus avant celui-ci';
    case 'retrans': return n > 1 ? `Renvoi de ${n} morceaux perdus` : 'Renvoi d’un morceau perdu';
    case 'dupack': return n > 1 ? `Il me manque un morceau ! (×${n})` : 'Il me manque un morceau !';
    case 'tls_client_hello': return d.sni ? `Chiffrons, je veux joindre ${d.sni}` : 'Voici comment chiffrer';
    case 'tls_server_hello': return d.version === 'TLSv1.3' ? 'D’accord, chiffrement moderne' : `D’accord, mais en ${d.version || 'TLS'}`;
    case 'tls_alert': return `Alerte : ${d.desc}`;
    case 'tls_data': return n > 1 ? `${nf(n)} messages chiffrés (${fmtBytes(e.bytes)})` : 'Message chiffré';
    case 'http_request': return `Demande ${d.method || ''} ${d.uri || ''}${d.basic ? ' avec mot de passe' : ''}`;
    case 'http_response': return `Réponse ${d.status}`;
    case 'dns_query': return `Quelle est l’adresse de ${d.name} ?`;
    case 'dns_response': return d.answers && d.answers.length ? `C’est ${d.answers[0]}` : 'Réponse sans adresse';
    case 'dns_slow': return `Réponse… ${nf(d.ms)} ms plus tard`;
    case 'dns_error': return d.rcode === 3 ? 'Ce nom n’existe pas' : 'L’annuaire a échoué';
    case 'arp_request': return 'Qui a cette adresse ?';
    case 'arp_reply': return 'C’est moi';
    case 'quic_handshake': return 'Ouverture chiffrée (QUIC)';
    case 'quic_data': return n > 1 ? `${nf(n)} paquets chiffrés (${fmtBytes(e.bytes)})` : 'Paquet chiffré';
    case 'smb_request': return `Demande au partage : ${String(d.info || '').replace(' Request', '')}`;
    case 'smb_response': return `Réponse du partage : ${String(d.info || '').replace(' Response', '')}`;
    case 'icmp': return 'Message d’erreur réseau';
    case 'gap': return `… ${plural(e.count, 'autre étape', 'autres étapes')}`;
    default: return e.info;
  }
};
const EV_DETAIL = (e, c) => {
  const d = e.detail || {};
  switch (e.kind) {
    case 'syn': return `Ce poste demande à ouvrir une connexion sur la porte ${d.port}${portTxt(d.port)}. C’est la première des trois étapes de la « poignée de main » TCP.`;
    case 'synack': return 'L’autre côté accepte. Le temps entre la question et cette réponse mesure la distance réseau.';
    case 'ack': return 'La connexion est ouverte. Tout ce qui suit passe par ce canal.';
    case 'rst': return 'Refus immédiat : la machine est joignable, mais aucun programme n’écoute sur cette porte.';
    case 'fin': return 'Fermeture normale de la connexion.';
    case 'data': return 'Le contenu est découpé en petits morceaux envoyés à la suite.';
    case 'lost': return 'Un trou est apparu : des morceaux précédents ne sont jamais arrivés.';
    case 'retrans': return 'L’émetteur renvoie les morceaux perdus. Pendant ce temps, il ralentit volontairement ses envois.';
    case 'dupack': return 'Le destinataire répète qu’il attend toujours le même morceau, alors que les suivants arrivent : c’est le signal d’une perte.';
    case 'tls_client_hello': return 'Ce poste propose des méthodes de chiffrement et annonce le site qu’il veut joindre. Ce nom est encore lisible ; la suite ne le sera plus.';
    case 'tls_server_hello': return `Le serveur choisit le chiffrement${d.version ? ' : ' + d.version : ''}.`;
    case 'tls_alert': return `Un des deux côtés arrête la connexion sécurisée (« ${d.desc} »).`;
    case 'tls_data': return 'Contenu chiffré : on ne voit plus que sa taille et son rythme.';
    case 'http_request': return d.basic ? 'La demande contient l’identifiant et le mot de passe, lisibles par n’importe qui sur le réseau.' : 'Demande web non chiffrée : son contenu est lisible sur le réseau.';
    case 'http_response': return `Le serveur répond avec le code ${d.status}.`;
    case 'dns_query': return `Avant de contacter ${d.name}, ce poste demande son adresse à l’annuaire (DNS).`;
    case 'dns_response': case 'dns_slow': return `Réponse en ${nf(d.ms || 0)} ms${d.answers && d.answers.length ? ' : ' + d.answers.join(', ') : ''}.`;
    case 'dns_error': return 'L’annuaire répond que ce nom n’existe pas, ou qu’il n’a pas pu le trouver.';
    case 'arp_request': return 'Sur le réseau local, les appareils se repèrent par leur adresse matérielle. Cette question est envoyée à tous.';
    case 'arp_reply': return 'Seul l’appareil concerné répond, avec son adresse matérielle.';
    case 'quic_handshake': case 'quic_data': return 'QUIC chiffre tout, y compris les accusés de réception.';
    default: return '';
  }
};
function seqSvg(data, selIdx) {
  const c = data.conv, evs = data.events, beg = B();
  const W = 420, xA = 104, xB = 392, top = 52, rh = beg ? 50 : 36, H = top + evs.length * rh + 8, t0 = evs[0] ? evs[0].t : 0;
  let s = `<svg class="seq" viewBox="0 0 ${W} ${H}" aria-label="Déroulé de l’échange"><defs>${['ink', 'crit', 'warn', 'mut'].map(k => `<marker id="ah-${k}" viewBox="0 0 8 8" refX="7.5" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,.6 L8,4 L0,7.4z" style="fill:var(--m-${k})"/></marker>`).join('')}</defs>
    <text class="lane-h" x="${xA}" y="16" text-anchor="middle">${esc(name(c.a.ip))}</text><text class="lane-s" x="${xA}" y="30" text-anchor="middle">${esc(c.a.ip)}${c.a.port ? ':' + c.a.port : ''}</text>
    <text class="lane-h" x="${W - 2}" y="16" text-anchor="end">${esc(name(c.b.ip))}</text><text class="lane-s" x="${W - 2}" y="30" text-anchor="end">${esc(c.b.ip)}${c.b.port ? ':' + c.b.port : ''}</text>
    <line class="lane" x1="${xA}" y1="38" x2="${xA}" y2="${H - 4}"/><line class="lane" x1="${xB}" y1="38" x2="${xB}" y2="${H - 4}"/>`;
  const COL = {rst: 'crit', tls_alert: 'crit', lost: 'crit', retrans: 'warn', dupack: 'warn', dns_slow: 'warn', dns_error: 'warn', data: 'mut', tls_data: 'mut', quic_data: 'mut'};
  evs.forEach((e, i) => {
    const y = top + i * rh, on = selIdx === i, col = COL[e.kind] || (e.kind === 'tls_server_hello' && e.detail && e.detail.version && e.detail.version !== 'TLSv1.3' && e.detail.version !== 'TLSv1.2' ? 'warn' : e.kind === 'http_request' && e.detail && e.detail.basic ? 'crit' : 'ink');
    const label = beg ? EV_B(e, c) : (e.info || EV_B(e, c)) + (e.count > 1 ? `  ×${e.count}` : '');
    s += `<g class="ev${on ? ' on' : ''}" data-i="${i}" tabindex="0" role="button" aria-pressed="${on}"><rect class="bg" x="0" y="${y - 6}" width="${W}" height="${rh}" rx="2"/>`;
    if (e.kind === 'gap') { s += `<text class="gap" x="${(xA + xB) / 2}" y="${y + rh / 2 - 2}" text-anchor="middle">${esc(EV_B(e, c))}</text></g>`; return; }
    const x1 = e.dir === 'ab' ? xA : xB, x2 = e.dir === 'ab' ? xB : xA, y1 = y + (beg ? 20 : 15), y2 = y1 + 9, lx = (xA + xB) / 2;
    const short = label.length > 46 ? label.slice(0, 45) + '…' : label;
    s += `<text class="dt" x="4" y="${y1 + 4}">${fmtDelta(e.t - t0)}</text>`;
    s += `<text class="lb${beg ? '' : ' m'}" x="${lx}" y="${y1 - 6}" text-anchor="middle" style="fill:var(--m-${col === 'mut' ? 'ink' : col})">${esc(short)}</text>`;
    const dash = ['retrans', 'dupack'].includes(e.kind) ? ';stroke-dasharray:5 3' : '';
    s += `<line x1="${x1}" y1="${y1}" x2="${x2 + (x2 > x1 ? -1 : 1)}" y2="${y2}" marker-end="url(#ah-${col})" style="stroke:var(--m-${col});stroke-width:${col === 'mut' ? 1.2 : 1.5}${dash}"/>`;
    if (beg) { const tech = (e.info || '').replace(/^\[[^\]]+\]\s*/, ''); s += `<text class="tt" x="${lx}" y="${y2 + 13}" text-anchor="middle">${esc(tech.length > 58 ? tech.slice(0, 57) + '…' : tech)}${e.count > 1 ? ' ×' + e.count : ''}</text>`; }
    s += `</g>`;
  });
  return s + '</svg>';
}
function convData(id) {
  if (!st.convCache.has(id)) st.convCache.set(id, Engine.conv(id, 36));
  return st.convCache.get(id);
}

/* ------------------------------------------------------------------ map */
function renderMap() {
  const ov = st.ov, svg = $('#map');
  const me = ov.hosts.find(h => h.role === 'self'), gw = ov.hosts.find(h => h.role === 'gateway');
  // Aggregate conversations per pair of hosts.
  const pairs = new Map();
  ov.convs.forEach(c => {
    const k = [c.a.ip, c.b.ip].sort().join('|');
    const p = pairs.get(k) || {a: c.a.ip, b: c.b.ip, bytes: 0, groups: {}, sev: 'ok', convs: []};
    p.bytes += c.bytes; p.groups[c.group] = (p.groups[c.group] || 0) + c.bytes; p.convs.push(c.id);
    const r = s => ({crit: 3, warn: 2, info: 1})[s] || 0;
    if (r(c.severity) > r(p.sev)) p.sev = c.severity;
    pairs.set(k, p);
  });
  const placed = new Map();
  const lanX = 150, gwX = 400, netX = 560;
  if (me) placed.set(me.ip, {x: lanX + 40, y: 240, me: true});
  if (gw) placed.set(gw.ip, {x: gwX, y: 240, gw: true});
  const talk = ip => [...pairs.values()].filter(p => p.a === ip || p.b === ip).reduce((s, p) => s + p.bytes, 0);
  const local = ov.hosts.filter(h => (h.scope === 'local' || h.scope === 'multicast' || h.scope === 'broadcast') && !placed.has(h.ip) && talk(h.ip) > 0).sort((a, b) => talk(b.ip) - talk(a.ip)).slice(0, 6);
  const pub = ov.hosts.filter(h => h.scope === 'public' && talk(h.ip) > 0).sort((a, b) => talk(b.ip) - talk(a.ip));
  const shownPub = pub.slice(0, 8), hiddenPub = pub.length - shownPub.length;
  local.forEach((h, i) => {
    const n = local.length, ang = (-70 + (n === 1 ? 70 : (140 * i) / (n - 1))) * Math.PI / 180;
    placed.set(h.ip, {x: lanX + 40 - Math.cos(ang) * 120, y: 240 + Math.sin(ang) * 175});
  });
  shownPub.forEach((h, i) => placed.set(h.ip, {x: netX, y: 60 + (shownPub.length === 1 ? 180 : (360 * i) / Math.max(1, shownPub.length - 1))}));
  const lw = b => 1.4 + Math.max(0, Math.log10(Math.max(b, 10)) - 2) * 1.3;
  let s = `<rect class="zone" x="8" y="8" width="322" height="444" rx="2"/><text class="zlabel" x="22" y="32">RÉSEAU LOCAL</text>
    <rect class="zone" x="452" y="8" width="340" height="444" rx="2"/><text class="zlabel" x="466" y="32">INTERNET</text>
    <line x1="${gwX}" y1="22" x2="${gwX}" y2="440" style="stroke:var(--rule);stroke-dasharray:2 4"/>`;
  let bundle = 0;
  const edges = [];
  pairs.forEach(p => {
    const A = placed.get(p.a), Bp = placed.get(p.b);
    if (!A || !Bp) return;
    const g = Object.entries(p.groups).sort((x, y) => y[1] - x[1])[0][0];
    let [from, to] = A.me ? [A, Bp] : Bp.me ? [Bp, A] : [A, Bp];
    let d;
    const toNet = to.x >= netX - 1 && gw;
    if (toNet && from.me) {
      const off = (bundle++ % 9 - 4) * 3.4;
      const G = placed.get(gw.ip);
      d = `M${from.x + 12},${from.y + off} L${G.x},${G.y + off} C${G.x + 70},${G.y + off} ${to.x - 110},${to.y} ${to.x - 9},${to.y}`;
    } else {
      d = `M${from.x},${from.y} Q${(from.x + to.x) / 2 + 24},${(from.y + to.y) / 2 - 14} ${to.x},${to.y}`;
    }
    edges.push({d, w: lw(p.bytes), g, sev: p.sev, convs: p.convs});
  });
  edges.sort((a, b) => b.w - a.w).forEach((e, i) => {
    const dim = st.open != null && !e.convs.includes(st.open);
    s += `<path class="edge${dim ? ' dim' : ''}" d="${e.d}" style="stroke:${GROUP_VAR(e.g)};stroke-width:${e.w}"/><path class="hit" d="${e.d}" data-convs="${e.convs.join(',')}" id="edge-${i}"><title>${plural(e.convs.length, 'échange', 'échanges')}</title></path>`;
  });
  s += `<g id="sevmarks"></g>`;
  placed.forEach((p, ip) => {
    const label = name(ip), right = p.x >= netX - 1;
    const lx = right ? p.x + 14 : p.x, ly = right ? p.y + 5 : p.y + (p.me || p.gw ? 34 : 26);
    const anchor = right ? 'start' : 'middle';
    const short = label.length > 24 ? label.slice(0, 23) + '…' : label;
    s += `<g class="node${p.me ? ' me' : ''}" data-ip="${esc(ip)}">${p.gw ? `<rect x="${p.x - 12}" y="${p.y - 12}" width="24" height="24" rx="2"/><path d="M${p.x - 5},${p.y} h10 M${p.x + 2},${p.y - 3} l3,3 -3,3" style="fill:none;stroke:var(--ink);stroke-width:1.4"/>`
      : p.me ? `<circle r="13" cx="${p.x}" cy="${p.y}"/><circle class="core" r="5.5" cx="${p.x}" cy="${p.y}"/>` : `<circle r="8" cx="${p.x}" cy="${p.y}"/>`}
      <text class="nl" x="${lx}" y="${ly}" text-anchor="${anchor}">${esc(short)}</text>${right ? '' : `<text class="ns" x="${lx}" y="${ly + 15}" text-anchor="${anchor}">${esc(ip)}</text>`}<title>${esc(label)} · ${esc(ip)}</title></g>`;
  });
  if (hiddenPub > 0) s += `<text class="ns" x="${netX - 6}" y="446">+ ${plural(hiddenPub, 'autre site', 'autres sites')}</text>`;
  svg.innerHTML = s;
  let m = '';
  edges.forEach((e, i) => {
    if (e.sev !== 'crit' && e.sev !== 'warn') return;
    const p = document.getElementById('edge-' + i); const L = p.getTotalLength(); const pt = p.getPointAtLength(L * 0.82);
    m += e.sev === 'crit' ? `<path class="sevm" d="M${pt.x},${pt.y - 8} l8,8 -8,8 -8,-8z" style="fill:var(--crit);stroke:var(--panel);stroke-width:2"/>` : `<path class="sevm" d="M${pt.x},${pt.y - 8} l8,13 h-16z" style="fill:var(--warn);stroke:var(--panel);stroke-width:2"/>`;
  });
  $('#sevmarks').innerHTML = m;
  const groups = [...new Set(ov.convs.map(c => c.group))];
  $('#legend').innerHTML = groups.map(g => `<span>${wire(g)}${B() ? GROUP_NAME[g] : GROUP_NAME_E[g]}</span>`).join('') + `<span style="color:var(--ink3)">Épaisseur = volume échangé</span>`;
}

/* ------------------------------------------------------------------ beginner report */
function renderStory() {
  const ov = st.ov, fs = ov.findings, me = ov.hosts.find(h => h.role === 'self');
  const important = fs.filter(f => f.severity !== 'info'), crit = fs.filter(f => f.severity === 'crit').length;
  const others = ov.hosts.filter(h => h.role !== 'self' && h.scope !== 'multicast' && h.scope !== 'broadcast').length;
  const top = [...ov.convs].sort((a, b) => b.bytes - a.bytes).slice(0, 2);
  const act = top.map(c => `${APP_B[c.app] || 'échange'} avec ${name(c.b.ip === (me && me.ip) ? c.a.ip : c.b.ip)} (${fmtBytes(c.bytes)})`);
  let h1;
  if (!fs.length) h1 = 'Tout semble normal sur ce réseau.';
  else if (!important.length) h1 = `Tout fonctionne, avec ${plural(fs.length, 'détail', 'détails')} à connaître.`;
  else h1 = `Ton réseau fonctionne, mais ${plural(important.length, 'point mérite', 'points méritent')} ton attention${crit ? (crit === important.length ? '' : `, dont ${crit} important${crit > 1 ? 's' : ''}`) : ''}.`;
  $('#story-head').innerHTML = `<p class="kicker">Bilan · ${nf(ov.summary.duration, 1)} secondes enregistrées</p><h1>${esc(h1)}</h1>
    <p class="lede">${me ? 'Ce poste a' : 'Les appareils capturés ont'} échangé avec ${plural(others, 'appareil ou site', 'appareils et sites')}.${act.length ? ` Les plus gros échanges : ${act.join(', puis ')}.` : ''}</p>`;
  const linked = new Set(fs.map(f => f.conv).filter(c => c != null));
  const ok = [...ov.convs].filter(c => c.severity === 'ok' && !linked.has(c.id)).sort((a, b) => b.bytes - a.bytes);
  const okShown = ok.slice(0, 8);
  let html = '';
  if (fs.length) html += `<section class="group"><h3 class="h"><span>À regarder, le plus important d’abord</span></h3><ul class="items">${fs.map((f, i) => findingItem(f, i)).join('')}</ul></section>`;
  html += `<section class="group"><h3 class="h"><span>Ce qui fonctionne normalement</span></h3><ul class="items">${okShown.map(convItem).join('')}</ul>${ok.length > okShown.length ? `<p class="empty">Et ${plural(ok.length - okShown.length, 'autre échange court', 'autres échanges courts')}, sans problème.</p>` : ''}</section>`;
  $('#story-list').innerHTML = html;
}
function seqBlock(convId) {
  if (!st.seqOpen) return `<button class="more" data-seq="1">Voir l’échange message par message ${chev}</button>`;
  const data = convData(convId), e = data.events[st.ev] || data.events[0];
  return `<div class="seqwrap">${seqSvg(data, st.ev)}</div>
    <div class="msg"><small>Trame ${e.frame} · ${esc(e.info || '')}</small><p>${esc(EV_DETAIL(e, data.conv) || EV_B(e, data.conv))}</p></div>
    <button class="more" data-seq="0">Masquer l’échange</button> <button class="more" data-goto="${e.frame}">Ouvrir ce paquet en mode Expert</button>`;
}
function findingItem(f, i) {
  const w = words(f), key = 'f' + i, open = st.open === key;
  let body = '';
  if (open) {
    body = `<div class="item-b"><p class="prose">${esc(w.sum)}</p>${w.todo && w.todo.length ? `<p class="subh">Que faire</p><ul class="todo">${w.todo.map(t => `<li>${esc(t)}</li>`).join('')}</ul>` : ''}${f.conv != null ? seqBlock(f.conv) : ''}</div>`;
  }
  return `<li class="item" data-open="${open}" id="it-${key}"><button class="item-h" data-open-k="${key}" aria-expanded="${open}"><span class="g">${glyph(f.severity, 12)}</span><span><b>${esc(w.tB)}</b><span class="one">${esc(w.one)}</span></span>${chev}</button>${body}</li>`;
}
function convItem(c) {
  const key = 'c' + c.id, open = st.open === key;
  const body = open ? `<div class="item-b"><p class="prose">${esc(convProse(c))}</p>${seqBlock(c.id)}</div>` : '';
  return `<li class="item ok" data-open="${open}" id="it-${key}"><button class="item-h" data-open-k="${key}" aria-expanded="${open}"><span class="g">${wire(c.group)}</span><span><b>${esc(convTitle(c))}</b><span class="one">${esc(convOne(c))}</span></span>${chev}</button>${body}</li>`;
}
function convProse(c) {
  const b = name(c.b.ip), a = name(c.a.ip);
  const dur = c.end - c.start;
  const base = {
    TLS: `${a} a échangé ${fmtBytes(c.bytes)} avec ${b}, par une connexion chiffrée${c.tls_version ? ' (' + c.tls_version.replace('TLSv', 'TLS ') + ')' : ''}. Le contenu n’est pas lisible, seulement sa taille et son rythme.`,
    QUIC: `${a} a reçu ${fmtBytes(c.b_to_a[1])} de ${b} par QUIC, un protocole récent et entièrement chiffré, souvent utilisé pour la vidéo.`,
    DNS: `Avant de contacter un site, ${a} demande son adresse à ${b}. ${plural(c.dns_queries, 'question posée', 'questions posées')}${c.dns_max_ms ? `, la plus lente en ${nf(c.dns_max_ms)} ms` : ''}.`,
    SMB2: `${a} a échangé ${fmtBytes(c.bytes)} avec le partage de fichiers de ${b}.`,
    ARP: `Sur un réseau local, les appareils se repèrent avec une adresse matérielle. ${a} demande régulièrement qui est ${b}, et la réponse arrive. C’est normal.`,
    mDNS: `${a} annonce sa présence pour que les autres appareils le trouvent sans réglage. Rien à faire.`,
  }[c.app] || `${a} a échangé ${fmtBytes(c.bytes)} avec ${b} en ${fmtDur(dur)}.`;
  return base + (c.rtt ? ` La connexion s’est ouverte en ${fmtDur(c.rtt)}.` : '');
}

/* ------------------------------------------------------------------ expert workbench */
const ROW_H = 24, PAGE = 400;
function quickChips() {
  const chips = [
    ['Problèmes', 'tcp.analysis.flags || tcp.flags.reset == 1 || dns.flags.rcode != 0 || tls.alert_message || http.authorization'],
    ['Poignées de main', 'tcp.flags.syn == 1 || tls.handshake.type in {1, 2}'],
    ['DNS', 'dns'], ['Chiffré', 'tls || quic'], ['Non chiffré', 'http || (tcp.len > 0 && !tls && !quic && !smb2 && !nbss)'],
  ];
  $('#qchips').innerHTML = chips.map(([l, f]) => `<button class="chip" data-filter="${esc(f)}">${l}</button>`).join('');
}
function applyFilter(f, keepSel = true) {
  const err = f.trim() ? Engine.check(f) : null;
  $('#fin').className = 'fin' + (f.trim() ? (err ? ' bad' : ' ok') : '');
  $('#ferr').hidden = !err; $('#ferr').textContent = err ? 'Filtre invalide : ' + err : '';
  if (err) return false;
  st.filter = f.trim(); st.pages.clear();
  const first = Engine.rows(st.filter, 0, PAGE);
  st.pages.set(0, first.rows); st.matched = first.matched;
  $('#fcount').textContent = st.filter ? `${nf(first.matched)} / ${nf(first.total)} paquets` : `${nf(first.total)} paquets`;
  $('#rows').style.height = st.matched * ROW_H + 'px';
  $('#plist').scrollTop = 0;
  if (keepSel && st.sel && Engine.indexOf(st.filter, st.sel) != null) scrollToFrame(st.sel, false);
  else if (first.rows.length) selectFrame(first.rows[0].n, false);
  else { st.sel = null; $('#tree').innerHTML = '<p class="empty" style="padding:8px 12px">Aucun paquet ne correspond à ce filtre.</p>'; $('#hex').innerHTML = ''; }
  paintRows();
  return true;
}
function rowAt(i) {
  const p = Math.floor(i / PAGE);
  if (!st.pages.has(p)) st.pages.set(p, Engine.rows(st.filter, p * PAGE, PAGE).rows);
  return st.pages.get(p)[i - p * PAGE];
}
function paintRows() {
  const el = $('#plist'), head = 29;
  const start = Math.max(0, Math.floor((el.scrollTop - head) / ROW_H) - 5), count = Math.ceil(el.clientHeight / ROW_H) + 12;
  let h = '';
  for (let i = start; i < Math.min(st.matched, start + count); i++) {
    const r = rowAt(i); if (!r) continue;
    h += `<div class="prow${r.x ? ' ' + r.x : ''}${r.n === st.sel ? ' on' : ''}" style="top:${i * ROW_H}px;--c:${GROUP_VAR(r.g)}" data-n="${r.n}"><div>${r.n}</div><div>${r.t.toFixed(6)}</div><div title="${esc(r.src)}">${esc(r.src)}</div><div title="${esc(r.dst)}">${esc(r.dst)}</div><div>${esc(r.proto)}</div><div>${r.len}</div><div title="${esc(r.info)}">${esc(r.info)}</div></div>`;
  }
  $('#rows').innerHTML = h;
}
function scrollToFrame(n, smooth) {
  const i = Engine.indexOf(st.filter, n);
  if (i == null) return false;
  const el = $('#plist'), y = i * ROW_H;
  if (y < el.scrollTop || y > el.scrollTop + el.clientHeight - ROW_H * 3) el.scrollTo({top: Math.max(0, y - el.clientHeight / 3), behavior: smooth ? 'smooth' : 'auto'});
  selectFrame(n, false);
  return true;
}
function selectFrame(n) {
  st.sel = n; st.frame = Engine.frame(n); st.field = null;
  renderTree(); renderHex(); paintRows();
}
function renderTree() {
  const f = st.frame; if (!f) return;
  const node = (x, path) => {
    const key = path + '/' + x.n, has = x.c && x.c.length, open = has && st.expanded.has(x.n);
    const cls = ['tn', has ? 'proto' : '', x.x || '', st.field && st.field.key === key ? 'on' : ''].join(' ');
    const fa = x.v != null ? `<span class="fa"><button data-fa="set" title="Remplacer le filtre">Filtrer</button><button data-fa="and" title="Ajouter au filtre avec &&">+ et</button></span>` : '';
    return `<li><div class="${cls}" data-key="${esc(key)}" data-o="${x.o}" data-s="${x.s}" data-n="${esc(x.n)}" data-v="${esc(x.v ?? '')}"><span class="tg">${has ? (open ? '▾' : '▸') : ''}</span><span class="tl">${esc(x.l || x.n)}</span><span class="tname">${esc(x.n)}</span>${fa}</div>${open ? `<ul>${x.c.map(c => node(c, key)).join('')}</ul>` : ''}</li>`;
  };
  $('#tree').innerHTML = `<ul>${f.tree.map(x => node(x, '')).join('')}</ul>`;
}
function renderHex() {
  const f = st.frame; if (!f) return;
  const hex = f.bytes, n = hex.length / 2, sel = st.field;
  const inSel = i => sel && sel.s > 0 && i >= sel.o && i < sel.o + sel.s;
  let out = '';
  for (let r = 0; r < n; r += 16) {
    let h = '', a = '';
    for (let i = r; i < Math.min(n, r + 16); i++) {
      const b = parseInt(hex.substr(i * 2, 2), 16), on = inSel(i) ? ' on' : '';
      h += `<span class="b${on}" data-i="${i}">${hex.substr(i * 2, 2)}</span>${i % 16 === 7 ? '  ' : ' '}`;
      a += `<span class="${on.trim()}">${b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : '.'}</span>`;
    }
    out += `<div><span class="off">${r.toString(16).padStart(4, '0')}</span>${h.padEnd(1)}<span class="asc">${a}</span></div>`;
  }
  $('#hex').innerHTML = out;
}
function fieldAt(off) {
  let best = null;
  const walk = (list, path) => list.forEach(x => {
    const key = path + '/' + x.n;
    if (x.s > 0 && off >= x.o && off < x.o + x.s && (!best || x.s <= best.s)) best = {key, o: x.o, s: x.s, n: x.n, path};
    if (x.c) walk(x.c, key);
  });
  walk(st.frame.tree, '');
  return best;
}
function renderTrace() {
  const tl = st.ov.timeline, max = Math.max(1, ...tl.bins.map(b => b.reduce((s, v) => s + v, 0)));
  let s = '';
  tl.bins.forEach((b, i) => {
    let y = 40;
    b.forEach((v, g) => { if (!v) return; const h = v / max * 38; y -= h; s += `<rect x="${i + .08}" y="${y}" width=".84" height="${h}" style="fill:${GROUP_VAR(tl.groups[g])}"/>`; });
  });
  $('#bars').innerHTML = s;
  const dur = Math.max(st.ov.summary.duration, 1e-6);
  $('#marks').innerHTML = st.ov.findings.filter(f => f.time != null && f.frame).map(f => `<button class="mk" style="left:${f.time / dur * 100}%" data-goto="${f.frame}" title="${esc(words(f).tE)}">${glyph(f.severity, 11)}</button>`).join('');
}
function convFilter(c) {
  if (c.tcp_stream != null) return `tcp.stream == ${c.tcp_stream}`;
  if (c.transport === 'udp') return `ip.addr == ${c.a.ip} && ip.addr == ${c.b.ip} && udp.port == ${c.b.port}`;
  if (c.transport === 'arp') return `arp && arp.src.proto_ipv4 in {${c.a.ip}, ${c.b.ip}}`;
  return `ip.addr == ${c.a.ip} && ip.addr == ${c.b.ip}`;
}
function renderPane() {
  const ov = st.ov, p = $('#pane');
  document.querySelectorAll('.tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === st.tab)));
  if (st.tab === 'finds') {
    p.innerHTML = ov.findings.length ? ov.findings.map(f => { const w = words(f); return `<button class="find" data-finding="${ov.findings.indexOf(f)}"><span class="g">${glyph(f.severity, 12)}</span><span class="t">${esc(w.tE)}</span><span class="s">${esc(w.subE)}${f.frame ? ` · trame ${f.frame}` : ''}</span></button>`; }).join('') + `<p class="empty">Un clic filtre la conversation et sélectionne le paquet en cause.</p>` : '<p class="empty">Aucun constat sur cette capture.</p>';
  } else if (st.tab === 'convs') {
    const list = [...ov.convs].sort((a, b) => b.bytes - a.bytes);
    p.innerHTML = `<table class="ctab"><tbody>${list.map(c => `<tr data-conv="${c.id}"><td>${wire(c.group)}</td><td class="ep">${esc(c.a.ip)}${c.a.port ? ':' + c.a.port : ''}<br>${esc(c.b.ip)}${c.b.port ? ':' + c.b.port : ''}</td><td>${esc(c.app)}${c.severity !== 'ok' ? ' ' + glyph(c.severity, 10) : ''}<br><span style="color:var(--ink3)">${esc(c.state || c.transport)}</span></td><td class="num">${nf(c.packets)}<br>${fmtBytes(c.bytes)}</td></tr>`).join('')}</tbody></table>`;
  } else if (st.tab === 'hosts') {
    const list = [...ov.hosts].sort((a, b) => b.bytes - a.bytes);
    p.innerHTML = `<table class="ctab"><tbody>${list.map(h => `<tr data-host="${esc(h.ip)}"><td class="ep">${esc(h.ip)}${h.mac ? '<br><span style="color:var(--ink3)">' + esc(h.mac) + '</span>' : ''}</td><td>${esc(h.role === 'self' ? 'Ce poste' : h.role === 'gateway' ? 'Passerelle' : h.names[0] || '')}<br><span style="color:var(--ink3)">${esc(h.scope)}${h.services.length ? ' · ports ' + h.services.join(', ') : ''}</span></td><td class="num">${nf(h.packets)}<br>${fmtBytes(h.bytes)}</td></tr>`).join('')}</tbody></table>`;
  } else {
    const list = ov.summary.protocols, max = Math.max(...list.map(x => x.frames));
    p.innerHTML = `<table class="ctab"><tbody>${list.map(x => `<tr data-proto="${esc(x.proto)}"><td style="width:42%">${esc(x.proto)}<div class="bar"><i style="width:${x.frames / max * 100}%;--c:var(--ink2)"></i></div></td><td class="num">${nf(x.frames)} paq.</td><td class="num">${fmtBytes(x.bytes)}</td></tr>`).join('')}</tbody></table>`;
  }
}
const PROTO_FILTER = p => ({'TLSv1.3': 'tls', 'TLSv1.2': 'tls', 'TLSv1': 'tls', 'TLSv1.1': 'tls', 'MDNS': 'mdns', 'NBSS': 'nbss', 'SMB2': 'smb2', 'ICMPv6': 'icmpv6'}[p] || p.toLowerCase());

/* ------------------------------------------------------------------ top level */
function renderTop() {
  const s = st.ov.summary;
  $('#fname').textContent = st.fileName;
  $('#fmeta').textContent = `${nf(s.duration, 1)} s · ${nf(s.frames)} paquets · ${nf(st.ov.hosts.length)} adresses · ${fmtBytes(s.bytes)}${st.ov.truncated ? ' · fichier incomplet' : ''}`;
  $('#sample-tag').hidden = !st.sample;
}
function renderMode() {
  document.querySelectorAll('.mode button').forEach(b => b.setAttribute('aria-pressed', String((b.id === 'm-b') === B())));
  $('#story').hidden = !B(); $('#bench').hidden = B();
  if (B()) { renderStory(); renderMap(); }
  else {
    renderPane(); renderTrace();
    if (!st.pages.size) applyFilter(st.filter, true); else { paintRows(); renderTree(); renderHex(); }
  }
}
function load(u8, fileName, sample) {
  try { Engine.open(u8); } catch (e) {
    toast(/pcap/.test(e.message) ? 'Ce fichier n’est pas une capture réseau. Trame lit les fichiers .pcap et .pcapng.' : 'Impossible de lire ce fichier : ' + e.message);
    return false;
  }
  st.ov = Engine.overview(); st.fileName = fileName; st.sample = sample;
  st.convCache.clear(); st.pages.clear(); st.filter = ''; $('#flt').value = ''; st.sel = null; st.seqOpen = false; st.ev = 0;
  st.open = st.ov.findings.length ? 'f0' : null;
  if (st.open) { const f = st.ov.findings[0]; if (f.conv != null) st.ev = eventIndexFor(f.conv, f.frame); }
  renderTop(); renderMode();
  if (!sample) toast(`${fileName} ouvert : ${nf(st.ov.summary.frames)} paquets.`);
  return true;
}
function eventIndexFor(conv, frame) {
  const evs = convData(conv).events; let best = 0;
  evs.forEach((e, i) => { if (e.frame <= frame) best = i; });
  return best;
}
async function openFile(file) {
  if (!file) return;
  if (file.size > 400e6) { toast('Ce fichier dépasse 400 Mo : l’application de bureau sera plus adaptée.'); return; }
  const buf = new Uint8Array(await file.arrayBuffer());
  load(buf, file.name, false);
}

/* ------------------------------------------------------------------ events */
document.addEventListener('click', ev => {
  const t = ev.target.closest('[data-open-k],[data-seq],[data-goto],[data-filter],[data-finding],[data-conv],[data-host],[data-proto],[data-tab],.ev,.hit,.node,.prow,.tn,[data-fa],.hex .b');
  if (!t) return;
  if (t.dataset.fa) {
    const tn = t.closest('.tn'), expr = `${tn.dataset.n} == ${tn.dataset.v}`;
    const f = t.dataset.fa === 'and' && st.filter ? `(${st.filter}) && ${expr}` : expr;
    $('#flt').value = f; applyFilter(f); return;
  }
  if (t.dataset.openK) {
    const k = t.dataset.openK; st.open = st.open === k ? null : k; st.seqOpen = false;
    if (st.open && k[0] === 'f') { const f = st.ov.findings[+k.slice(1)]; st.ev = f.conv != null ? eventIndexFor(f.conv, f.frame) : 0; } else st.ev = 0;
    renderStory(); renderMap(); return;
  }
  if (t.dataset.seq) { st.seqOpen = t.dataset.seq === '1'; renderStory(); return; }
  if (t.classList.contains('ev')) { st.ev = +t.dataset.i; renderStory(); const el = document.querySelector(`.ev[data-i="${st.ev}"]`); if (el) el.focus({preventScroll: true}); return; }
  if (t.dataset.goto) {
    const n = +t.dataset.goto;
    if (B()) { st.mode = 'e'; renderMode(); }
    if (!scrollToFrame(n, true)) { $('#flt').value = ''; applyFilter(''); scrollToFrame(n, true); }
    return;
  }
  if (t.classList.contains('hit')) {
    const ids = t.dataset.convs.split(',').map(Number);
    const fi = st.ov.findings.findIndex(f => ids.includes(f.conv));
    st.open = fi >= 0 ? 'f' + fi : 'c' + ids[0]; st.seqOpen = false; st.ev = fi >= 0 ? eventIndexFor(st.ov.findings[fi].conv, st.ov.findings[fi].frame) : 0;
    renderStory(); renderMap();
    const it = document.getElementById('it-' + st.open); if (it) it.scrollIntoView({behavior: 'smooth', block: 'center'});
    return;
  }
  if (t.classList.contains('node')) { if (!B()) { const f = `ip.addr == ${t.dataset.ip}`; $('#flt').value = f; applyFilter(f); } return; }
  if (t.dataset.filter) { $('#flt').value = t.dataset.filter; applyFilter(t.dataset.filter); return; }
  if (t.dataset.tab) { st.tab = t.dataset.tab; renderPane(); return; }
  if (t.dataset.finding) {
    const f = st.ov.findings[+t.dataset.finding];
    const c = f.conv != null ? st.ov.convs[f.conv] : null;
    const filt = f.kind === 'tcp_refused' ? `ip.addr == ${f.params.host} && tcp.port == ${f.params.port}` : c ? convFilter(c) : '';
    $('#flt').value = filt; applyFilter(filt, false); if (f.frame) scrollToFrame(f.frame, true); return;
  }
  if (t.dataset.conv) { const f = convFilter(st.ov.convs[+t.dataset.conv]); $('#flt').value = f; applyFilter(f, false); return; }
  if (t.dataset.host) { const f = `ip.addr == ${t.dataset.host}`; $('#flt').value = f; applyFilter(f, false); return; }
  if (t.dataset.proto) { const f = PROTO_FILTER(t.dataset.proto); $('#flt').value = f; applyFilter(f, false); return; }
  if (t.classList.contains('prow')) { selectFrame(+t.dataset.n); $('#plist').focus({preventScroll: true}); return; }
  if (t.classList.contains('tn')) {
    const key = t.dataset.key, n = t.dataset.n;
    if (ev.target.closest('.tg') || (st.field && st.field.key === key)) { st.expanded.has(n) ? st.expanded.delete(n) : st.expanded.add(n); }
    st.field = {key, o: +t.dataset.o, s: +t.dataset.s, n};
    renderTree(); renderHex(); return;
  }
  if (t.classList.contains('b')) {
    const f = fieldAt(+t.dataset.i); if (!f) return;
    f.path.split('/').filter(Boolean).forEach(n => st.expanded.add(n));
    st.field = f; renderTree(); renderHex();
    const el = document.querySelector('.tn.on'); if (el) el.scrollIntoView({block: 'nearest'});
  }
});
document.addEventListener('keydown', ev => {
  const t = ev.target;
  if ((ev.key === 'Enter' || ev.key === ' ') && t.classList && t.classList.contains('ev')) { ev.preventDefault(); t.dispatchEvent(new MouseEvent('click', {bubbles: true})); return; }
  if (t.id === 'flt') { if (ev.key === 'Enter') applyFilter(t.value); return; }
  if (B() || !st.sel || t.tagName === 'INPUT') return;
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
    const i = Engine.indexOf(st.filter, st.sel); if (i == null) return;
    const j = Math.max(0, Math.min(st.matched - 1, i + (ev.key === 'ArrowDown' ? 1 : -1)));
    const r = rowAt(j); if (r) { scrollToFrame(r.n, false); ev.preventDefault(); }
  }
});
$('#flt').addEventListener('input', e => {
  const v = e.target.value, err = v.trim() ? Engine.check(v) : null;
  $('#fin').className = 'fin' + (v.trim() ? (err ? ' bad' : ' ok') : '');
});
$('#flt-go').addEventListener('click', () => applyFilter($('#flt').value));
$('#plist').addEventListener('scroll', () => requestAnimationFrame(paintRows));
window.addEventListener('resize', () => { if (!B()) paintRows(); });
$('#plot').addEventListener('click', e => {
  if (e.target.closest('.mk')) return;
  const r = $('#plot').getBoundingClientRect(), bin = Math.floor((e.clientX - r.left) / r.width * st.ov.timeline.bins.length);
  let n = 1; for (let i = 0; i < bin; i++) n += st.ov.timeline.bins[i].reduce((s, v) => s + v, 0);
  if (st.filter) { $('#flt').value = ''; applyFilter(''); }
  scrollToFrame(Math.min(n, st.ov.summary.frames), true);
});
['m-b', 'm-e'].forEach(id => $('#' + id).addEventListener('click', () => {
  st.mode = id === 'm-b' ? 'b' : 'e';
  try { localStorage.setItem('trame-mode', st.mode); } catch (e) {}
  renderMode();
}));
$('#file-in').addEventListener('change', e => { openFile(e.target.files[0]); e.target.value = ''; });
let dragDepth = 0;
document.addEventListener('dragenter', e => { if ([...e.dataTransfer.types].includes('Files')) { dragDepth++; $('#drop').hidden = false; e.preventDefault(); } });
document.addEventListener('dragover', e => { if ([...e.dataTransfer.types].includes('Files')) e.preventDefault(); });
document.addEventListener('dragleave', () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) $('#drop').hidden = true; });
document.addEventListener('drop', e => { e.preventDefault(); dragDepth = 0; $('#drop').hidden = true; openFile(e.dataTransfer.files[0]); });

/* ------------------------------------------------------------------ boot */
(async () => {
  quickChips();
  try {
    await Engine.init();
    let sample;
    if (window.TRAME_SAMPLE_B64) sample = Uint8Array.from(atob(window.TRAME_SAMPLE_B64), c => c.charCodeAt(0));
    else sample = new Uint8Array(await (await fetch('sample.pcapng')).arrayBuffer());
    load(sample, 'bureau-lundi.pcapng', true);
  } catch (e) {
    $('#fname').textContent = 'Le moteur n’a pas pu démarrer';
    $('#story-head').innerHTML = `<h1>Le moteur n’a pas pu démarrer.</h1><p class="lede">${esc(e.message)}</p>`;
  }
})();
})();
