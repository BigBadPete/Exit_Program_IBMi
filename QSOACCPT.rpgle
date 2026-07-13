**FREE
//==============================================================
// Programme de sortie : QSOACCPT
// Point de sortie      : QIBM_QSO_ACCEPT
// Format               : ACPT0100
//
// STRUCTURE INTEGRALEMENT CONFIRMEE le 2026-07-14 directement
// depuis la doc IBM "Sockets accept() API Exit Program" (collée
// par l'utilisateur) - REMPLACE ENTIEREMENT la version précédente
// qui utilisait un schéma à 4 paramètres + message *ESCAPE
// totalement erroné.
//
// ATTENTION CRITIQUE - CONVENTION DE CODE RETOUR INVERSEE :
// contrairement à TOUS les autres fichiers de ce répertoire où
// '1' = autoriser, ICI c'est L'INVERSE :
//   '0' = autoriser la connexion
//   '1' = refuser la connexion
//   '9' = autoriser ET ne plus jamais rappeler ce programme de
//         sortie pour le reste de la durée de vie du PROCESSUS
//   toute autre valeur = refuser (comportement par défaut sûr)
// Une confusion avec la convention des autres fichiers (croire
// que '1' autorise) inverserait complètement la politique de
// sécurité - vérifie ce point AVANT toute réutilisation de code
// entre fichiers de ce répertoire.
//
// QSYSINC : structure définie par le membre ESOEXTPT.
//
// Ce point de sortie appartient au REGISTRE UTILISATEUR (pas
// WRKREGINF comme les serveurs hôtes) - ajout/suppression exige
// les autorités *IOSYSCFG + *ALLOBJ + *SECADM. Il se déclenche
// pour TOUTE connexion TCP entrante acceptée sur la machine, pour
// les applications qui utilisent effectivement les API sockets
// (couverture non universelle - cf. avertissement plus bas).
//
// Par défaut, une connexion rejetée est ignorée SILENCIEUSEMENT
// par l'application appelante (accept() attend juste la connexion
// suivante). Pour que l'application appelante voie une erreur,
// elle doit avoir activé l'option socket SO_ACCEPTEPERM - dans ce
// cas, accept()/accept_and_recv()/QsoStartAccept() échouent avec
// EPERM. Ce comportement dépend de l'application cliente, pas de
// ce programme de sortie.
//
// CAVEAT : toutes les applications IBM n'appellent pas ce point
// de sortie (API sockets non utilisée, ou appel venant d'une
// tâche système incapable d'invoquer un programme de sortie
// utilisateur) - ne pas supposer une couverture exhaustive de
// tout le trafic TCP entrant de la machine.
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Sockets accept() API Exit Program", collée directement par
// l'utilisateur le 2026-07-14).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres CONFIRMES -
// attention à l'ORDRE, différent des autres fichiers : les
// données d'abord, le code retour ensuite)
//--------------------------------------------------------------
dcl-pi *n;
  p_ExitData    char(96) const options(*varsize);  // E : structure ACPT0100 (infos de connexion)
  p_RtnIndicator char(1);                           // S : '0'=autoriser, '1'=refuser, '9'=autoriser+ne
                                                     //     plus rappeler pour ce processus
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ACPT0100 (confirmé). Les 3 zones
// d'adresse contiennent des structures sockaddr brutes (sockaddr_in
// pour IPv4 ou sockaddr_in6 pour IPv6, selon la famille encodée
// dans les 2 premiers octets de chaque zone) - PAS des adresses IP
// déjà décodées en texte. Leur décodage précis (famille, port en
// network byte order, octets d'adresse) nécessite de connaître le
// layout exact de sockaddr_in/sockaddr_in6 - se référer à
// l'exemple de programme fourni par IBM plutôt que d'improviser un
// décodage, une erreur ici pourrait faire mal identifier l'IP
// distante sur un contrôle de sécurité.
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  LocalBoundAddrLen     int(10);   // offset 0  - longueur utile de LocalBoundAddr
  LocalBoundAddr        char(28);  // offset 4  - adresse locale sur laquelle le
                                    // socket est lié (bind) - structure sockaddr brute
  LocalIncomingAddrLen  int(10);   // offset 32 - longueur utile de LocalIncomingAddr
  LocalIncomingAddr     char(28);  // offset 36 - adresse locale réelle de CETTE
                                    // connexion (peut différer de LocalBoundAddr si
                                    // le bind était sur une adresse générique/*ANY)
  RemoteAddrLen         int(10);   // offset 64 - longueur utile de RemoteAddr
  RemoteAddr            char(28);  // offset 68 - adresse du client distant -
                                    // structure sockaddr brute
end-ds;                            // taille totale = 96 octets

dcl-s p_ExitDataPtr pointer inz;

dcl-c ACCEPT_ALLOW        '0';
dcl-c ACCEPT_REJECT       '1';
dcl-c ACCEPT_ALLOW_NOMORE '9'; // autoriser + ne plus jamais rappeler pour ce processus

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de la connexion acceptée (audit) - à limiter
//    ou filtrer si le volume est trop important en production
exsr LogAttempt;

// 2) Contrôle de la connexion - politique de sécurité à définir.
//    IMPORTANT : ce point de sortie se déclenche pour TOUTE
//    connexion TCP entrante (tous ports/applications confondus) -
//    limiter explicitement l'action aux cas réellement concernés.
exsr CheckSocketAccept;

// 3) Positionnement du code retour - ATTENTION, CONVENTION
//    INVERSEE par rapport aux autres fichiers (voir avertissement
//    en en-tête) : '0' = autoriser ICI, pas '1'.
if Allowed;
  p_RtnIndicator = ACCEPT_ALLOW;
else;
  p_RtnIndicator = ACCEPT_REJECT;
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la connexion acceptée
//==============================================================
begsr LogAttempt;
  // TODO : décoder ExitData_t.RemoteAddr (structure sockaddr brute)
  //        pour en extraire l'IP/le port du client, puis écrire
  //        cette information avec la date/heure système dans un
  //        fichier d'audit dédié (ex: WRITE sur un fichier
  //        LOGSOAP), ou tracer via QAUDJRN / DTAARA selon le
  //        besoin. Prévoir un filtrage (ex: uniquement certains
  //        ports locaux, à extraire de LocalIncomingAddr) pour
  //        éviter un volume excessif vu que ce point de sortie se
  //        déclenche pour toute connexion TCP entrante.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur la connexion socket
//==============================================================
begsr CheckSocketAccept;
  Allowed = *on;

  // TODO : décoder le port local depuis ExitData_t.LocalIncomingAddr
  // pour restreindre la politique à un service précis (ex : ne
  // filtrer que le port 23/Telnet et laisser passer le reste sans
  // traitement) - indispensable pour ne pas impacter tous les
  // services TCP de la machine par erreur.

  // TODO : décoder l'IP distante depuis ExitData_t.RemoteAddr pour
  // appliquer une restriction par plage d'adresses.

  // Note : ACCEPT_ALLOW_NOMORE ('9') n'est pas géré par le flux
  // ci-dessus (qui ne connaît que Allowed = *on/*off). Si un cas
  // d'usage précis nécessite de ne plus être rappelé pour le reste
  // du processus (ex : validation faite une seule fois au premier
  // accept()), positionner directement p_RtnIndicator dans le
  // corps principal après cette sous-routine plutôt que via
  // l'indicateur Allowed, et sortir explicitement du flux normal.
endsr;
