**FREE
//==============================================================
// Programme de sortie : QTMXREQ
// Point de sortie      : QIBM_QTMX_SERVER_REQ
// Format               : VLRQ0100
//
// IDENTIFICATION DESORMAIS CONFIRMEE (2026-07-10) : la première
// version de ce fichier n'était qu'une hypothèse ("QTMX =
// REXEC probablement"). C'est maintenant confirmé par
// recoupement documentaire : QIBM_QTMX_SERVER_REQ est bien le
// point de sortie de validation des requêtes du serveur REXEC
// (exécution de commande à distance, protocole REXEC, port 512).
//
// PARTICULARITE IMPORTANTE : ce format VLRQ0100 est PARTAGE par
// QUATRE points de sortie TCP/IP : QIBM_QTMF_CLIENT_REQ,
// QIBM_QTMF_SERVER_REQ (voir QTMFREQ.rpgle), QIBM_QTMX_SERVER_REQ
// (ce fichier) et QIBM_QTOD_SERVER_REQ (TFTP). Le paramètre 1
// (identifiant d'application) vaut 2 pour le serveur REXEC.
//
// Source : recoupement de plusieurs documents IBM (manuel
// SC41-5420-04 "TCP/IP Configuration and Reference", annexe B).
//
// A CONFIRMER : le détail exact du contenu du champ "Informations
// spécifiques à l'opération" pour REXEC (attendu : la commande à
// exécuter, à valider précisément).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (8 paramètres CONFIRMES,
// identiques à QIBM_QTMF_SERVER_REQ - format VLRQ0100 partagé)
//--------------------------------------------------------------
dcl-pi *n;
  p_AppId          int(10)     const;                   // E : 2 = serveur REXEC pour ce point de sortie
  p_OperationId    int(10)     const;                   // E : opération demandée
  p_UserProfile    char(10)    const;                   // E : profil utilisateur de la session
  p_RemoteIPAddr   char(65535) const options(*varsize); // E : adresse IP distante
  p_RemoteIPAddrLen int(10)    const;                   // E : longueur de p_RemoteIPAddr
  p_OpInfo         char(65535) const options(*varsize); // E : informations spécifiques (commande à exécuter attendue)
  p_OpInfoLen      int(10)     const;                   // E : longueur de p_OpInfo
  p_AllowOperation int(10);                              // S : indicateur d'autorisation
end-pi;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================

// 1) Journalisation de la requête REXEC (audit)
exsr LogAttempt;

// 2) Contrôle de la requête - politique de sécurité à définir
exsr CheckRexecRequest;

// 3) Positionnement du code retour
if Allowed;
  p_AllowOperation = 1;
else;
  p_AllowOperation = 0;
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête REXEC
//==============================================================
begsr LogAttempt;
  // TODO : écrire p_UserProfile, p_OperationId,
  //        %subst(p_RemoteIPAddr:1:%min(p_RemoteIPAddrLen:65535)),
  //        %subst(p_OpInfo:1:%min(p_OpInfoLen:65535)), date/heure
  //        système dans un fichier d'audit dédié (ex: WRITE sur
  //        un fichier LOGTMXP), ou tracer via QAUDJRN / DTAARA
  //        selon le besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur la requête REXEC
//==============================================================
begsr CheckRexecRequest;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if p_UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer certaines commandes sensibles (une fois le
  // contenu exact de p_OpInfo confirmé)
  // if %scan('CRTUSRPRF':%subst(p_OpInfo:1:%min(p_OpInfoLen:65535))) > 0;
  //   Allowed = *off;
  // endif;
endsr;
