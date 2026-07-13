**FREE
//==============================================================
// Programme de sortie : QTMFREQ
// Point de sortie      : QIBM_QTMF_SERVER_REQ
// Format               : VLRQ0100
//
// STRUCTURE CONFIRMEE par recherche documentaire (2026-07-10) -
// remplace une première version entièrement spéculative.
// PARTICULARITE IMPORTANTE : ce format VLRQ0100 est PARTAGE par
// QUATRE points de sortie TCP/IP : QIBM_QTMF_CLIENT_REQ (client
// FTP), QIBM_QTMF_SERVER_REQ (serveur FTP, ce fichier),
// QIBM_QTMX_SERVER_REQ (serveur REXEC, voir QTMXREQ.rpgle) et
// QIBM_QTOD_SERVER_REQ (serveur TFTP). Le paramètre 1
// (identifiant d'application) indique lequel appelle.
//
// Ce point de sortie est appelé pour CHAQUE commande FTP exécutée
// après connexion (RETR, STOR, DELE, RNFR/RNTO, MKD, RMD, LIST,
// CWD...).
//
// Source : recoupement de plusieurs documents IBM (manuel
// SC41-5420-04 "TCP/IP Configuration and Reference", annexe B).
//
// A CONFIRMER : la table complète des valeurs possibles du champ
// "Identifiant d'opération" (une par commande FTP) et le détail
// exact du contenu de "Informations spécifiques à l'opération".
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (8 paramètres CONFIRMES)
//--------------------------------------------------------------
dcl-pi *n;
  p_AppId          int(10)     const;                   // E : 0=client FTP, 1=serveur FTP, 2=serveur REXEC, 3=serveur TFTP
  p_OperationId    int(10)     const;                   // E : commande demandée (RETR/STOR/DELE/...)
  p_UserProfile    char(10)    const;                   // E : profil utilisateur de la session
  p_RemoteIPAddr   char(65535) const options(*varsize); // E : adresse IP distante
  p_RemoteIPAddrLen int(10)    const;                   // E : longueur de p_RemoteIPAddr
  p_OpInfo         char(65535) const options(*varsize); // E : informations spécifiques à l'opération (ex: chemin visé)
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

// 1) Journalisation de la commande FTP (audit)
exsr LogAttempt;

// 2) Contrôle de la commande - politique de sécurité à définir
exsr CheckFtpRequest;

// 3) Positionnement du code retour
if Allowed;
  p_AllowOperation = 1;
else;
  p_AllowOperation = 0;
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la commande FTP
//==============================================================
begsr LogAttempt;
  // TODO : écrire p_UserProfile, p_OperationId,
  //        %subst(p_RemoteIPAddr:1:%min(p_RemoteIPAddrLen:65535)),
  //        %subst(p_OpInfo:1:%min(p_OpInfoLen:65535)), date/heure
  //        système dans un fichier d'audit dédié (ex: WRITE sur
  //        un fichier LOGFTRQ), ou tracer via QAUDJRN / DTAARA
  //        selon le besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur la commande FTP
//==============================================================
begsr CheckFtpRequest;
  Allowed = *on;

  // Exemple : bloquer l'accès en dehors d'un répertoire autorisé
  // if %scan('/PAYROLL/':%subst(p_OpInfo:1:%min(p_OpInfoLen:65535))) > 0;
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur toute commande FTP
  // if p_UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
