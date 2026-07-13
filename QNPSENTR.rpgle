**FREE
//==============================================================
// Programme de sortie : QNPSENTR
// Point de sortie      : QIBM_QNPS_ENTRY
// Format               : ENTR0100
//
// STRUCTURE RE-CONFIRMEE le 2026-07-13 directement depuis la
// table IBM (collée par l'utilisateur) - s'avère EXACTE, aucune
// correction nécessaire par rapport à la version du 2026-07-10.
// CORRECTION IMPORTANTE (toujours valide) : le point de sortie
// "QIBM_QNPSERVR" utilisé dans une toute première version
// n'existe pas tel quel - il s'agit en réalité de DEUX points de
// sortie distincts pour le Network Print Server (identifiant
// serveur interne QNPSERVR) :
//   - QIBM_QNPS_ENTRY (ce fichier) : contrôle l'accès au serveur
//     lui-même, appelé à l'initiation du serveur.
//   - QIBM_QNPS_SPLF (voir QNPSSPLF.rpgle) : contrôle le
//     traitement d'un fichier spoule existant (ex : fax).
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Network print server", collée directement par
// l'utilisateur le 2026-07-13).
//
// A CONFIRMER : le mode de passage exact des paramètres (par
// analogie avec les autres serveurs hôtes confirmés - QZDA_INIT,
// QZSO_SIGNONSRV - la convention à 2 paramètres [code retour +
// structure] est très probable mais pas vérifiée individuellement
// pour ce point de sortie précis).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec les autres serveurs hôtes confirmés)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);          // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(32) value;   // Entrée : structure ENTR0100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ENTR0100 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile         char(10); // Profil utilisateur appelant le serveur
  ServerId             char(10);// Toujours 'QNPSERVR'
  FormatName             char(8);// Toujours 'ENTR0100'
  FunctionId            int(10); // Toujours X'0802'
end-ds;

dcl-s p_ExitDataPtr pointer inz;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de l'accès au serveur d'impression (audit)
exsr LogAttempt;

// 2) Contrôle d'accès - politique de sécurité à définir
exsr CheckAccess;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, date/heure système
  //        dans un fichier d'audit dédié (ex: WRITE sur un
  //        fichier LOGNPSP), ou tracer via QAUDJRN / DTAARA
  //        selon le besoin.
endsr;

//==============================================================
// Sous-routine : contrôle d'accès
//==============================================================
begsr CheckAccess;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
