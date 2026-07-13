**FREE
//==============================================================
// Programme de sortie : QNPSSPLF
// Point de sortie      : QIBM_QNPS_SPLF
// Format               : SPLF0100
//
// STRUCTURE RE-CONFIRMEE le 2026-07-14 directement depuis la
// table IBM (collée par l'utilisateur) - CORRIGE UN BUG réel de
// la version du 2026-07-10 : la constante SPLF_APPDATA_OFFSET
// valait 44 au lieu de 76 (et n'était même pas utilisée dans le
// code). Tous les autres offsets/types étaient déjà exacts.
//
// Ce point de sortie est appelé pour TRAITER un fichier spoule
// existant via le Network Print Server (ex : envoi vers un
// service de fax réseau). Voir aussi QNPSENTR.rpgle (contrôle
// d'accès au serveur lui-même, point de sortie distinct).
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Network print server", collée directement par
// l'utilisateur le 2026-07-14).
//
// A CONFIRMER : le mode de passage exact des paramètres (par
// analogie avec les autres serveurs hôtes confirmés, la
// convention à 2 paramètres [code retour + structure] est très
// probable mais pas vérifiée individuellement pour ce point de
// sortie précis - la présence d'un champ CHAR(*) de taille
// variable en fin de structure suggère plutôt un passage PAR
// REFERENCE que par valeur, contrairement à ENTR0100 qui est de
// taille fixe).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec les autres serveurs hôtes confirmés)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);                              // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(65535) const options(*varsize);   // Entrée : structure SPLF0100
end-pi;

//--------------------------------------------------------------
// Gabarit de la partie fixe du format SPLF0100 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile     char(10);  // Profil utilisateur appelant le serveur
  ServerId        char(10);  // Toujours 'QNPSERVR'
  FormatName      char(8);   // Toujours 'SPLF0100'
  FunctionId      int(10);   // Toujours X'010D'
  JobName         char(10);  // Nom du travail ayant créé le fichier spoule
  UserName        char(10);  // Profil utilisateur du travail d'origine
  JobNumber       char(6);   // Numéro du travail d'origine
  SplfName        char(10);  // Nom du fichier spoule demandé
  SplfNumber      int(10);   // Numéro du fichier spoule demandé
  ExitPgmDataLen  int(10);   // Longueur des données applicatives qui suivent
end-ds;                      // Les données applicatives suivent immédiatement

dcl-s p_ExitDataPtr pointer inz;
dcl-s p_AppDataPtr  pointer inz;
dcl-s AppData       char(65535) based(p_AppDataPtr); // tronqué au-delà - limite RPG CHAR fixe

dcl-c SPLF_APPDATA_OFFSET 76; // offset des données applicatives (confirmé, corrigé le 2026-07-14 - était 44)

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);
p_AppDataPtr  = p_ExitDataPtr + SPLF_APPDATA_OFFSET;

// 1) Journalisation du traitement du fichier spoule (audit)
exsr LogAttempt;

// 2) Contrôle du traitement demandé - politique de sécurité à définir
exsr CheckSplfAccess;

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
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.JobName,
  //        ExitData_t.SplfName, ExitData_t.SplfNumber,
  //        %subst(AppData:1:%min(ExitData_t.ExitPgmDataLen:65535)),
  //        date/heure système dans un fichier d'audit dédié (ex:
  //        WRITE sur un fichier LOGSPLP), ou tracer via QAUDJRN /
  //        DTAARA selon le besoin. AppData contient les données
  //        fournies par l'application cliente (ex : numéro de fax
  //        pour un exit program de fax réseau) - ne le déréférencer
  //        que si ExitData_t.ExitPgmDataLen > 0.
endsr;

//==============================================================
// Sous-routine : contrôle du traitement du fichier spoule
//==============================================================
begsr CheckSplfAccess;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer le traitement des fichiers spoule d'un
  // travail précis
  // if %trim(ExitData_t.JobName) = 'PAYROLL';
  //   Allowed = *off;
  // endif;
endsr;
