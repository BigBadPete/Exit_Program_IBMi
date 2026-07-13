**FREE
//==============================================================
// Programme de sortie : QZRCRMT
// Point de sortie      : QIBM_QZRC_RMT
// Format               : CZRC0100
//
// STRUCTURE RE-CONFIRMEE le 2026-07-13 directement depuis la
// table IBM (collée par l'utilisateur) - CORRIGE une ERREUR
// STRUCTURELLE de la version du 2026-07-10 : ce point de sortie
// gère en fait DEUX types de requêtes bien distincts qui partagent
// le même nom de format CZRC0100 mais PAS la même structure au-
// delà de l'offset 32 (RequestedFunction) :
//   - X'1002' = commande à distance (RMTCMD)      -> texte de commande
//   - X'1003' = appel de programme distribué (DPC) -> nom de
//     programme/bibliothèque + liste de paramètres
// La version précédente fusionnait à tort les deux (champs
// PgmName/LibName d'un côté, CmdData de l'autre, dans une seule
// structure toujours présente) - c'était inexact.
//
// Ce point de sortie est appelé par le serveur de commande à
// distance / appel de programme distribué (job QZRCSRVS,
// application '*RMTSRV').
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Identify the IBM i exit point for the remote command and
// the distributed program call server", collée directement par
// l'utilisateur le 2026-07-13).
//
// A CONFIRMER malgré tout :
//  - le mode de passage exact du paramètre 2 (par référence
//    supposé ici, vu la présence de champs CHAR(*) de taille
//    variable - contrairement à ZDAI0100/ZDAD0100/ZDAR0100 qui
//    sont de taille fixe) ;
//  - la valeur exacte du code retour pour autoriser/refuser
//    (supposée '1'/'0' par analogie avec les autres serveurs
//    hôtes confirmés) ;
//  - le détail fin du parcours de la liste de paramètres pour le
//    cas "appel de programme distribué" (structure répétitive
//    non entièrement implémentée ici, cf. sous-routine dédiée).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec les autres serveurs hôtes confirmés - à revalider pour
// QZRC_RMT spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);                              // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(65535) const options(*varsize);   // Entrée : structure CZRC0100 (RMTCMD ou DPC)
end-pi;

//--------------------------------------------------------------
// En-tête commun aux deux types de requête (offsets 0-31, confirmé)
//--------------------------------------------------------------
dcl-ds CommonHdr_t qualified based(p_ExitDataPtr);
  UserProfile       char(10);  // offset 0  - Profil utilisateur appelant le serveur
  ServerId          char(10);  // offset 10 - Toujours '*RMTSRV'
  FormatName        char(8);   // offset 20 - Toujours 'CZRC0100'
  RequestedFunction int(10);   // offset 28 - X'1002'=RMTCMD (4098), X'1003'=DPC (4099)
end-ds;

//--------------------------------------------------------------
// Variante "commande à distance" (RequestedFunction = X'1002')
//--------------------------------------------------------------
dcl-ds RmtCmd_t qualified based(p_ExitDataPtr);
  *n            char(32);   // en-tête commun (voir CommonHdr_t)
  CmdCcsid      int(10);    // offset 32 - CCSID : 0=CCSID du job, 1200=UTF-16, 1208=UTF-8
  Reserved      char(16);   // offset 36 - non utilisé pour ce type de requête
  CmdStringLen  int(10);    // offset 52 - longueur du texte de commande qui suit
end-ds;                     // CmdString CHAR(*) suit immédiatement à l'offset 56

//--------------------------------------------------------------
// Variante "appel de programme distribué" (RequestedFunction = X'1003')
//--------------------------------------------------------------
dcl-ds Dpc_t qualified based(p_ExitDataPtr);
  *n         char(32);  // en-tête commun (voir CommonHdr_t)
  PgmName    char(10);  // offset 32 - Nom du programme appelé
  LibName    char(10);  // offset 42 - Bibliothèque du programme
  NumParms   int(10);   // offset 52 - Nombre total de paramètres de l'appel
end-ds;                 // Informations sur les paramètres CHAR(*) à l'offset 56 :
                         // pour chaque paramètre (structure répétée) :
                         //   BINARY(4) longueur des données de ce paramètre
                         //   BINARY(4) longueur maximale du paramètre
                         //   BINARY(2) type d'usage (1=entrée, 2=sortie, 3=entrée/sortie)
                         //   CHAR(*)   valeur du paramètre (si entrée ou entrée/sortie)

dcl-s p_ExitDataPtr pointer inz;
dcl-s p_CmdPtr      pointer inz;
dcl-s CmdString     char(65535) based(p_CmdPtr); // tronqué au-delà - limite RPG CHAR fixe

dcl-c RMTCMD_FUNC 4098; // X'1002'
dcl-c DPC_FUNC    4099; // X'1003'

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de la requête (audit)
exsr LogAttempt;

// 2) Contrôle - politique de sécurité à définir, distincte selon
//    le type de requête
select;
  when CommonHdr_t.RequestedFunction = RMTCMD_FUNC;
    p_CmdPtr = p_ExitDataPtr + 56;
    exsr CheckRemoteCommand;
  when CommonHdr_t.RequestedFunction = DPC_FUNC;
    exsr CheckDistributedPgmCall;
  other;
    Allowed = *on; // type de requête inconnu - à traiter explicitement
                   // selon la politique de sécurité (rejeter par défaut
                   // est souvent plus prudent pour un type non prévu)
endsl;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête
//==============================================================
begsr LogAttempt;
  // TODO : écrire CommonHdr_t.UserProfile, CommonHdr_t.RequestedFunction,
  //        date/heure système dans un fichier d'audit dédié (ex:
  //        WRITE sur un fichier LOGRMTP), ou tracer via QAUDJRN /
  //        DTAARA selon le besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur une commande à distance
//==============================================================
begsr CheckRemoteCommand;
  Allowed = *on;

  // Exemple : bloquer les commandes de création de profil
  // if %scan('CRTUSRPRF':%subst(CmdString:1:%min(RmtCmd_t.CmdStringLen:65535))) > 0;
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur toute commande distante
  // if CommonHdr_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur un appel de programme distribué
//==============================================================
begsr CheckDistributedPgmCall;
  Allowed = *on;

  // Exemple : bloquer l'appel de programmes dans une bibliothèque
  // sensible
  // if %trim(Dpc_t.LibName) = 'PAYROLL';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer l'appel d'un programme précis
  // if %trim(Dpc_t.PgmName) = 'DELETEALL';
  //   Allowed = *off;
  // endif;

  // TODO : pour inspecter la VALEUR des paramètres passés (pas
  // seulement le nom du programme/bibliothèque), il faut parcourir
  // la zone "Informations sur les paramètres" à partir de l'offset
  // 56, en lisant pour chacun des Dpc_t.NumParms paramètres la
  // structure répétitive décrite ci-dessus (longueur, longueur
  // max, type d'usage, puis la donnée elle-même) - non implémenté
  // dans ce squelette simple.
endsr;
