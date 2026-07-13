**FREE
//==============================================================
// Programme de sortie : QZSOSGNR
// Point de sortie      : QIBM_QZSO_SIGNONSRV
// Format               : ZSOY0100
//
// STRUCTURE INTEGRALEMENT CONFIRMEE le 2026-07-14 directement
// depuis la table IBM (collée par l'utilisateur) - remplace la
// version précédente qui ne confirmait que l'en-tête (offsets
// 0-19) et laissait le reste en hypothèse.
//
// La structure complète ne fait que 32 OCTETS - elle s'arrête au
// champ "Requested function" (offset 28, 4 octets). Il n'y a PAS
// de champ IP client ni de champ mot de passe dans cette
// structure, contrairement à ce qu'on pourrait attendre d'un
// serveur d'authentification - le contrôle doit donc se faire
// uniquement sur le profil utilisateur et le type de requête.
//
// Ce point de sortie est appelé par le Signon Server (job
// QZSOSIGN, application '*SIGNON') pour : démarrage de serveur,
// récupération d'informations de connexion, changement de mot de
// passe, génération de jeton d'authentification (pour soi-même ou
// pour un autre utilisateur).
//
// Par analogie confirmée avec les autres serveurs hôtes (structure
// fixe, pas de champ CHAR(*) en fin), il reçoit vraisemblablement
// 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée, probablement PAR VALEUR
//      comme ZDAI0100/ZDAD0100/ZDAR0100/ZHQ00100) - CHAR(32)
//      format ZSOY0100
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Signon server", collée directement par l'utilisateur le
// 2026-07-14).
//
// A CONFIRMER malgré tout :
//  - le mode de passage exact du paramètre 2 (par valeur ou
//    référence) ;
//  - la valeur du code retour pour autoriser/refuser (supposée
//    '1'/'0' par analogie avec les autres serveurs hôtes
//    confirmés).
// Teste en environnement non productif avant mise en service.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec les autres serveurs hôtes confirmés - à revalider pour
// QZSO_SIGNONSRV spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);         // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(32) value;  // Entrée : structure ZSOY0100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ZSOY0100 (intégralement confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile        char(10); // offset 0  - Profil utilisateur associé à la requête
  ServerId           char(10); // offset 10 - Toujours '*SIGNON'
  FormatName         char(8);  // offset 20 - Toujours 'ZSOY0100'
  RequestedFunction  int(10);  // offset 28 - Fonction demandée :
                                //   X'7002' Démarrage de serveur
                                //   X'7004' Récupération d'infos de connexion
                                //   X'7005' Changement de mot de passe
                                //   X'7007' Génération de jeton d'authentification
                                //   X'7008' Génération de jeton pour un autre utilisateur
end-ds;                        // taille totale = 32 octets

dcl-s p_ExitDataPtr pointer inz;

dcl-c SIGNON_START_SRV   28674; // X'7002'
dcl-c SIGNON_RETRIEVE    28676; // X'7004'
dcl-c SIGNON_CHGPWD      28677; // X'7005'
dcl-c SIGNON_GENTOKEN    28679; // X'7007'
dcl-c SIGNON_GENTOKEN_ON 28680; // X'7008' - jeton généré pour un AUTRE utilisateur

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de la tentative d'authentification (audit)
exsr LogAttempt;

// 2) Contrôle de l'authentification - politique de sécurité à définir
exsr CheckSignon;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la tentative d'authentification
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        date/heure système dans un fichier d'audit dédié (ex:
  //        WRITE sur un fichier LOGSGNP), ou tracer via QAUDJRN /
  //        DTAARA selon le besoin. Comme cette structure ne fournit
  //        PAS l'IP client, une détection de brute force devra
  //        s'appuyer uniquement sur le profil utilisateur et la
  //        fréquence des appels.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'authentification
//==============================================================
begsr CheckSignon;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;

  // Exemple : interdire la génération de jeton pour le compte
  // d'un AUTRE utilisateur (fonctionnalité sensible)
  // if ExitData_t.RequestedFunction = SIGNON_GENTOKEN_ON;
  //   Allowed = *off;
  // endif;

  // Exemple : interdire le changement de mot de passe via ce canal
  // if ExitData_t.RequestedFunction = SIGNON_CHGPWD;
  //   Allowed = *off;
  // endif;
endsr;
