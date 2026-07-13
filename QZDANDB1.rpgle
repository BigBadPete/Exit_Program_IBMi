**FREE
//==============================================================
// Programme de sortie : QZDANDB1
// Point de sortie      : QIBM_QZDA_NDB1
// Format               : ZDAD0100
//
// STRUCTURE RE-CONFIRMEE le 2026-07-13 directement depuis la
// table IBM (collée par l'utilisateur) - tous les offsets et
// types de la version du 2026-07-10 (issue de setgetweb.com)
// s'avèrent EXACTS, aucune correction structurelle nécessaire.
// Seule la liste des codes d'opération est précisée ci-dessous.
//
// Ce point de sortie est appelé pour CHAQUE requête de base de
// données "native" (accès niveau enregistrement, hors SQL) faite
// via le serveur hôte de base de données. Par analogie confirmée
// avec QIBM_QZDA_INIT (même famille EZDAEP/QSYSINC), il reçoit
// vraisemblablement 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée) - CHAR(358) format ZDAD0100
//
// Sources :
//  - https://www.ibm.com/docs/en/i/7.5.0?topic=eppf-parameter-fields-exit-point-qibm-qzda-ndb1-format-zdad0100
//    (table collée directement par l'utilisateur le 2026-07-13)
//  - http://www.setgetweb.com/p/i5/rzaiimstexdb.htm
//
// A CONFIRMER malgré tout :
//  - le mode de passage du paramètre 2 (par valeur comme pour
//    ZDAI0100, ou par référence - la taille de 358 octets rend
//    les deux plausibles) ;
//  - la valeur du code retour pour autoriser/refuser (supposée
//    '1'/'0' par analogie avec QZDA_INIT).
// Teste en environnement non productif avant mise en service.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec QIBM_QZDA_INIT - à revalider pour NDB1 spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);          // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(358) value;  // Entrée : structure ZDAD0100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ZDAD0100 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile        char(10);   // Profil utilisateur appelant le serveur
  ServerId           char(10);   // Toujours '*NDB' pour ce point de sortie
  FormatName         char(8);    // Toujours 'ZDAD0100'
  RequestedFunction  int(10);    // Code d'opération - valeurs confirmées :
                                  //   X'1800' Créer un fichier physique source
                                  //   X'1801' Créer un fichier BDD basé sur un fichier existant
                                  //   X'1802' Ajouter un membre
                                  //   X'1803' Vider un membre
                                  //   X'1804' Supprimer un membre
                                  //   X'1805' Surcharger (override) un fichier
                                  //   X'1806' Supprimer une surcharge de fichier
                                  //   X'1807' Créer un fichier de sauvegarde (save file)
                                  //   X'1808' Vider un fichier de sauvegarde
                                  //   X'1809' Supprimer un fichier
  FileName           char(128);  // Nom du fichier visé par la fonction
  LibraryName        char(10);   // Bibliothèque contenant le fichier
  MemberName         char(10);   // Membre visé
  Authority           char(10);  // Autorité utilisée pour une création
  BasedOnFileName     char(128); // Fichier source (cas d'une création)
  BasedOnLibraryName  char(10);  // Bibliothèque du fichier source
  OverrideFileName    char(10);  // Fichier faisant l'objet d'un override
  OverrideLibraryName char(10);  // Bibliothèque de l'override
  OverrideMemberName  char(10);  // Membre de l'override
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

// 1) Journalisation de la requête (audit)
exsr LogAttempt;

// 2) Contrôle de l'accès natif - politique de sécurité à définir
exsr CheckNativeRequest;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête native
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        ExitData_t.LibraryName, ExitData_t.FileName,
  //        ExitData_t.MemberName, date/heure système dans un
  //        fichier d'audit dédié (ex: WRITE sur un fichier
  //        LOGNDBP), ou tracer via QAUDJRN / DTAARA selon
  //        le besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'accès natif
//==============================================================
begsr CheckNativeRequest;
  Allowed = *on;

  // Exemple : bloquer l'accès à une bibliothèque sensible
  // if %trim(ExitData_t.LibraryName) = 'PAYROLL';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer l'accès à un fichier précis
  // if %trim(ExitData_t.FileName) = 'SALAIRES';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur tout accès natif
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
