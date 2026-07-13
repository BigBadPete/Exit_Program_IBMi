**FREE
//==============================================================
// Programme de sortie : QZHQDTAQ
// Point de sortie      : QIBM_QZHQ_DATA_QUEUE
// Format               : ZHQ00100
//
// STRUCTURE CONFIRMEE le 2026-07-13 directement depuis la table
// IBM (collée par l'utilisateur) - REMPLACE toutes les versions
// précédentes qui étaient entièrement spéculatives (deux noms de
// point de sortie candidats avaient été trouvés sans confirmation
// - c'est bien "QIBM_QZHQ_DATA_QUEUE" qui est correct).
//
// Ce point de sortie est appelé par le serveur de data queue
// (application '*DATAQSRV') pour chaque opération distante sur
// une file d'attente de données : interrogation d'attributs,
// réception (avec ou sans suppression), création, suppression,
// envoi, effacement, annulation d'une réception en attente.
//
// Par analogie avec les autres serveurs hôtes confirmés
// (structure fixe, pas de champ CHAR(*) en fin), il reçoit
// vraisemblablement 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée, probablement PAR VALEUR
//      comme ZDAI0100/ZDAD0100/ZDAR0100, structure de taille
//      fixe) - CHAR(314) format ZHQ00100
//
// Structure définie par le membre EZHQEP (fichiers H, QRPGSRC,
// QRPGLESRC, QLBLSRC, QCBLLESRC de la bibliothèque QSYSINC).
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "Identify the IBM i exit point for data queue serving",
// collée directement par l'utilisateur le 2026-07-13).
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
// QZHQ_DATA_QUEUE spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);          // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(314) value;  // Entrée : structure ZHQ00100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ZHQ00100 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile          char(10);  // offset 0  - Profil utilisateur appelant le serveur
  ServerId             char(10);  // offset 10 - Toujours '*DATAQSRV'
  FormatName           char(8);   // offset 20 - Toujours 'ZHQ00100'
  RequestedFunction    int(10);   // offset 28 - Opération demandée :
                                   //   X'0001' Interroger les attributs
                                   //   X'0002' Recevoir un message (avec suppression)
                                   //   X'0003' Créer la data queue
                                   //   X'0004' Supprimer la data queue
                                   //   X'0005' Envoyer un message
                                   //   X'0006' Effacer les messages
                                   //   X'0007' Annuler une réception en attente
                                   //   X'0012' Recevoir sans supprimer (Peek)
  ObjectName           char(10);  // offset 32 - Nom de la data queue
  LibraryName          char(10);  // offset 42 - Bibliothèque de la data queue
  RelationalOperation  char(2);   // offset 52 - Opérateur pour réception par clé :
                                   //   X'0000' aucun, 'EQ','NE','GE','GT','LE','LT'
  KeyLength            int(10);   // offset 54 - Longueur de la clé demandée
  KeyValue             char(256); // offset 58 - Valeur de la clé demandée
end-ds;                           // taille totale = 314 octets

dcl-s p_ExitDataPtr pointer inz;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de l'opération (audit)
exsr LogAttempt;

// 2) Contrôle de l'accès à la data queue - politique de sécurité
//    à définir
exsr CheckDataQueueAccess;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de l'accès à la data queue
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        ExitData_t.LibraryName, ExitData_t.ObjectName, date/heure
  //        système dans un fichier d'audit dédié (ex: WRITE sur un
  //        fichier LOGDTQP), ou tracer via QAUDJRN / DTAARA selon
  //        le besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'accès à la data queue
//==============================================================
begsr CheckDataQueueAccess;
  Allowed = *on;

  // Exemple : bloquer l'accès à une bibliothèque sensible
  // if %trim(ExitData_t.LibraryName) = 'PAYROLL';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer l'accès à une data queue précise
  // if %trim(ExitData_t.ObjectName) = 'DTQSECURE';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer la suppression de data queues
  // if ExitData_t.RequestedFunction = 4; // X'0004'
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur tout accès data queue
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
