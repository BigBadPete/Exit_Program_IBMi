**FREE
//==============================================================
// Programme de sortie : QZDASQL2
// Point de sortie      : QIBM_QZDA_SQL2
// Format               : ZDAQ0200
//
// STRUCTURE CONFIRMEE (corrigée le 2026-07-10 par recherche
// documentaire - remplace une première version qui utilisait un
// nom de format (SQLR0100) et des offsets inventés).
//
// Ce point de sortie est appelé pour CHAQUE requête SQL exécutée
// via le serveur hôte de base de données (JDBC/ODBC/CLI, etc.).
// Par analogie confirmée avec QIBM_QZDA_INIT (même famille
// EZDAEP/QSYSINC), il reçoit vraisemblablement 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée, PAR REFERENCE vu la taille
//      variable) - format ZDAQ0200, avec le texte SQL complet
//      en fin de structure (jusqu'à 2 Mo).
//
// Sources :
//  - http://www.setgetweb.com/p/i5/rzaiimstexdb.htm
//  - https://www.ibm.com/docs/en/i/7.5.0?topic=eppf-parameter-fields-exit-point-qibm-qzda-sql2-format-zdaq0200
//
// CORRECTION DU 2026-07-13 (signalée par l'utilisateur après
// relecture de la doc IBM ci-dessus) : la zone "Reserved" de 129
// octets (offset 105) était en réalité structurée (mode de
// nommage + décalages/longueurs pour un nom de curseur et un
// schéma SQL par défaut étendus, utilisés quand ces noms
// dépassent les 18/10 caractères des champs standards). Détaillée
// ci-dessous. Les champs RequestedFunction (BINARY(4)) et
// DrdaIndicator (BINARY(2)) étaient corrects malgré les
// apparences : int(10) et int(5) en RPG correspondent bien à des
// entiers de 4 et 2 octets respectivement (RPG dimensionne par
// précision décimale, pas par octets).
//
// A CONFIRMER malgré tout :
//  - le mode de passage exact du paramètre 2 (probablement par
//    référence puisque la taille est variable jusqu'à 2 Mo) ;
//  - la valeur du code retour pour autoriser/refuser (supposée
//    '1'/'0' par analogie avec QZDA_INIT).
// LIMITE DE CE SQUELETTE : le texte SQL est lu ici via un tampon
// de 65535 caractères max (limite RPG pour un CHAR fixe) - les
// instructions SQL dépassant cette taille (jusqu'à 2 Mo réels)
// seront tronquées dans ce squelette simple. Utilise
// ExitData_t.SqlStmtLen pour connaître la vraie longueur et
// adapte la lecture si besoin de gérer des instructions très
// longues. Teste en environnement non productif avant mise en
// service.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec QIBM_QZDA_INIT - à revalider pour SQL2 spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);                          // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(65535) const options(*varsize); // Entrée : structure ZDAQ0200
end-pi;

//--------------------------------------------------------------
// Gabarit de la partie fixe du format ZDAQ0200 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile          char(10);  // Profil utilisateur appelant le serveur
  ServerId              char(10); // Toujours '*SQLSRV'
  FormatName             char(8); // Toujours 'ZDAQ0200'
  RequestedFunction     int(10);  // Opération (Prepare/Execute/Connect...)
  StatementName          char(18);// Nom de l'instruction préparée
  CursorName             char(18);// Nom du curseur (fonction Open)
  PrepareOption           char(2);// Option de la fonction Prepare
  OpenAttributes           char(2);// Option de la fonction Open
  ExtDynPkgName            char(10);// Nom du package SQL dynamique étendu
  PkgLibName               char(10);// Bibliothèque de ce package
  DrdaIndicator            int(5);  // 0 = connexion locale, 1 = distante
  CommitControlLevel       char(1); // A/C/N/S/L
  DefaultSqlCollection     char(10);// Collection SQL par défaut
  NamingMode               char(1); // Mode de nommage SQL/système (corrigé le 2026-07-13,
                                     // signalé par l'utilisateur - cf. commentaire ci-dessous)
  Reserved2                char(2); // Réservé
  ExtCursorNameOffset      int(10); // Décalage du nom de curseur étendu (noms longs)
  ExtCursorNameLen         int(10); // Longueur du nom de curseur étendu
  ExtSchemaOffset          int(10); // Décalage du schéma SQL par défaut étendu
  ExtSchemaLen             int(10); // Longueur du schéma SQL par défaut étendu
  Reserved3                char(110);// Réservé
  SqlStmtLen               int(10); // Longueur réelle du texte SQL (jusqu'à 2 Mo)
end-ds;                             // Le texte SQL suit immédiatement (offset 238)

dcl-s p_ExitDataPtr      pointer inz;
dcl-s p_SqlStmtPtr       pointer inz;
dcl-s SqlStmtText        char(65535) based(p_SqlStmtPtr); // tronqué au-delà - cf. avertissement

// Le nom de curseur étendu et le schéma SQL par défaut étendu ne
// sont utilisés QUE si le nom correspondant dépasse les champs
// fixes standards (CursorName 18 car. / DefaultSqlCollection 10
// car.) - dans ce cas seulement, Ext*Offset et Ext*Len sont non
// nuls et pointent vers le texte réel (position NON fixe,
// contrairement au texte SQL qui suit toujours à l'offset 238).
dcl-s p_ExtCursorNamePtr pointer inz;
dcl-s ExtCursorNameText  char(65535) based(p_ExtCursorNamePtr);
dcl-s p_ExtSchemaPtr     pointer inz;
dcl-s ExtSchemaNameText  char(65535) based(p_ExtSchemaPtr);

dcl-c SQLSTMT_OFFSET 238;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);
p_SqlStmtPtr  = p_ExitDataPtr + SQLSTMT_OFFSET;

// Ces deux champs ne sont significatifs que si leur longueur est
// non nulle (nom court -> champs fixes standards suffisants,
// aucune zone étendue fournie par le serveur).
if ExitData_t.ExtCursorNameLen > 0;
  p_ExtCursorNamePtr = p_ExitDataPtr + ExitData_t.ExtCursorNameOffset;
endif;
if ExitData_t.ExtSchemaLen > 0;
  p_ExtSchemaPtr = p_ExitDataPtr + ExitData_t.ExtSchemaOffset;
endif;

// 1) Journalisation de la requête SQL (audit)
exsr LogAttempt;

// 2) Contrôle de l'instruction SQL - politique de sécurité à définir
exsr CheckSqlStatement;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête SQL
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        %subst(SqlStmtText:1:%min(ExitData_t.SqlStmtLen:65535)),
  //        date/heure système dans un fichier d'audit dédié
  //        (ex: WRITE sur un fichier LOGSQLP), ou tracer via
  //        QAUDJRN / DTAARA selon le besoin. Si le nom de curseur
  //        ou le schéma dépassent les champs fixes standards,
  //        %subst(ExtCursorNameText:1:%min(ExitData_t.ExtCursorNameLen:65535))
  //        et %subst(ExtSchemaNameText:1:%min(ExitData_t.ExtSchemaLen:65535))
  //        contiennent les valeurs complètes (cf. contrôle de
  //        longueur > 0 avant lecture, dans le corps du programme).
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'instruction SQL
//==============================================================
begsr CheckSqlStatement;
  Allowed = *on;

  // Exemple : bloquer les DROP TABLE
  // if %scan('DROP TABLE':%subst(SqlStmtText:1:%min(ExitData_t.SqlStmtLen:65535))) > 0;
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur toute requête SQL
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
