**FREE
//==============================================================
// Programme de sortie : QZDAROI1
// Point de sortie      : QIBM_QZDA_ROI1
// Format               : ZDAR0100 (variante ZDAR0200 pour la
//                        récupération de clés primaires/étrangères
//                        - non implémentée ici, cf. note en bas)
//
// STRUCTURE RE-CONFIRMEE le 2026-07-13 directement depuis la
// table IBM (collée par l'utilisateur) - CORRIGE 2 points de la
// version du 2026-07-10 :
//  1. Il manquait le dernier champ "Extended Schema Name"
//     CHAR(256) à l'offset 404 - la taille réelle de la structure
//     est donc 660 octets, PAS 404.
//  2. Le champ à l'offset 32 s'appelle réellement "Schema name"
//     (pas "Library name" comme précédemment nommé) - avec une
//     règle spéciale : si le nom/motif dépasse 20 caractères, ce
//     champ contient la valeur spéciale '*EXTDSCHMA' et la vraie
//     valeur se trouve dans le nouveau champ ExtendedSchemaName.
//
// Ce point de sortie est appelé pour les requêtes de RECUPERATION
// D'INFORMATIONS SUR DES OBJETS (bibliothèques, fichiers,
// membres, champs, index, packages, bases de données
// relationnelles...) faites via le serveur hôte de base de
// données - typiquement le genre de requêtes émises par les
// outils de "Catalog"/métadonnées ODBC/JDBC. ServerId = '*RTVOBJINF'.
//
// Par analogie confirmée avec QIBM_QZDA_INIT (même famille
// EZDAEP/QSYSINC), il reçoit vraisemblablement 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée) - CHAR(660) format ZDAR0100
//
// Sources :
//  - https://www.ibm.com/docs/en/i/7.5.0?topic=eppf-parameter-fields-exit-point-qibm-qzda-roi1-format-zdar0100
//    (table collée directement par l'utilisateur le 2026-07-13)
//  - http://www.setgetweb.com/p/i5/rzaiimstexdb.htm
//
// A CONFIRMER malgré tout :
//  - le mode de passage du paramètre 2 (par valeur ou référence) ;
//  - la valeur du code retour pour autoriser/refuser (supposée
//    '1'/'0' par analogie avec QZDA_INIT) ;
//  - la variante ZDAR0200 (clés primaires/étrangères - codes
//    X'1809'/X'180A', cohérent avec le trou dans la liste des
//    codes ci-dessous qui saute directement de X'1808' à X'180B')
//    n'est PAS gérée par ce squelette - à ajouter séparément si
//    nécessaire, en distinguant sur ExitData_t.RequestedFunction.
// Teste en environnement non productif avant mise en service.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec QIBM_QZDA_INIT - à revalider pour ROI1 spécifiquement)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);          // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(660) value;  // Entrée : structure ZDAR0100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ZDAR0100 (confirmé directement
// depuis la table IBM le 2026-07-13)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile        char(10);   // offset 0   - Profil utilisateur appelant le serveur
  ServerId           char(10);   // offset 10  - Toujours '*RTVOBJINF'
  FormatName         char(8);    // offset 20  - Toujours 'ZDAR0100'
  RequestedFunction  int(10);    // offset 28  - Type d'information demandée :
                                  //   X'1800' Infos bibliothèque
                                  //   X'1801' Infos base de données relationnelle
                                  //   X'1802' Infos package SQL
                                  //   X'1803' Infos instruction de package SQL
                                  //   X'1804' Infos fichier
                                  //   X'1805' Infos membre de fichier
                                  //   X'1806' Infos format d'enregistrement
                                  //   X'1807' Infos champ
                                  //   X'1808' Infos index
                                  //   X'180B' Infos colonne spéciale
                                  //   (X'1809'/X'180A' = clés primaires/étrangères,
                                  //    format ZDAR0200 distinct - non géré ici)
  SchemaName         char(20);   // offset 32  - Schéma/bibliothèque ou motif de
                                  // recherche. Si le nom réel dépasse 20 car.,
                                  // vaut '*EXTDSCHMA' et la vraie valeur est
                                  // dans ExtendedSchemaName (TOUJOURS renseigné,
                                  // même quand SchemaName suffit déjà).
  RdbName            char(36);   // offset 52  - Base de données relationnelle ou motif
  PackageName        char(20);   // offset 88  - Package SQL ou motif de recherche
  FileName           char(256);  // offset 108 - Fichier (alias SQL) ou motif de recherche
  MemberName         char(20);   // offset 364 - Membre ou motif de recherche
  RecordFormatName   char(20);   // offset 384 - Format d'enregistrement ou motif de recherche
  ExtendedSchemaName char(256);  // offset 404 - Schéma étendu ou motif (toujours valide,
                                  // à utiliser de préférence à SchemaName)
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

// 1) Journalisation de la requête de métadonnées (audit)
exsr LogAttempt;

// 2) Contrôle de l'accès aux métadonnées - politique de sécurité
//    à définir
exsr CheckObjectInfoAccess;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête de métadonnées
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        %trimr(ExitData_t.ExtendedSchemaName), ExitData_t.FileName,
  //        date/heure système dans un fichier d'audit dédié (ex:
  //        WRITE sur un fichier LOGROIP), ou tracer via QAUDJRN /
  //        DTAARA selon le besoin. Utiliser ExtendedSchemaName
  //        plutôt que SchemaName (toujours valide, y compris pour
  //        les noms courts).
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'accès aux métadonnées
//==============================================================
begsr CheckObjectInfoAccess;
  Allowed = *on;

  // Exemple : bloquer la découverte de métadonnées sur un schéma
  // sensible (utiliser ExtendedSchemaName, toujours fiable)
  // if %trim(ExitData_t.ExtendedSchemaName) = 'PAYROLL';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
