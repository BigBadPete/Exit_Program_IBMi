**FREE
//==============================================================
// Programme de sortie : QPWFSSRV
// Point de sortie      : QIBM_QPWFS_FILE_SERV
// Format               : PWFS0100 (implémenté ci-dessous) - la
//                        variante PWFS0200 est documentée en fin
//                        de fichier à titre de référence.
//
// STRUCTURE PWFS0100 RE-CONFIRMEE le 2026-07-13 directement
// depuis la table IBM (collée par l'utilisateur) - elle s'avère
// EXACTE, aucune correction nécessaire par rapport à la version
// du 2026-07-10 (issue de setgetweb.com).
//
// Ce point de sortie est associé au serveur de fichiers IBM i
// NetServer (partage SMB/CIFS vers l'IFS) - il est appelé pour
// chaque opération sur fichier/répertoire (ouverture, création,
// lecture, écriture, suppression, déplacement, renommage,
// allocation de conversation).
//
// IMPORTANT - CHOIX DU FORMAT (PWFS0100 vs PWFS0200) : contrairement
// à QZRC_RMT où le type de requête se détermine AU RUNTIME (un
// seul programme gère les deux cas via un test sur un champ), le
// choix entre PWFS0100 et PWFS0200 se fait A L'ENREGISTREMENT
// (WRKREGINF) : le serveur appelle le format pour lequel le
// programme est enregistré. Si un programme est enregistré pour
// les DEUX formats, SEUL celui enregistré pour PWFS0200 est
// appelé. PWFS0200 est un sur-ensemble de PWFS0100 (il ajoute la
// requête "Copy" et un mécanisme d'offsets pour les noms de
// fichier/cible) - c'est le format recommandé pour une nouvelle
// implémentation ; PWFS0100 reste documenté ici car déjà
// implémenté et toujours valide.
//
// AUTRES POINTS IMPORTANTS SIGNALES PAR IBM :
//  - Le nom du programme de sortie est résolu au DEMARRAGE du
//    sous-système QSERVER : un changement de programme enregistré
//    nécessite un ENDSBS/STRSBS de QSERVER pour être pris en compte.
//  - L'utilisateur doit avoir au moins l'autorité *RX sur chaque
//    répertoire du chemin menant à l'objet, sinon la requête
//    échoue avant même d'atteindre ce programme de sortie.
//  - SECURITE : si ce programme de sortie fait un "profile swap"
//    vers un autre utilisateur SANS revenir à l'utilisateur
//    d'origine avant de rendre la main, cela n'a AUCUN EFFET sur
//    les opérations du serveur de fichiers - le serveur continue
//    d'utiliser les informations d'identification de la connexion
//    initiale. Un contrôle d'accès par swap de profil ne
//    fonctionnera donc PAS ici, contrairement à d'autres contextes.
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page IBM
// "Exit point QIBM_QPWFS_FILE_SERV format PWFS0100/PWFS0200",
// collée directement par l'utilisateur le 2026-07-13).
//
// IMPORTANT : le nom du fichier est fourni en CCSID 1200
// (Unicode UTF-16BE), PAS en CCSID EBCDIC habituel - à prendre
// en compte pour toute comparaison de chaîne (ex : conversion via
// iconv() ou CDRCVRT avant comparaison).
//
// A CONFIRMER : le mode de passage exact des paramètres (par
// analogie avec les autres serveurs hôtes confirmés, la
// convention à 2 paramètres [code retour + structure] est très
// probable mais pas vérifiée individuellement pour ce point de
// sortie précis).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres, par analogie
// avec les autres serveurs hôtes confirmés)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);                              // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(65535) const options(*varsize);   // Entrée : structure PWFS0100
end-pi;

//--------------------------------------------------------------
// Gabarit de la partie fixe du format PWFS0100 (confirmé)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile        char(10); // Profil utilisateur appelant le serveur
  ServerId           char(10); // Toujours '*FILESRV'
  RequestedFunction  int(10);  // Opération demandée :
                                //   X'0000' Changer les attributs du fichier
                                //   X'0001' Créer un fichier/répertoire
                                //   X'0002' Supprimer un fichier/répertoire
                                //   X'0003' Lister les attributs
                                //   X'0004' Déplacer
                                //   X'0005' Ouvrir un fichier (flux)
                                //   X'0006' Renommer
                                //   X'0007' Allouer une conversation
  FormatName         char(8);  // Toujours 'PWFS0100'
  ReadAccess         char(1);  // Indicateur d'accès en lecture
  WriteAccess        char(1);  // Indicateur d'accès en écriture
  ReadWriteAccess    char(1);  // Indicateur d'accès lecture/écriture
  DeleteAccess       char(1);  // Indicateur d'accès en suppression
  FileNameLen        int(10);  // Longueur du nom de fichier (max 16 Mo)
end-ds;                        // Le nom du fichier (CCSID 1200 / UTF-16BE)
                                // suit immédiatement à l'offset 40

dcl-s p_ExitDataPtr pointer inz;
dcl-s p_FileNamePtr pointer inz;
dcl-s FileNameUtf16 char(65495) based(p_FileNamePtr); // tronqué au-delà - cf. avertissement

dcl-c FILENAME_OFFSET 40;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr  = %addr(p_ExitData);
p_FileNamePtr  = p_ExitDataPtr + FILENAME_OFFSET;

// 1) Journalisation de l'opération (audit)
exsr LogAttempt;

// 2) Contrôle de l'accès fichier/répertoire - politique de
//    sécurité à définir
exsr CheckFileAccess;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de l'accès au partage de fichiers
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile, ExitData_t.RequestedFunction,
  //        date/heure système dans un fichier d'audit dédié
  //        (ex: WRITE sur un fichier LOGFSVP), ou tracer via
  //        QAUDJRN / DTAARA selon le besoin. Le nom de fichier
  //        (FileNameUtf16) est en UTF-16BE - convertir avant
  //        de le journaliser en clair si besoin.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'accès fichier/répertoire
//==============================================================
begsr CheckFileAccess;
  Allowed = *on;

  // Exemple : bloquer toute suppression
  // if ExitData_t.DeleteAccess = '1';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis sur tout accès au partage
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;

//==============================================================
// REFERENCE : format PWFS0200 (non branché dans le flux actif
// ci-dessus - à utiliser si le programme est enregistré pour
// PWFS0200 plutôt que PWFS0100, cf. explication en en-tête de
// fichier). Sur-ensemble de PWFS0100 : ajoute la requête "Copy"
// (X'0008') et remplace la position fixe du nom de fichier par
// un mécanisme d'offsets (le nom de fichier ET le nom cible - en
// cas de déplacement/renommage/copie - peuvent chacun être
// absents, positionnés via un offset à zéro).
// Taille totale max (structure + noms) : 16 Mo.
//==============================================================
dcl-ds ExitData0200_t qualified based(p_ExitDataPtr);
  UserProfile          char(10); // offset 0  - Profil utilisateur appelant le serveur
  ServerId             char(10); // offset 10 - Toujours '*FILESRV'
  RequestedFunction    int(10);  // offset 20 - Comme PWFS0100, plus X'0008' Copy
  FormatName           char(8);  // offset 24 - Toujours 'PWFS0200'
  ReadAccess           char(1);  // offset 32 - Valide seulement si Open (X'0005')
  WriteAccess          char(1);  // offset 33
  ReadWriteAccess      char(1);  // offset 34
  DeleteAccess         char(1);  // offset 35
  ObjectType           char(10); // offset 36 - '*STMF'/'*DIR', valide seulement si
                                  // Create (X'0001')
  Reserved             char(6);  // offset 46
  FileNameOffset       int(10);  // offset 52 - décalage depuis le début du format
                                  // vers le nom de fichier ; 0 si Allocate
                                  // conversation (X'0007')
  FileNameLen          int(10);  // offset 56 - longueur du nom de fichier (max 16 Mo)
  TargetFileNameOffset int(10);  // offset 60 - décalage vers le nom cible ; non nul
                                  // seulement pour Move (X'0004'), Rename (X'0006')
                                  // ou Copy (X'0008')
  TargetFileNameLen    int(10);  // offset 64 - longueur du nom cible ; 0 si
                                  // TargetFileNameOffset = 0
end-ds;                          // Les noms (CCSID 1200) suivent à des positions
                                  // VARIABLES indiquées par *Offset, PAS à un offset
                                  // fixe comme en PWFS0100 - il faut les lire via
                                  // p_ExitDataPtr + ExitData0200_t.FileNameOffset et
                                  // p_ExitDataPtr + ExitData0200_t.TargetFileNameOffset,
                                  // en vérifiant d'abord que l'offset est non nul.
