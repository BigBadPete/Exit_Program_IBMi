**FREE
//==============================================================
// Programme de sortie : QTMFLOGN
// Point de sortie      : QIBM_QTMF_SVR_LOGON
// Format               : TCPL0100 (variantes TCPL0200/TCPL0300
//                        documentées en fin de fichier à titre de
//                        référence, non implémentées ici)
//
// STRUCTURE RE-CONFIRMEE le 2026-07-14 directement depuis la
// table IBM (collée par l'utilisateur) - s'avère EXACTE, aucune
// correction nécessaire par rapport à la version du 2026-07-10.
//
// PARTICULARITE : ce format TCPL0100 est PARTAGE entre le
// serveur FTP (QIBM_QTMF_SVR_LOGON, ce fichier) et le serveur
// REXEC (QIBM_QTMX_SVR_LOGON - point de sortie DISTINCT, non
// couvert par un fichier séparé ici ; il utilise exactement la
// même signature TCPL0100/TCPL0300, contrairement à TCPL0200 qui
// est réservé à FTP uniquement). Ce squelette utilise 11
// PARAMETRES DISTINCTS, PAS le schéma générique "code retour +
// une structure" utilisé par les serveurs hôtes (QZDA, QZSO,
// QNPS, QZRC...).
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "TCPL0100 exit point format", collée directement par
// l'utilisateur le 2026-07-14).
//
// AVERTISSEMENT SECURITE IMPORTANT (rappelé par IBM) : ne JAMAIS
// coder de mot de passe en dur dans un programme de sortie, et
// être très prudent avec le paramètre 10 (mot de passe en
// sortie) - à utiliser uniquement si la politique de sécurité
// l'exige explicitement (ex : substitution contrôlée), jamais
// pour de la journalisation en clair.
//
// A CONFIRMER : la signification précise de chaque valeur de
// code retour (0 = refuser confirmé ; 1 à 6 = accepter avec
// traitement différent des paramètres de sortie, détail exact à
// vérifier dans la doc IBM i avant mise en service).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (11 paramètres CONFIRMES)
//--------------------------------------------------------------
dcl-pi *n;
  p_AppId          int(10)     const;                   // E : 0=FTP client, 1=FTP serveur, 2=REXEC serveur
  p_UserId         char(65535) const options(*varsize);  // E : identifiant utilisateur fourni par le client
  p_UserIdLen       int(10)    const;                    // E : longueur de p_UserId
  p_AuthString      char(65535) const options(*varsize); // E : chaîne d'authentification (mot de passe)
  p_AuthStringLen   int(10)    const;                    // E : longueur de p_AuthString
  p_ClientIPAddr    char(65535) const options(*varsize); // E : adresse IP du client
  p_ClientIPAddrLen int(10)    const;                    // E : longueur de p_ClientIPAddr
  p_RtnCode         int(10);                             // S : 0=refuser, 1-6=autoriser (détail à confirmer)
  p_UserProfile     char(10);                            // S : profil utilisateur à utiliser (si substitution)
  p_Password        char(10);                            // S : mot de passe à utiliser - MANIPULER AVEC PRECAUTION
  p_InitialLibrary  char(10);                             // S : bibliothèque courante initiale
end-pi;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================

// 1) Journalisation de la tentative de connexion (audit) - NE
//    JAMAIS journaliser p_AuthString en clair
exsr LogAttempt;

// 2) Contrôle de l'authentification - politique de sécurité à définir
exsr CheckSignon;

// 3) Positionnement du code retour (0 = refuser confirmé ; les
//    autres valeurs à confirmer précisément avant utilisation
//    fine des paramètres de sortie 9-11)
if Allowed;
  p_RtnCode = 1;
else;
  p_RtnCode = 0;
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la tentative de connexion FTP
//==============================================================
begsr LogAttempt;
  // TODO : écrire p_AppId, %subst(p_UserId:1:%min(p_UserIdLen:65535)),
  //        %subst(p_ClientIPAddr:1:%min(p_ClientIPAddrLen:65535)),
  //        date/heure système dans un fichier d'audit dédié
  //        (ex: WRITE sur un fichier LOGFTPP), ou tracer via
  //        QAUDJRN / DTAARA selon le besoin. Utile pour détecter
  //        des tentatives répétées (brute force) depuis une même IP.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur la connexion FTP/REXEC
//==============================================================
begsr CheckSignon;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if %subst(p_UserId:1:%min(p_UserIdLen:10)) = 'QSECOFR';
  //   Allowed = *off;
  // endif;

  // Exemple : n'autoriser qu'une plage d'IP
  // if %subst(p_ClientIPAddr:1:6) <> '10.0.0';
  //   Allowed = *off;
  // endif;
endsr;

//==============================================================
// REFERENCE : format TCPL0200 (FTP UNIQUEMENT - PAS REXEC).
// Ajoute par rapport à TCPL0100 : le paramètre 8 devient "Allow
// logon" (même rôle que "Return code" mais renommé), la
// bibliothèque courante initiale (11) devient Entrée/Sortie
// (peut être pré-remplie par le serveur), et 4 nouveaux
// paramètres apparaissent : répertoire personnel initial (12-13)
// et informations spécifiques à l'application (14-15).
//--------------------------------------------------------------
// dcl-pi *n;
//   p_AppId            int(10)     const;
//   p_UserId           char(65535) const options(*varsize);
//   p_UserIdLen        int(10)     const;
//   p_AuthString       char(65535) const options(*varsize);
//   p_AuthStringLen    int(10)     const;
//   p_ClientIPAddr     char(65535) const options(*varsize);
//   p_ClientIPAddrLen  int(10)     const;
//   p_AllowLogon       int(10);                              // S : autoriser la connexion
//   p_UserProfile      char(10);                              // S
//   p_Password         char(10);                              // S
//   p_InitialLibrary   char(10);                              // E/S
//   p_InitialHomeDir   char(65535) options(*varsize);          // S
//   p_InitialHomeDirLen int(10);                               // E/S
//   p_AppSpecificInfo  char(65535) options(*varsize);          // E/S
//   p_AppSpecificInfoLen int(10)   const;                      // E
// end-pi;
//==============================================================

//==============================================================
// REFERENCE : format TCPL0300 (partagé FTP + REXEC, comme
// TCPL0100). Version la plus riche : ajoute la gestion des CCSID
// pour la chaîne d'authentification, le mot de passe (devient
// CHAR(*) avec longueur+CCSID plutôt qu'un CHAR(10) fixe - permet
// des mots de passe longs/Unicode) et le répertoire personnel
// initial. C'est probablement le format à privilégier pour une
// nouvelle implémentation si le support Unicode/mots de passe
// longs est requis.
//--------------------------------------------------------------
// dcl-pi *n;
//   p_AppId               int(10)     const;
//   p_UserId              char(65535) const options(*varsize);
//   p_UserIdLen            int(10)    const;
//   p_AuthString           char(65535) const options(*varsize);
//   p_AuthStringLen        int(10)    const;
//   p_AuthStringCcsid      int(10)    const;                   // E : CCSID de la chaîne d'authentification
//   p_ClientIPAddr         char(65535) const options(*varsize);
//   p_ClientIPAddrLen      int(10)    const;
//   p_AllowLogon           int(10);                             // S
//   p_UserProfile          char(10);                            // S
//   p_Password             char(65535) options(*varsize);       // S : CHAR(*), plus de limite à 10 car.
//   p_PasswordLen          int(10);                              // S
//   p_PasswordCcsid        int(10);                              // S
//   p_InitialLibrary       char(10);                             // E/S
//   p_InitialHomeDir       char(65535) options(*varsize);        // S
//   p_InitialHomeDirLen    int(10);                              // E/S
//   p_InitialHomeDirCcsid  int(10);                              // E/S
//   p_AppSpecificInfo      char(65535) options(*varsize);        // E/S
//   p_AppSpecificInfoLen   int(10)    const;                     // E
// end-pi;
//==============================================================
