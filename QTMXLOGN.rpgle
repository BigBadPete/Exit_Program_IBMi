**FREE
//==============================================================
// Programme de sortie : QTMXLOGN
// Point de sortie      : QIBM_QTMX_SVR_LOGON
// Format               : TCPL0100 (variante TCPL0300 documentée
//                        en fin de fichier à titre de référence -
//                        NOTE : TCPL0200 n'existe PAS pour ce
//                        point de sortie, il est réservé à FTP)
//
// STRUCTURE CONFIRMEE le 2026-07-14 - ce fichier reprend le même
// format TCPL0100 que QTMFLOGN.rpgle (serveur FTP), confirmé
// directement par la doc IBM comme étant PARTAGE entre les deux
// points de sortie QIBM_QTMF_SVR_LOGON et QIBM_QTMX_SVR_LOGON
// (serveur REXEC - exécution de commande à distance, protocole
// REXEC, port 512). Seule la valeur du paramètre 1 (identifiant
// d'application) change en pratique.
//
// Ce point de sortie est appelé à CHAQUE tentative de connexion
// (logon) au serveur REXEC, avant que la commande elle-même ne
// soit soumise (cf. QTMXREQ.rpgle pour la validation de la
// commande une fois connecté, format VLRQ0100 - même famille).
//
// Source : https://www.ibm.com/docs/en/i/7.5.0?topic=... (page
// IBM "TCPL0100 exit point format", collée directement par
// l'utilisateur le 2026-07-14 pour QTMFLOGN.rpgle, réutilisée ici
// pour QIBM_QTMX_SVR_LOGON qui partage exactement la même
// signature).
//
// AVERTISSEMENT SECURITE IMPORTANT (rappelé par IBM) : ne JAMAIS
// coder de mot de passe en dur dans un programme de sortie, et
// être très prudent avec le paramètre 10 (mot de passe en
// sortie) - à utiliser uniquement si la politique de sécurité
// l'exige explicitement (ex : substitution contrôlée), jamais
// pour de la journalisation en clair.
//
// A CONFIRMER : la valeur exacte de l'identifiant d'application
// pour un appel REXEC sur CE point de sortie précis (par analogie
// avec le format VLRQ0100 - partagé par QTMF_SERVER_REQ et
// QTMX_SERVER_REQ - où 2 = serveur REXEC, valeur reprise ici mais
// non vérifiée indépendamment pour TCPL0100/QTMX_SVR_LOGON) ; et
// la signification précise de chaque valeur de code retour
// (0 = refuser confirmé ; 1 à 6 = accepter avec traitement
// différent des paramètres de sortie, détail exact à vérifier
// dans la doc IBM i avant mise en service).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (11 paramètres CONFIRMES,
// structure TCPL0100 identique à QTMFLOGN.rpgle)
//--------------------------------------------------------------
dcl-pi *n;
  p_AppId          int(10)     const;                   // E : identifiant d'application - 2=serveur REXEC (à confirmer pour ce point de sortie précis)
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
// Sous-routine : journalisation de la tentative de connexion REXEC
//==============================================================
begsr LogAttempt;
  // TODO : écrire p_AppId, %subst(p_UserId:1:%min(p_UserIdLen:65535)),
  //        %subst(p_ClientIPAddr:1:%min(p_ClientIPAddrLen:65535)),
  //        date/heure système dans un fichier d'audit dédié
  //        (ex: WRITE sur un fichier LOGTMXP), ou tracer via
  //        QAUDJRN / DTAARA selon le besoin. Utile pour détecter
  //        des tentatives répétées (brute force) depuis une même IP -
  //        particulièrement pertinent pour REXEC, protocole ancien
  //        et souvent ciblé.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur la connexion REXEC
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

  // Exemple : REXEC étant un protocole ancien et peu sécurisé
  // (authentification en clair par défaut), une politique fréquente
  // est de le désactiver purement et simplement :
  // Allowed = *off;
endsr;

//==============================================================
// REFERENCE : format TCPL0300 (partagé FTP + REXEC comme
// TCPL0100 - TCPL0200 n'existe PAS pour REXEC). Version la plus
// riche : ajoute la gestion des CCSID pour la chaîne
// d'authentification, le mot de passe (devient CHAR(*) avec
// longueur+CCSID plutôt qu'un CHAR(10) fixe) et le répertoire
// personnel initial.
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
