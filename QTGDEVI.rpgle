**FREE
//==============================================================
// Programme de sortie : QTGDEVI
// Point de sortie      : QIBM_QTG_DEVINIT
// Format               : INIT0100 (et non "DEVI0100" comme
//                        indiqué dans une première version)
//
// STRUCTURE CONFIRMEE par recherche documentaire (2026-07-10) :
// membre QSYSINC associé = ETGDEVEX. CORRECTION IMPORTANTE :
// ce point de sortie utilise 7 PARAMETRES DISTINCTS, PAS le
// schéma générique "code retour + une structure" utilisé par
// les autres serveurs hôtes (QZDA, QZSO, QNPS, QZRC...).
//
// Ce point de sortie est appelé par le serveur Telnet IBM i lors
// de la création d'une session (device 5250) pour un client
// entrant. Il peut MODIFIER des données en sortie (paramètres 1
// et 2, en entrée-sortie).
//
// Source : http://www.setgetweb.com/p/i5/rzaiwdevinit.htm
//
// A CONFIRMER : le détail champ par champ des structures "User
// description information", "Device description information"
// et "Connection description information" (paramètres 1 à 3) -
// non trouvées dans la source consultée. Seule l'existence et le
// rôle de ces 3 structures est confirmé, pas leur contenu
// détaillé. Consulte la doc IBM i (TCP/IP - Telnet - Exit
// Programs - QTG_DEVINIT, rubriques liées aux formats détaillés)
// avant d'exploiter ces champs.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (7 paramètres CONFIRMES)
//--------------------------------------------------------------
dcl-pi *n;
  p_UserDesc      char(32767) options(*varsize);       // E/S : infos utilisateur - structure interne non confirmée
  p_DeviceDesc    char(32767) options(*varsize);       // E/S : infos device - structure interne non confirmée
  p_ConnDesc      char(32767) const options(*varsize); // E   : infos connexion - structure interne non confirmée
  p_EnvOptions    char(32767) const options(*varsize); // E   : options d'environnement
  p_EnvOptionsLen int(10)     const;                   // E   : longueur des options d'environnement
  p_AllowConn     char(1);                             // S   : '1' = autoriser la connexion
  p_AllowAutoSgn  char(1);                              // S   : '1' = autoriser l'auto-sign-on
end-pi;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================

// 1) Journalisation de la création de session Telnet (audit)
exsr LogAttempt;

// 2) Contrôle et/ou personnalisation de la session - politique
//    de sécurité et de nommage à définir (nécessite de connaître
//    le détail des structures d'entrée pour lire l'IP client,
//    le device demandé, etc. - cf. avertissement en en-tête)
exsr CheckAndCustomizeDevice;

// 3) Positionnement des codes de sortie
if Allowed;
  p_AllowConn = '1';
else;
  p_AllowConn = '0';
endif;
p_AllowAutoSgn = '0'; // par défaut, ne pas autoriser l'auto-sign-on
                       // sans analyse explicite de la politique de sécurité

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la création de session Telnet
//==============================================================
begsr LogAttempt;
  // TODO : une fois la structure des paramètres 1 à 3 confirmée,
  //        écrire le profil utilisateur, l'IP client, le nom de
  //        device demandé, date/heure système dans un fichier
  //        d'audit dédié (ex: WRITE sur un fichier LOGTGDP), ou
  //        tracer via QAUDJRN / DTAARA selon le besoin.
endsr;

//==============================================================
// Sous-routine : contrôle d'accès et personnalisation du device
//==============================================================
begsr CheckAndCustomizeDevice;
  Allowed = *on;

  // TODO : une fois la structure confirmée, ajouter les règles
  // de contrôle (plage d'IP, personnalisation du nom de device
  // selon l'IP client, etc.) en lisant/écrivant p_UserDesc et
  // p_DeviceDesc.
endsr;
