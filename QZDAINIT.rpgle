**FREE
//==============================================================
// Programme de sortie : QZDAINIT
// Point de sortie      : QIBM_QZDA_INIT
// Format               : ZDAI0100
//
// STRUCTURE RE-CONFIRMEE le 2026-07-13 directement depuis la
// table IBM (collée par l'utilisateur, page bloquée à la
// récupération automatisée mais lue manuellement) - CORRIGE une
// erreur de la version précédente : il manquait 3 champs, la
// vraie taille de la structure est 285 octets et NON 32 octets.
//
// L'exemple communautaire de 2003 (archive.midrange.com) qui
// utilisait une structure de 32 octets correspondait
// vraisemblablement à une version plus ancienne du format (V5R1/
// V5R2) - IBM a depuis étendu ZDAI0100 avec 3 champs
// supplémentaires (type/nom/niveau d'interface) tout en gardant
// le même nom de format. Sur les systèmes actuels (7.x), c'est la
// structure à 285 octets ci-dessous qui s'applique.
//
// Ce point de sortie est appelé UNE FOIS par le serveur de base
// de données (QZDASOINIT/QZDASSINIT) à l'initialisation de la
// connexion. Il reçoit exactement 2 paramètres :
//   1. Code retour (sortie) - CHAR(1)
//   2. Données d'exit point (entrée, PASSEES PAR VALEUR) - CHAR(285)
//      correspondant au format ZDAI0100.
//
// Structure définie par le membre EZDAEP (fichiers H, QRPGSRC,
// QRPGLESRC, QCBLSRC, QCBLLESRC de la bibliothèque QSYSINC).
//
// Sources :
//  - https://www.ibm.com/docs/en/i/7.5.0?topic=eppf-parameter-fields-exit-point-qibm-qzda-init-format-zdai0100
//    (table collée directement par l'utilisateur le 2026-07-13)
//  - http://www.setgetweb.com/p/i5/rzaiimstexdb.htm
//  - https://archive.midrange.com/midrange-l/200301/msg01461.html
//    (exemple RPG communautaire confirmant la signature à 2
//    paramètres et le passage par valeur - mais avec une taille
//    de structure obsolète, cf. remarque ci-dessus)
//
// A CONFIRMER malgré tout : la valeur exacte du code retour pour
// autoriser/refuser. La convention la plus citée est '1' =
// autoriser et '0' = refuser, mais une ancienne discussion
// signale une confusion possible dans la documentation IBM sur
// ce point à cette époque - TESTE en environnement non productif
// avant mise en service (ex : forcer un refus et vérifier que la
// connexion est bien rejetée, pas acceptée par erreur).
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie (2 paramètres confirmés)
//--------------------------------------------------------------
dcl-pi *n;
  p_RtnCode   char(1);         // Sortie : '1' = autoriser, '0' = refuser (à tester)
  p_ExitData  char(285) value; // Entrée, PAR VALEUR : structure ZDAI0100
end-pi;

//--------------------------------------------------------------
// Gabarit des données du format ZDAI0100 (confirmé directement
// depuis la table IBM le 2026-07-13)
//--------------------------------------------------------------
dcl-ds ExitData_t qualified based(p_ExitDataPtr);
  UserProfile       char(10);   // offset 0   - Profil utilisateur appelant le serveur
  ServerId          char(10);   // offset 10  - Toujours '*SQL' pour ce point de sortie
  FormatName        char(8);    // offset 20  - Toujours 'ZDAI0100'
  RequestedFunction int(10);    // offset 28  - Seule valeur valide documentée : 0
  InterfaceType     char(63);   // offset 32  - Type d'interface de l'application appelante
  InterfaceName     char(127);  // offset 95  - Nom de l'interface de l'application appelante
  InterfaceLevel    char(63);   // offset 222 - Niveau de l'interface de l'application appelante
end-ds;                         // taille totale = 285 octets (222+63)

dcl-s p_ExitDataPtr pointer inz;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================
p_ExitDataPtr = %addr(p_ExitData);

// 1) Journalisation de la tentative de connexion (audit)
exsr LogAttempt;

// 2) Contrôle d'autorisation - politique de sécurité à définir
exsr CheckAuthorization;

// 3) Positionnement du code retour
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation
//==============================================================
begsr LogAttempt;
  // TODO : écrire ExitData_t.UserProfile,
  //        %trimr(ExitData_t.InterfaceType), %trimr(ExitData_t.InterfaceName),
  //        date/heure système dans un fichier d'audit dédié
  //        (ex: WRITE sur un fichier LOGCNXP), ou tracer via
  //        QAUDJRN / DTAARA selon le besoin. Ce format ne fournit
  //        toujours PAS l'IP du client, mais permet désormais de
  //        savoir quel type de client/interface se connecte
  //        (ODBC, JDBC, .NET...) via InterfaceType/InterfaceName.
endsr;

//==============================================================
// Sous-routine : contrôle d'autorisation
//==============================================================
begsr CheckAuthorization;
  Allowed = *on;

  // Exemple : bloquer un profil précis
  // if ExitData_t.UserProfile = 'QSECOFR';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un type d'interface précis
  // if %scan('ODBC':%trimr(ExitData_t.InterfaceType)) > 0;
  //   Allowed = *off;
  // endif;
endsr;
