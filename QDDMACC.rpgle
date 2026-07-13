**FREE
//==============================================================
// Programme de sortie : QDDMACC
// Mécanisme            : Contrôle d'accès DDM et DRDA par
//                        programme de sortie utilisateur
//                        (paramètre réseau DDMACC)
//
// A LA DIFFERENCE DE TOUS LES SQUELETTES PRECEDENTS : ce
// programme n'est PAS un point de sortie enregistré via
// WRKREGINF / la facilité d'enregistrement (pas de nom
// QIBM_Q...). Il est appelé DIRECTEMENT par le serveur DDM/DRDA
// (APPC et TCP/IP) parce qu'il est référencé par le paramètre
// réseau DDMACC, configuré ainsi :
//
//     CHGNETA DDMACC(VOTRELIB/QDDMACC)
//
// Il est appelé pour chaque requête DDM (accès distant à un
// fichier via Distributed Data Management) et pour chaque
// connexion DRDA (accès SQL distant via des middlewares DRDA
// standard, qui ne passent PAS par les points de sortie
// QZDA_INIT/NDB1/SQL2 utilisés dans les squelettes précédents -
// c'est justement pour cette raison que ce mécanisme existe).
//
// Sources (structure des paramètres corroborée par plusieurs
// documents IBM et dérivés) :
//  - https://www.ibm.com/docs/en/i/7.5.0?topic=security-drda-ddm-server-access-control-using-user-exit-programs
//  - http://www.setgetweb.com/p/i5/rbae5exitpgms.htm
//
// A CONFIRMER malgré tout avant mise en prod : les valeurs
// exactes possibles du champ FUNC selon le type de requête DDM
// (ouverture de fichier, lecture, écriture...) et DRDA (SQLCNN
// pour la connexion), qui ne sont listées ici qu'à titre
// d'exemple.
//==============================================================
ctl-opt dftactgrp(*no) actgrp(*new) option(*nodebugio:*srcstmt);

//--------------------------------------------------------------
// Interface du programme de sortie DDMACC
// (paramètres nommés, tous CHAR(10) sauf le code retour)
//--------------------------------------------------------------
dcl-pi *n;
  p_User      char(10) const;  // Profil utilisateur de la requête DDM/DRDA
  p_App       char(10) const;  // '*DDM' ou '*DRDA'
  p_Func      char(10) const;  // Fonction demandée (ex: 'SQLCNN' pour une
                                // connexion DRDA ; autres codes pour DDM)
  p_Object    char(10) const;  // Nom du fichier visé
  p_Direct    char(10) const;  // Nom de la bibliothèque visée
  p_Member    char(10) const;  // Nom du membre visé
  p_Reserved  char(10) const;  // Réservé
  p_RtnCode   char(1);         // Code retour : '1' = autoriser,
                                // toute autre valeur = refuser
end-pi;

//--------------------------------------------------------------
// Variables de travail
//--------------------------------------------------------------
dcl-s Allowed ind inz(*on);

//==============================================================
// Corps du programme
//==============================================================

// 1) Journalisation de la requête DDM/DRDA (audit)
exsr LogAttempt;

// 2) Contrôle d'accès - politique de sécurité à définir
exsr CheckDdmDrdaAccess;

// 3) Positionnement du code retour - PAS de message *ESCAPE ici,
//    le refus se fait uniquement via ce paramètre de sortie.
if Allowed;
  p_RtnCode = '1';
else;
  p_RtnCode = '0';
endif;

*inlr = *on;
return;

//==============================================================
// Sous-routine : journalisation de la requête DDM/DRDA
//==============================================================
begsr LogAttempt;
  // TODO : écrire p_User, p_App, p_Func, p_Direct, p_Object,
  //        p_Member, date/heure système dans un fichier d'audit
  //        dédié (ex: WRITE sur un fichier LOGDDMP), ou tracer
  //        via QAUDJRN / DTAARA selon le besoin. Utile pour
  //        repérer les accès DRDA venant de middlewares qui ne
  //        passent pas par QZDA_INIT/NDB1/SQL2.
endsr;

//==============================================================
// Sous-routine : règles de contrôle sur l'accès DDM/DRDA
//==============================================================
begsr CheckDdmDrdaAccess;
  Allowed = *on;

  // Exemple : bloquer l'accès à une bibliothèque sensible
  // if %trim(p_Direct) = 'PAYROLL';
  //   Allowed = *off;
  // endif;

  // Exemple : n'autoriser DRDA que pour certains profils
  // if p_App = '*DRDA' and p_User <> 'APPBATCH';
  //   Allowed = *off;
  // endif;

  // Exemple : bloquer un profil précis quel que soit le protocole
  // if p_User = 'QSECOFR';
  //   Allowed = *off;
  // endif;
endsr;
