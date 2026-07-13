**FREE
//==============================================================
// CE FICHIER EST OBSOLETE - CORRECTION DU 2026-07-10
//
// "QIBM_QNPSERVR" n'est pas un nom de point de sortie valide.
// C'est en réalité l'IDENTIFIANT SERVEUR interne (champ
// ServerId = 'QNPSERVR' dans les structures de données), pas le
// nom du point de sortie à enregistrer via WRKREGINF.
//
// Le Network Print Server expose en réalité DEUX points de
// sortie distincts, corrigés dans deux fichiers séparés :
//
//   - QIBM_QNPS_ENTRY (format ENTR0100) -> voir QNPSENTR.rpgle
//     Contrôle l'accès au serveur d'impression lui-même.
//
//   - QIBM_QNPS_SPLF (format SPLF0100) -> voir QNPSSPLF.rpgle
//     Contrôle le traitement d'un fichier spoule existant
//     (ex : envoi vers un service de fax réseau).
//
// Ce fichier est conservé vide à titre indicatif ; utilise les
// deux fichiers ci-dessus à sa place.
//==============================================================
