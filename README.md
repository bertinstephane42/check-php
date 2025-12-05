# PHP Security Audit Scanner

## Présentation

Le projet **PHP Security Audit Scanner** est un outil d'analyse automatisée des projets PHP, conçu pour détecter les vulnérabilités et non-conformités par rapport aux bonnes pratiques de sécurité OWASP 2021. Il permet aux développeurs et équipes de sécurité de :

- Identifier rapidement les risques liés au code PHP.
- Générer des rapports détaillés au format JSON pour un suivi et un audit.
- Maintenir la conformité aux recommandations de sécurité modernes.

## Fonctionnalités principales

- Analyse automatique des fichiers PHP contenus dans une archive ZIP.
- Vérification des bonnes pratiques et détection de vulnérabilités selon OWASP Top 10 2021.
- Extraction sécurisée des archives et contrôle strict des chemins pour éviter les attaques de type path traversal.
- Suppression automatique des fichiers uploadés pour garantir la confidentialité.
- Rapport JSON détaillé avec niveau de gravité et description des vulnérabilités.
- Interface web simple et sécurisée pour soumettre des archives.

## Installation

1. Cloner le dépôt sur votre serveur web PHP :  
```bash
   git clone https://github.com/bertinstephane42/check-php.git
```

2. Assurer que PHP 7.4 ou supérieur est installé.
3. Vérifier que les dossiers `uploads/` et `rapports/` sont accessibles en écriture par le serveur web.

## Utilisation

1. Accéder à la page `index.php` via un navigateur web.
2. Sélectionner une archive ZIP contenant votre projet PHP.
3. Soumettre l’archive pour analyse.
4. Télécharger le rapport JSON généré ou visualiser les résultats.

## Sécurité et confidentialité

* Les archives ZIP uploadées sont supprimées automatiquement après traitement pour garantir la confidentialité.
* Le scanner ne conserve pas de copies temporaires du code source en dehors du dossier `uploads/`.
* Toutes les opérations sont effectuées en respectant les recommandations de sécurité PHP modernes.

## Contribuer

Les contributions sont les bienvenues pour améliorer la détection de vulnérabilités et enrichir le scanner :

1. Forker le dépôt.
2. Créer une branche pour votre fonctionnalité ou correctif.
3. Soumettre une pull request détaillant les changements effectués.


