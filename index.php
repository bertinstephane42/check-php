<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Audit de sécurité PHP - OWASP Top 10 2021</title>
<style>
/* ---------------------------------------------
   STYLE GLOBAL — Cohérent avec rapport.php
--------------------------------------------- */
body { 
    font-family: Arial, sans-serif; 
    padding: 20px; 
    background: #f4f4f4; 
    color: #333; 
}
h1 { 
    text-align: center; 
}

/* Conteneur principal */
.container { 
    max-width: 1200px; 
    margin: 0 auto; 
    background: #fff;
    padding: 25px 30px;
    border-radius: 10px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.15);
}

/* Boutons — mêmes styles que rapport.php */
button { 
    padding: 10px 15px; 
    font-size: 1rem; 
    cursor: pointer; 
    border: none;
    border-radius: 5px;
    background-color: #ffffff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.15);
    transition: 0.2s;
}
button:hover { opacity: 0.9; }

/* Bouton Aide */
#helpBtn {
    background-color: #1976d2;
    color: white;
}

/* Bouton Analyser */
button[type="submit"] {
    background-color: #4caf50;
    color: white;
}

/* Fichier + select */
input, select { 
    padding: 5px; 
    margin: 5px 0; 
    font-size: 1rem; 
}

/* Encadré des règles détectées */
.rule-info {
    display:inline-block; 
    padding:8px 12px; 
    background:#eef2f5; 
    border-left:4px solid #007bff; 
    border-radius:4px; 
    color:#333; 
    font-size:14px; 
    font-weight:500;
    margin-bottom: 20px;
}

/* Zones d’affichage des résultats */
.result { 
    border:1px solid #ddd; 
    margin:10px 0; 
    padding:10px; 
    border-radius:8px; 
    background: #fff; 
}

/* ---------------------------------------------
   MODALE AIDE — Identique et cohérente rapport.php
--------------------------------------------- */
#helpModal {
    display: none; /* reste cachée au chargement */
    position: fixed;
    top: 0; 
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.45);
    z-index: 1000;

    /* pas de display:flex ici ! */
    justify-content: center;
    align-items: center;
}


.modal-content {
    background-color: #fff;
    padding: 25px 30px;
    max-width: 600px;
    width: 90%;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    animation: fadeInModal 0.25s ease-out;
    position: relative;
}

/* Animation douce d’apparition */
@keyframes fadeInModal {
    from { opacity: 0; transform: translateY(-10px); }
    to   { opacity: 1; transform: translateY(0); }
}

.modal-content h2 {
    margin-top: 0;
    color: #333;
    text-align: center;
    margin-bottom: 15px;
}

/* Bouton de fermeture */
#closeHelp {
    background-color: #1976d2;
    color: white;
    border: none;
    padding: 10px 15px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1rem;
    display: block;
    margin: 15px auto 0; /* centré */
}

.modal-content p {
    line-height: 1.5;
    margin-bottom: 12px;
    font-size: 0.95rem;
}

.modal-content ul {
    margin-left: 20px;
}
</style>
</head>
<body>

<div class="container">
<h1>Audit de sécurité PHP - OWASP Top 10 2021</h1>

<?php 
session_start();

// Génère un nouveau token **uniquement si aucun token n’existe déjà**
if (!isset($_SESSION['upload_token'])) {
    $_SESSION['upload_token'] = bin2hex(random_bytes(32));
}
$token = $_SESSION['upload_token'];
define('SCANNER_ENTRY', true);
require_once 'scanner.php';
$nbRules = is_array($rules) ? count($rules) : 0;
echo "<div style='display:inline-block; padding:8px 12px; margin-top:10px; background:#eef2f5; border-left:4px solid #007bff; border-radius:4px; color:#333; font-size:14px; font-weight:500;'>
        $nbRules règles de détection OWASP
      </div>";

?>

<form action="upload.php" method="post" enctype="multipart/form-data">
    <p>Sélectionnez une archive ZIP contenant votre projet PHP :</p>
    <input type="file" id="zipfile" name="zipfile" accept=".zip" required>
    <input type="hidden" name="token" value="<?php echo $_SESSION['upload_token']; ?>">
    
	<div style="margin:10px 0;">
		<label for="delete_report">
			<input type="checkbox" id="delete_report" name="delete_report" checked>
			Supprimer le rapport du serveur après téléchargement
		</label>
	</div>

    <button type="submit">Analyser le projet</button>
    <button type="button" id="helpBtn">Aide</button>
</form>

<div id="results"></div>
</div>

<!-- Modale d'aide -->
<div id="helpModal" class="modal">
    <div class="modal-content">
        <h2>À propos de la confidentialité et suppression des rapports</h2>
        <p>
            Toutes les informations envoyées sont traitées uniquement pour générer le rapport. 
            L’archive ZIP que vous envoyez est supprimée immédiatement après l’analyse afin d’éviter toute récupération pour des raisons de droit d’auteur.
        </p>
        <p>
            Le rapport généré reste disponible sur le serveur tant que vous ne choisissez pas de le supprimer.
        </p>
        <p>
            Pour supprimer le rapport JSON du serveur après l’avoir téléchargé, cochez l’option 
            <strong>« Supprimer le rapport du serveur après téléchargement »</strong> avant de lancer le téléchargement. 
            Si cette case n’est pas cochée, le rapport restera disponible sur le serveur jusqu’à suppression manuelle.
        </p>
        <p>
            Cette fonctionnalité vous permet de contrôler la confidentialité et la disponibilité de vos rapports générés.
        </p>

        <!-- Encadré OWASP 2021 -->
        <div style="margin-top:20px; padding:15px; border:1px solid #ccc; border-radius:5px; background-color:#f9f9f9;">
            <h3>Introduction à OWASP 2021</h3>
            <p>
                OWASP (Open Web Application Security Project) publie régulièrement une liste des risques de sécurité majeurs pour les applications web. 
                La version 2021 identifie les 10 principales vulnérabilités auxquelles il faut être attentif, comme l’injection, la mauvaise gestion de l’authentification, ou l’exposition de données sensibles.
            </p>
            <p>
                Comprendre et utiliser OWASP 2021 permet aux développeurs et aux analystes de :
            </p>
            <ul>
                <li>Identifier et prioriser les failles critiques dans les applications.</li>
                <li>Mettre en place des pratiques de codage sécurisées.</li>
                <li>Réduire les risques d’exploitation par des attaquants.</li>
            </ul>
            <p>
                Dans le cadre de ce TP, le rapport généré vous aide à détecter certaines vulnérabilités alignées avec OWASP 2021 pour apprendre à les corriger.
            </p>
        </div>
		<button id="closeHelp">Fermer</button>
    </div>
</div>

<script>
// Gestion de la modale d'aide
const helpBtn = document.getElementById('helpBtn');
const modal = document.getElementById('helpModal');
const closeBtn = document.getElementById('closeHelp');

helpBtn.onclick = () => {
    modal.style.display = "flex"; // AU LIEU DE "block"
};

closeBtn.onclick = () => modal.style.display = "none";

window.onclick = (e) => {
    if (e.target === modal) modal.style.display = "none";
};

// Gestion du stockage local pour la case à cocher
const deleteCheckbox = document.getElementById('delete_report');

// Initialiser la checkbox en fonction du localStorage ou de l'état par défaut
if (localStorage.getItem('delete_json') === '1' || deleteCheckbox.checked) {
    deleteCheckbox.checked = true;
    localStorage.setItem('delete_json', '1'); // synchronise le localStorage avec le comportement par défaut
} else {
    deleteCheckbox.checked = false;
}

// Écouteur de changement
deleteCheckbox.addEventListener('change', () => {
    if (deleteCheckbox.checked) {
        localStorage.setItem('delete_json', '1');
    } else {
        localStorage.removeItem('delete_json');
    }
});

// Vider le champ zipfile à chaque rechargement de page
window.addEventListener('load', () => {
    const zipInput = document.getElementById('zipfile');
    if (zipInput) zipInput.value = '';
});
</script>

</body>
</html>