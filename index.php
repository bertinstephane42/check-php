<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Audit de sécurité PHP - OWASP Top 10 2021</title>
<style>
body { font-family: Arial, sans-serif; padding: 20px; background: #f4f4f4; color: #333; }
h1 { text-align: center; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #fff; }
th, td { padding: 10px; border: 1px solid #ccc; text-align: left; vertical-align: top; cursor: default; }
th { background-color: #eee; cursor: pointer; }
.high { background-color: #f8d7da; color: #721c24; }
.medium { background-color: #fff3cd; color: #856404; }
.low { background-color: #fffbe6; color: #665500; }
.info { background-color: #d1ecf1; color: #0c5460; }
pre { margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: Consolas, monospace; }
.container { max-width: 1200px; margin: 0 auto; }
button { padding: 10px 15px; margin: 5px; font-size: 1rem; cursor: pointer; }
button:hover { opacity: 0.9; }
input, select { padding: 5px; margin: 5px; font-size: 1rem; }
.result { border:1px solid #ddd; margin:10px 0; padding:10px; border-radius:8px; background: #fff; }

.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0; top: 0;
    width: 100%; height: 100%;
    overflow: auto;
    background-color: rgba(0,0,0,0.5);
}
.modal-content {
    background-color: #fff;
    margin: 15% auto;
    padding: 20px;
    border-radius: 8px;
    max-width: 600px;
    box-shadow: 0 0 10px rgba(0,0,0,0.3);
}
.close-btn {
    float: right;
    font-size: 1.2rem;
    font-weight: bold;
    cursor: pointer;
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
        <input type="checkbox" id="delete_report" name="delete_report">
        <label for="delete_report">Supprimer le rapport du serveur après téléchargement</label>
    </div>

    <button type="submit">Analyser le projet</button>
    <button type="button" id="helpBtn">Aide</button>
</form>

<div id="results"></div>
</div>

<!-- Modale d'aide -->
<div id="helpModal" class="modal">
    <div class="modal-content">
        <span class="close-btn" id="closeHelp">&times;</span>
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
    </div>
</div>

<script>
// Gestion de la modale d'aide
const helpBtn = document.getElementById('helpBtn');
const modal = document.getElementById('helpModal');
const closeBtn = document.getElementById('closeHelp');

helpBtn.onclick = () => modal.style.display = 'block';
closeBtn.onclick = () => modal.style.display = 'none';
window.onclick = (e) => { if(e.target === modal) modal.style.display = 'none'; }

// Gestion du stockage local pour la case à cocher
const deleteCheckbox = document.getElementById('delete_report');

// Initialiser la checkbox en fonction du localStorage
if (localStorage.getItem('delete_json') === '1') {
    deleteCheckbox.checked = true;
}

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