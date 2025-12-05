<?php
// =====================================================
// rapport.php
// Affichage du rapport HTML depuis le JSON généré
// Compatible OWASP 2021 avec tri et filtres interactifs
// =====================================================

$reportDir = __DIR__ . '/rapports/';

// Vérifie la présence du paramètre 'file'
if (!isset($_GET['file'])) {
    die('Erreur : aucun rapport spécifié.');
}

$reportFile = $reportDir . basename($_GET['file']);

// Réécrit le JSON en UTF-8 lisible
rewriteJsonUtf8($reportFile);

// Vérifie que le fichier existe
if (!file_exists($reportFile)) {
    die('Erreur : le fichier de rapport est introuvable.');
}

// Charge les résultats JSON
$json = file_get_contents($reportFile);
$results = json_decode($json, true);

usort($results, function($a, $b){
    return strcmp($a['id'] ?? '', $b['id'] ?? '');
});

// ------------------------------------------------------
// Fonctions utilitaires
// ------------------------------------------------------
function severityClass($severity) {
    switch (strtolower($severity)) {
        case 'high': return 'high';
        case 'medium': return 'medium';
        case 'low': return 'low';
        case 'info': return 'info';
        default: return '';
    }
}

function formatAdvice($item) {
    $advice = $item['advice'] ?? '';

    switch (strtolower($item['severity'])) {
        case 'high':
            $advice .= " ⚠️ À corriger en priorité pour éviter une exploitation critique.";
            break;
        case 'medium':
            $advice .= " À revoir pour réduire le risque de vulnérabilité.";
            break;
        case 'low':
            $advice .= " À surveiller, risque faible mais potentiel.";
            break;
        case 'info':
            $advice .= " Information utile pour le code propre et sécurisé.";
            break;
    }

    $msg = $item['message'] ?? '';
    if (stripos($msg, 'SQL') !== false) {
        $advice .= " Utiliser des requêtes préparées ou ORM pour sécuriser la base de données.";
    } elseif (stripos($msg, 'XSS') !== false) {
        $advice .= " Toujours échapper les données utilisateur avec htmlspecialchars() ou filter_var().";
    } elseif (stripos($msg, 'include') !== false) {
        $advice .= " Vérifier la source du fichier et utiliser des chemins absolus sécurisés.";
    } elseif (stripos($msg, 'eval') !== false) {
        $advice .= " Remplacer par des fonctions fixes et éviter l’exécution dynamique de code.";
    }

    return htmlspecialchars($advice);
}

// ------------------------------------------------------
// Réécriture du JSON pour conserver les caractères UTF-8
// ------------------------------------------------------
function rewriteJsonUtf8($file) {
    $json = @file_get_contents($file);
    if ($json === false) return;

    $data = json_decode($json, true);
    if ($data !== null) {
        file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'audit PHP - OWASP 2021</title>
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
</style>
</head>
<body>
<div class="container">
<h1>Rapport d'audit PHP - OWASP 2021</h1>

<p>
    <a href="<?= htmlspecialchars('rapports/' . basename($_GET['file'])) ?>" download="<?= htmlspecialchars(basename($_GET['file'])) ?>">
        <button type="button">Télécharger le rapport JSON</button>
    </a>
    <a href="index.php">
        <button type="button">Retour à l'accueil</button>
    </a>
	<!-- Bouton Aide -->
	<button type="button" id="helpBtn">Aide</button>
</p>

<?php if (empty($results)): ?>
    <p>Aucune vulnérabilité détectée.</p>
<?php else: ?>
    <div>
        <label>Filtrer par gravité :
            <select id="filterSeverity">
                <option value="">Toutes</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
            </select>
        </label>
        <label>Filtrer par mot-clé :
            <input type="text" id="filterKeyword" placeholder="SQL, XSS, eval...">
        </label>
    </div>

    <table id="reportTable">
        <thead>
            <tr>
                <th data-sort="id">ID</th>
                <th data-sort="file">Fichier</th>
                <th data-sort="line">Ligne</th>
                <th data-sort="severity">Gravité</th>
                <th data-sort="message">Vulnérabilité</th>
                <th>Extrait de code</th>
                <th>Conseil</th>
                <th data-sort="size">Taille fichier</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($results as $item): ?>
                <tr class="<?= severityClass($item['severity']) ?>">
                    <td><?= htmlspecialchars(is_scalar($item['id']) ? $item['id'] : '-') ?></td>
					<td><?= htmlspecialchars(is_scalar($item['file']) ? $item['file'] : '-') ?></td>
					<td><?= htmlspecialchars(is_numeric($item['line']) ? $item['line'] : '-') ?></td>
					<td><?= htmlspecialchars(ucfirst(is_scalar($item['severity']) ? $item['severity'] : '-')) ?></td>
					<td><?= htmlspecialchars(is_scalar($item['message']) ? $item['message'] : '-') ?></td>
                    <td><pre><?= htmlspecialchars($item['excerpt']) ?></pre></td>
                    <td><?= formatAdvice($item) ?></td>
                    <td><?= isset($item['size']) ? htmlspecialchars($item['size']) . ' bytes' : '-' ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>
</div>

<!-- Modale d'aide -->
<div id="helpModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; 
     background:rgba(0,0,0,0.5); z-index:1000; justify-content:center; align-items:center;">
    <div style="background:#fff; padding:20px; max-width:600px; width:90%; border-radius:10px; position:relative;">
        <h2>Aide - Utilisation du rapport</h2>
        <p><strong>Tri par colonne :</strong> Cliquez sur l'entête d'une colonne (ID, Fichier, Gravité, etc.) pour trier les résultats. Cliquez à nouveau pour inverser l'ordre.</p>
        <p><strong>Filtre par gravité :</strong> Sélectionnez la gravité (High, Medium, Low, Info) pour ne voir que les vulnérabilités correspondantes.</p>
        <p><strong>Filtre par mot-clé :</strong> Saisissez un mot-clé (SQL, XSS, eval...) pour filtrer les vulnérabilités contenant ce terme.</p>
        <p><strong>Utilité :</strong> Ces fonctions permettent de prioriser et analyser rapidement les vulnérabilités selon leur criticité et type. En entreprise, cela correspond à un processus OWASP 2021 de gestion et traitement des vulnérabilités pour sécuriser le code et réduire les risques d’exploitation.</p>
        <button id="closeHelp" style="margin-top:10px;">Fermer</button>
    </div>
</div>

<script>
// ------------------------------------------------------
// Tri des colonnes
// ------------------------------------------------------
document.querySelectorAll('#reportTable th[data-sort]').forEach(function(th) {
    th.addEventListener('click', function() {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const index = Array.from(th.parentNode.children).indexOf(th);
        const type = th.dataset.sort;
        const rows = Array.from(tbody.querySelectorAll('tr'));

        let asc = !th.asc;
        th.asc = asc;

        rows.sort((a, b) => {
            let aText = a.children[index].innerText.toLowerCase();
            let bText = b.children[index].innerText.toLowerCase();

            if (!isNaN(parseFloat(aText)) && !isNaN(parseFloat(bText))) {
                return asc ? aText - bText : bText - aText;
            } else {
                return asc ? aText.localeCompare(bText) : bText.localeCompare(aText);
            }
        });

        rows.forEach(row => tbody.appendChild(row));
    });
});

// ------------------------------------------------------
// Filtres interactifs
// ------------------------------------------------------
const filterSeverity = document.getElementById('filterSeverity');
const filterKeyword = document.getElementById('filterKeyword');
const tableRows = document.querySelectorAll('#reportTable tbody tr');

function applyFilters() {
    const severityVal = filterSeverity.value.toLowerCase();
    const keywordVal = filterKeyword.value.toLowerCase();

    tableRows.forEach(row => {
        const severity = row.children[3].innerText.toLowerCase();
        const message = row.children[4].innerText.toLowerCase();
        const show = (severityVal === '' || severity === severityVal)
                     && (keywordVal === '' || message.includes(keywordVal));
        row.style.display = show ? '' : 'none';
    });
}

filterSeverity.addEventListener('change', applyFilters);
filterKeyword.addEventListener('input', applyFilters);

// ------------------------------------------------------
// Gestion de la modale d'aide
// ------------------------------------------------------
const helpBtn = document.getElementById('helpBtn');
const helpModal = document.getElementById('helpModal');
const closeHelp = document.getElementById('closeHelp');

helpBtn.addEventListener('click', () => {
    helpModal.style.display = 'flex';
});

closeHelp.addEventListener('click', () => {
    helpModal.style.display = 'none';
});

// Fermer si clic en dehors de la modale
helpModal.addEventListener('click', (e) => {
    if (e.target === helpModal) {
        helpModal.style.display = 'none';
    }
});

// ------------------------------------------------------
// Supprime le rapport JSON après le clic sur "Télécharger"
// ------------------------------------------------------
const downloadBtn = document.querySelector('a[href$="<?= addslashes(basename($_GET['file'])) ?>"] button');
const reportFile = "<?= addslashes(basename($_GET['file'])) ?>";

if (downloadBtn && localStorage.getItem('delete_json') === '1') {
    downloadBtn.addEventListener('click', () => {
        fetch('delete_report.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'file=' + encodeURIComponent(reportFile)
        })
        .then(response => {
            if (response.ok) {
                console.log('Rapport supprimé sur le serveur après téléchargement.');
                localStorage.removeItem('delete_json');
            } else {
                console.error('Erreur lors de la suppression du rapport.');
            }
        })
        .catch(err => console.error('Erreur lors de la suppression :', err));
    });
}
</script>
</body>
</html>