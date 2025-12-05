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
button:hover { opacity: 0.9; }
input, select { padding: 5px; margin: 5px; font-size: 1rem; }
/* Boutons généraux */
button { 
    padding: 10px 15px; 
    font-size: 1rem; 
    cursor: pointer; 
    border: none;
    border-radius: 5px;
    background-color: #ffffff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.15);
}
button:hover { opacity: 0.9; }

/* Conteneur des boutons */
p { 
    display: flex; 
    gap: 10px; 
    flex-wrap: wrap; 
    margin-bottom: 20px;
}
p button { margin: 0; }

/* Bouton Retour */
.btn-retour {
    background-color: #e3e7eb;
    color: #1a2a33;
}

/* Bouton Aide */
.btn-help {
    background-color: #1976d2;
    color: white;
}

/* Bouton Télécharger */
#downloadBtn {
    background-color: #4caf50;
    color: white;
}

/* Bouton Exporter données filtrées */
#exportFilteredBtn {
    background-color: #ff9800;
    color: white;
}
/* --- Modale d'aide --- */
#helpModal {
    display: none;
    position: fixed;
    top: 0; 
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.45);
    z-index: 1000;

    /* centrer uniquement quand elle est affichée */
    justify-content: center;
    align-items: center;
}

/* Contenu de la fenêtre modale */
.help-content {
    background: #ffffff;
    padding: 25px 30px;
    max-width: 600px;
    width: 90%;
    border-radius: 12px;

    /* cohérence visuelle : même style que tables et boutons */
    box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    position: relative;
    animation: fadeInModal 0.25s ease-out;
}

/* Animation douce d'apparition */
@keyframes fadeInModal {
    from { opacity: 0; transform: translateY(-10px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* Titre cohérent */
.help-content h2 {
    margin-top: 0;
    color: #333;
    text-align: center;
    margin-bottom: 15px;
}

/* Paragraphes plus lisibles */
.help-content p {
    line-height: 1.5;
    margin-bottom: 12px;
    font-size: 0.95rem;
}

/* Style du bouton "Fermer" cohérent */
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

#closeHelp:hover {
    opacity: 0.9;
}

/* Conteneur principal : réduire au minimum les marges pour plus de place au tableau */
.container {
    max-width: 95%;       /* occupe toute la largeur disponible */
    margin: 0 auto;
    padding-left: 10px;     /* marge minimale à gauche */
    padding-right: 10px;    /* marge minimale à droite */
}

/* Table : conserver la largeur fixe des colonnes */
table {
    width: 100%;
    table-layout: fixed;  
    word-wrap: break-word;
    overflow-x: auto;      /* scroll horizontal si nécessaire */
}
</style>
</head>
<body>
<div class="container">
<h1>Rapport d'audit PHP - OWASP 2021</h1>

<p>
    <a id="downloadLink" href="<?= htmlspecialchars('rapports/' . basename($_GET['file'])) ?>" 
       download="<?= htmlspecialchars(basename($_GET['file'])) ?>">
        <button type="button" id="downloadBtn">Télécharger le rapport JSON</button>
    </a>

    <button type="button" id="exportFilteredBtn">Exporter les données filtrées</button>

    <a href="index.php">
        <button type="button" class="btn-retour">Retour à l'accueil</button>
    </a>

    <button type="button" class="btn-help" id="helpBtn">Aide</button>
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
					<td>
					<?= htmlspecialchars(
						is_scalar($item['file'])
							? preg_replace('#^.*/uploads/[^/]+/#', '', $item['file'])
							: '-'
					) ?>
					</td>
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
<div id="helpModal">
    <div class="help-content">
        <h2>Aide – Utilisation du rapport</h2>

        <p><strong>Tri par colonne :</strong> Cliquez sur l’en-tête d’une colonne (ID, Fichier, Gravité, etc.) pour trier les résultats. Cliquez à nouveau pour inverser l’ordre.</p>

        <p><strong>Filtre par gravité :</strong> Sélectionnez la gravité (High, Medium, Low, Info) pour ne voir que les vulnérabilités correspondantes.</p>

        <p><strong>Filtre par mot-clé :</strong> Saisissez un mot-clé (SQL, XSS, eval...) pour filtrer les vulnérabilités contenant ce terme.</p>

        <p><strong>Utilité :</strong> Ces fonctions permettent de prioriser et analyser rapidement les vulnérabilités selon leur criticité. Cela s’inscrit dans une démarche OWASP 2021 pour identifier, classer et réduire les risques d’exploitation liés au code.</p>

        <button id="closeHelp">Fermer</button>
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
// Gestion du téléchargement et suppression conditionnelle
// ------------------------------------------------------
const downloadBtn = document.querySelector('a[href$="<?= addslashes(basename($_GET['file'])) ?>"] button');
const reportFile = "<?= addslashes(basename($_GET['file'])) ?>";

// Vérifie si la case "Supprimer le rapport" est cochée au moment du clic
if (downloadBtn) {
    downloadBtn.addEventListener('click', () => {
        const deleteJson = localStorage.getItem('delete_json') === '1';

        if (deleteJson) {
            // Désactive le bouton après le clic
            downloadBtn.disabled = true;
            downloadBtn.style.opacity = 0.5;
            downloadBtn.title = "Le rapport a été téléchargé et sera supprimé du serveur.";

            // Suppression côté serveur
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
        }
        // Sinon, le bouton reste actif et le téléchargement se fait normalement
    });
}

// ------------------------------------------------------
// Exporter les données filtrées
// ------------------------------------------------------
const exportFilteredBtn = document.getElementById('exportFilteredBtn');

exportFilteredBtn.addEventListener('click', () => {
    if (!confirm("Voulez-vous vraiment télécharger les données filtrées ?")) {
        return;
    }

    const filteredRows = Array.from(tableRows).filter(row => row.style.display !== 'none');

    const filteredData = filteredRows.map(row => {
        return {
            id: row.children[0].innerText,
            file: row.children[1].innerText,
            line: row.children[2].innerText,
            severity: row.children[3].innerText.toLowerCase(),
            message: row.children[4].innerText,
            excerpt: row.children[5].innerText,
            advice: row.children[6].innerText,
            size: row.children[7].innerText.replace(' bytes','') || null
        };
    });

    const blob = new Blob([JSON.stringify(filteredData, null, 4)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = "rapport_filtré_<?= addslashes(basename($_GET['file'])) ?>";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});
</script>
</body>
</html>