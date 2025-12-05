<?php
// =====================================================
// upload.php sécurisé
// =====================================================

session_start();

// Vérifie le token POST
if (empty($_POST['token']) || empty($_SESSION['upload_token'])) {
    http_response_code(403);
    exit('Accès interdit (token manquant).');
}

if (!hash_equals($_SESSION['upload_token'], $_POST['token'])) {
    http_response_code(403);
    exit('Accès interdit (token invalide).');
}

// Vérifie la présence du fichier
if (!isset($_FILES['zipfile']) || $_FILES['zipfile']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    exit('Aucun fichier ZIP fourni.');
}

// Emplacement des dossiers
$uploadDir  = __DIR__ . '/uploads/';
$reportDir  = __DIR__ . '/rapports/';

if (!is_dir($uploadDir)) mkdir($uploadDir, 0755, true);
if (!is_dir($reportDir)) mkdir($reportDir, 0755, true);

// Vérifie upload
if (!isset($_FILES['zipfile']) || $_FILES['zipfile']['error'] !== UPLOAD_ERR_OK) {
    die('Erreur : aucun fichier ZIP uploadé.');
}

// Taille max (5Mo)
if ($_FILES['zipfile']['size'] > 5 * 1024 * 1024) {
    die('Erreur : le fichier ZIP dépasse la taille maximale autorisée (5 Mo).');
}

// Nom d'origine nettoyé
$originalName = basename($_FILES['zipfile']['name']);
$originalName = preg_replace('/[^A-Za-z0-9._-]/', '_', $originalName);

// Vérification extension réelle
if (!preg_match('/\.zip$/i', $originalName)) {
    die('Erreur : fichier ZIP invalide (double extension interdite).');
}

// Nom unique basé sur le nom nettoyé
$timestamp   = date('Ymd_His');
$baseName    = pathinfo($originalName, PATHINFO_FILENAME);
$uploadPath  = $uploadDir . $baseName . '_' . $timestamp . '.zip';
$extractDir  = $uploadDir . $baseName . '_' . $timestamp . '/';

mkdir($extractDir, 0755, true);

// Fonction pour supprimer le ZIP en toute sécurité
function delete_uploaded_zip($uploadPath, $uploadDir) {
    if (file_exists($uploadPath) && str_starts_with(realpath($uploadPath), realpath($uploadDir))) {
        unlink($uploadPath);
        error_log("ZIP supprimé via shutdown function : $uploadPath");
    }
}

// S'assure que le ZIP sera supprimé à la fin du script, même en cas d'erreur
register_shutdown_function('delete_uploaded_zip', $uploadPath, $uploadDir);

// Déplace le ZIP
if (!move_uploaded_file($_FILES['zipfile']['tmp_name'], $uploadPath)) {
    die('Erreur : impossible de déplacer le fichier uploadé.');
}

// =============================
//  Vérification + extraction ZIP
// =============================
$zip = new ZipArchive();

if ($zip->open($uploadPath) !== TRUE) {
    die('Erreur : impossible d’ouvrir le fichier ZIP.');
}

// Vérifie que l'archive contient au moins un fichier PHP
$containsPHP = false;

for ($i = 0; $i < $zip->numFiles; $i++) {
    $entry = $zip->getNameIndex($i);

    // Détection d'au moins un fichier PHP
    if (preg_match('/\.php$/i', $entry)) {
        $containsPHP = true;
    }

    // Directory traversal
    if (strpos($entry, '../') !== false || strpos($entry, '..\\') !== false) {
        $zip->close();
        die('Erreur : le ZIP contient des chemins non autorisés (../).');
    }

    // Chemins absolus
    if (preg_match('/^[A-Z]:/i', $entry) || substr($entry, 0, 1) === '/') {
        $zip->close();
        die('Erreur : chemins absolus interdits.');
    }
}

// Si aucun fichier PHP n’a été trouvé → rejet
if (!$containsPHP) {
    $zip->close();
    die('Erreur : l’archive doit contenir au moins un fichier PHP.');
}

for ($i = 0; $i < $zip->numFiles; $i++) {
    $entry = $zip->getNameIndex($i);

    // Directory traversal
    if (strpos($entry, '../') !== false || strpos($entry, '..\\') !== false) {
        $zip->close();
        die('Erreur : le ZIP contient des chemins non autorisés (../).');
    }

    // Chemins absolus
    if (preg_match('/^[A-Z]:/i', $entry) || substr($entry, 0, 1) === '/') {
        $zip->close();
        die('Erreur : chemins absolus interdits.');
    }
}

$zip->extractTo($extractDir);
$zip->close();

// ===================================
// Nettoyage post-extraction
// ===================================
$allowedExtensions = ['php','html','htm','css','js','txt','json','xml'];

$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($extractDir));

foreach ($rii as $file) {
    if ($file->isDir()) continue;

    $ext = strtolower(pathinfo($file->getPathname(), PATHINFO_EXTENSION));

    if (!in_array($ext, $allowedExtensions)) {
        unlink($file->getPathname());
    }
}

// =============================
// Appel du scanner
// =============================
define('SCANNER_ENTRY', true);
include __DIR__ . '/scanner.php';
$results = scan_project($extractDir);

// Sauvegarde JSON
$reportFile = $reportDir . 'rapport_' . $baseName . '_' . $timestamp . '.json';
file_put_contents($reportFile, json_encode($results, JSON_PRETTY_PRINT));

// =============================
// Suppression du ZIP + dossier extrait
// =============================

// Fonction récursive très sécurisée pour supprimer un dossier complet
function rrmdir_secure($dir, $allowedBase, $log = true) {
    // Vérifie que le dossier n’est pas vide et qu’il existe
    if (empty($dir) || !is_dir($dir)) return;

    // Résout le chemin réel pour éviter les symlinks et path traversal
    $realDir  = realpath($dir);
    $realBase = realpath($allowedBase);

    if ($realDir === false || $realBase === false) return;

    // Vérifie que le dossier est bien à l’intérieur du dossier autorisé
    if (!str_starts_with($realDir, $realBase)) {
        if ($log) error_log("Tentative de suppression interdite : $realDir en dehors de $realBase");
        return; // on n’y touche pas
    }

    // Parcours récursif
    $files = array_diff(scandir($realDir), ['.', '..']);
    foreach ($files as $file) {
        $path = "$realDir/$file";
        if (is_dir($path)) {
            rrmdir_secure($path, $allowedBase, $log);
        } else {
            unlink($path);
            if ($log) error_log("Fichier supprimé : $path");
        }
    }

    // Supprime le dossier lui-même
    rmdir($realDir);
    if ($log) error_log("Dossier supprimé : $realDir");
}

// Supprime le dossier extrait en toute sécurité
rrmdir_secure($extractDir, $uploadDir);

// Redirection
header('Location: rapport.php?file=' . urlencode(basename($reportFile)));
exit;