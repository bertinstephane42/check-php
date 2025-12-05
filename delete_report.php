<?php
// =====================================================
// delete_report.php
// Supprime un rapport JSON spécifique généré par l'utilisateur
// Sécurisé et compatible avec rapport.php
// =====================================================

session_start();

// Vérifie la méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo 'Méthode non autorisée';
    exit;
}

// Vérifie que le fichier à supprimer est précisé en POST
if (!isset($_POST['file'])) {
    http_response_code(400);
    echo 'Paramètre "file" manquant';
    exit;
}

// Récupère le nom du fichier et nettoie
$fileName = basename($_POST['file']); // évite les traversals ../
$reportDir = __DIR__ . '/rapports/';
$reportPath = realpath($reportDir . $fileName);

// Vérifie que le fichier existe et qu'il est bien dans le dossier rapports
if ($reportPath === false || !str_starts_with($reportPath, realpath($reportDir))) {
    http_response_code(404);
    echo 'Fichier introuvable ou non autorisé';
    exit;
}

// Supprime le fichier
if (unlink($reportPath)) {
    http_response_code(200);
    echo 'Rapport supprimé avec succès';
} else {
    http_response_code(500);
    echo 'Erreur lors de la suppression';
}
?>