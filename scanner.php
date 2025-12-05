<?php

// Empêche l'exécution directe du script
if (!defined('SCANNER_ENTRY')) {
    http_response_code(403);
    die('Accès direct interdit');
}

    // ============================================
    // 1. REGLES (régex et heuristiques)
    // ============================================
	$rules = [

		// =====================================================
		//  OWASP A1 – Injection (RCE, SQLi, Command Injection)
		// =====================================================

		// 1. Exécution de code PHP via eval()
		[
			'id' => 'EVAL_USAGE',
			'regex' => '/\beval\s*\(/i',
			'level' => 'high',
			'message' => 'Usage dangereux de eval() — OWASP A1: Injection. Toujours éviter. Utiliser un mapping de fonctions autorisées ou alternatives sûres.'
		],

		// 2. assert() interprétant potentiellement du code
		[
			'id' => 'ASSERT_CODE_EXEC',
			'regex' => '/\bassert\s*\(/i',
			'level' => 'high',
			'message' => 'assert() peut exécuter du code si la chaîne est manipulée — OWASP A1. Remplacer par des alternatives sûres.'
		],

		// 3. Commandes système critiques
		[
			'id' => 'SYSTEM_COMMANDS',
			'regex' => '/\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i',
			'level' => 'high',
			'message' => 'Appel système critique — OWASP A1: Command Injection. Utiliser wrapper sécurisé et escapeshellcmd().'
		],

		// 4. Appels dynamiques via call_user_func avec input utilisateur
		[
			'id' => 'CALL_USER_FUNC_INPUT',
			'regex' => '/\bcall_user_func\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Appel dynamique contrôlé par l’utilisateur — OWASP A1. Utiliser une whitelist stricte.'
		],

		// 5. Appels dynamiques via call_user_func_array avec input utilisateur
		[
			'id' => 'CALL_USER_FUNC_ARRAY_INPUT',
			'regex' => '/\bcall_user_func_array\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Appel dynamique array contrôlé par l’utilisateur — OWASP A1. Toujours vérifier les paramètres.'
		],

		// 6. Variables variables
		[
			'id' => 'VARIABLE_VARIABLES_USER',
			'regex' => '/\$\s*\{\s*\$_(GET|POST|REQUEST|COOKIE)\s*\}/i',
			'level' => 'medium',
			'message' => 'Variables variables provenant de l’utilisateur — OWASP A1. Utiliser tableau associatif au lieu de noms dynamiques.'
		],

		// 7. create_function() obsolète
		[
			'id' => 'CREATE_FUNCTION_OBSOLETE',
			'regex' => '/\bcreate_function\s*\(/i',
			'level' => 'high',
			'message' => 'create_function() obsolète et dangereux — OWASP A1. Remplacer par closure anonyme.'
		],

		// 8. Requête SQL construite avec input utilisateur
		[
			'id' => 'SQL_INJECTION',
			'regex' => '/mysqli_query\s*\(\s*[^,]+,\s*["\'].*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Requête SQL construite avec données utilisateur — OWASP A1: SQL Injection. Toujours utiliser requêtes préparées.'
		],

		// =====================================================
		//  OWASP A2 – Broken Authentication / Session
		// =====================================================

		// 9. session_start() avec session_id externe
		[
			'id' => 'SESSION_START_EXTERNAL_ID',
			'regex' => '/session_start\s*\(.*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'session_start() avec session_id externe — OWASP A2. Désactiver session.use_trans_sid, activer strict_mode.'
		],

		// 10. setcookie() basé sur input utilisateur
		[
			'id' => 'SETCOOKIE_USER_INPUT',
			'regex' => '/\bsetcookie\s*\(.*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'setcookie() contrôlé par l’utilisateur — OWASP A2. Toujours utiliser httponly, secure et samesite=strict.'
		],

		// =====================================================
		//  OWASP A3 – Sensitive Data Exposure
		// =====================================================

		// 11. md5() obsolète
		[
			'id' => 'MD5_OBSOLETE',
			'regex' => '/\bmd5\s*\(/i',
			'level' => 'low',
			'message' => 'md5() est obsolète — OWASP A3. Remplacer par password_hash() ou hash("sha256").'
		],

		// 12. sha1() obsolète
		[
			'id' => 'SHA1_OBSOLETE',
			'regex' => '/\bsha1\s*\(/i',
			'level' => 'low',
			'message' => 'sha1() est obsolète — OWASP A3. Remplacer par hash("sha256") ou hash("sha512").'
		],

		// =====================================================
		//  OWASP A4 – XXE / File Processing
		// =====================================================

		// 13. file_get_contents() avec input utilisateur
		[
			'id' => 'FILE_GET_CONTENTS_USER',
			'regex' => '/file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'Lecture de fichier basée sur input externe — OWASP A4. Imposer dossier racine et whitelist des fichiers.'
		],

		// 14. file_put_contents() avec input utilisateur
		[
			'id' => 'FILE_PUT_CONTENTS_USER',
			'regex' => '/file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Écriture de fichier basée sur input externe — OWASP A4. Valider et normaliser le chemin.'
		],

		// 15. fopen() avec input utilisateur
		[
			'id' => 'FOPEN_USER_INPUT',
			'regex' => '/fopen\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'Ouverture de fichier avec input utilisateur — OWASP A4. Vérifier nom et extension.'
		],

		// 16. Inclusion via flux php://
		[
			'id' => 'INCLUDE_PHP_STREAM',
			'regex' => '/\b(include|require|require_once|include_once)\s*\(\s*[\'"]php:\/\//i',
			'level' => 'high',
			'message' => 'Inclusion dangereuse d’un flux php:// — OWASP A4. À éviter.'
		],

		// 17. file_put_contents() sur php://input
		[
			'id' => 'FILE_PUT_PHP_INPUT',
			'regex' => '/file_put_contents\s*\(\s*[\'"]php:\/\/input[\'"]\s*\)/i',
			'level' => 'info',
			'message' => 'Écriture sur php://input atypique — probable erreur de développement.'
		],

		// 18. include()/require() dynamique
		[
			'id' => 'DYNAMIC_INCLUDE_LFI',
			'regex' => '/\b(include|require)(_once)?\s*\(\s*(\$|[\'"][^\'"]*\.{2}\/)/i',
			'level' => 'high',
			'message' => 'Include dynamique ou LFI détecté (variable ou ../) — OWASP A5:2021. Toujours valider le répertoire et utiliser une whitelist.'
		],

		// 19. Vérification HTTPS fragile
		[
			'id' => 'HTTPS_CHECK_WEAK',
			'regex' => '/\$_SERVER\s*\[\s*[\'"]HTTPS[\'"]\s*\]/i',
			'level' => 'info',
			'message' => 'Vérification HTTPS potentiellement fragile — OWASP A6. Recommander une fonction centralisée tenant compte des proxys/load balancers.'
		],

		// 20. Echo de données utilisateur sans échappement
		[
			'id' => 'ECHO_USER_INPUT',
			'regex' => '/echo\s+.*\$_(GET|POST|REQUEST|COOKIE)/i',
			'level' => 'medium',
			'message' => 'Affichage direct de données utilisateur sans htmlspecialchars() — OWASP A7: XSS.'
		],

		// 21. unserialize() sur input utilisateur
		[
			'id' => 'UNSERIALIZE_USER_INPUT',
			'regex' => '/\bunserialize\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'unserialize() sur input externe — OWASP A8. Très dangereux : injection d’objets. Utiliser JSON.'
		],

		// 22. Base64 longue possible code masqué
		[
			'id' => 'BASE64_OBFUSCATION',
			'regex' => '/base64_decode\s*\(\s*[\'"]?[A-Za-z0-9+\/]{32,}[=]{0,2}[\'"]?\s*\)/i',
			'level' => 'medium',
			'message' => 'Chaîne Base64 longue détectée — possible code masqué. Examiner le fichier plus profondément.'
		],

		// 23. Path traversal potentiel
		[
			'id' => 'PATH_TRAVERSAL',
			'regex' => '/\b(realpath|dirname)\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'Path traversal potentiel. Valider et normaliser le chemin.'
		],

		// 24. Directory listing non autorisé
		[
			'id' => 'SCANDIR_USER_INPUT',
			'regex' => '/\bscandir\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'Directory listing contrôlé par l’utilisateur. Ne jamais permettre à l’utilisateur de lister un dossier.'
		],

		// 25. Redirection basée sur input utilisateur
		[
			'id' => 'OPEN_REDIRECT',
			'regex' => '/header\s*\(\s*[\'"]Location:.*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Redirection non filtrée (Open Redirect) détectée — OWASP A10:2021. Limiter aux URLs internes ou whitelist.'
		],

		// 26. Regex construite via input — ReDoS possible
		[
			'id' => 'REGEX_REDOS',
			'regex' => '/preg_replace\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)[^,]*,/i',
			'level' => 'medium',
			'message' => 'Motif regex construit depuis input utilisateur — OWASP A1: risque ReDoS.'
		],

		// 27. Lecture du corps HTTP via php://input
		[
			'id' => 'PHP_INPUT_READ',
			'regex' => '/file_get_contents\s*\(\s*[\'"]php:\/\/input[\'"]\s*\)/i',
			'level' => 'info',
			'message' => 'Lecture standard du corps HTTP via php://input (JSON POST). Aucun risque d’exécution.'
		],

		// 28. preg_replace() avec modificateur /e
		[
			'id' => 'PREG_REPLACE_E',
			'regex' => '/preg_replace\s*\(.*\/e[\'"]?\s*\)/i',
			'level' => 'high',
			'message' => 'preg_replace() avec modificateur /e — OWASP A1: Code Injection. Remplacer par preg_replace_callback().'
		],

		// 29. extract() sur input utilisateur
		[
			'id' => 'EXTRACT_USER_INPUT',
			'regex' => '/\bextract\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'extract() sur données utilisateur — OWASP A1. Crée des variables dynamiques non contrôlées. À éviter.'
		],

		// 30. parse_str() sur input utilisateur
		[
			'id' => 'PARSE_STR_USER_INPUT',
			'regex' => '/\bparse_str\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'parse_str() sur input utilisateur — OWASP A1. Crée des variables potentiellement dangereuses. Utiliser un parseur manuel.'
		],

		// 31. print/printf/var_dump/die/exit avec input utilisateur
		[
			'id' => 'PRINT_USER_INPUT',
			'regex' => '/\b(print|printf|var_dump|die|exit)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)/i',
			'level' => 'medium',
			'message' => 'Affichage direct de données utilisateur — OWASP A7: XSS. Toujours échapper avec htmlspecialchars().'
		],

		// 32. move_uploaded_file() avec chemin utilisateur
		[
			'id' => 'MOVE_UPLOADED_FILE_USER_PATH',
			'regex' => '/move_uploaded_file\s*\([^,]+,\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'Path traversal potentiel sur upload — OWASP A4. Ne jamais laisser l’utilisateur définir le chemin.'
		],

		// 33. glob() avec input utilisateur
		[
			'id' => 'GLOB_USER_INPUT',
			'regex' => '/\bglob\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'glob() contrôlé par utilisateur — A5:2021. Risque Path Traversal. Restreindre aux dossiers et extensions autorisés.'
		],
		
		// 34. Clé API ou token codé en dur
		[
			'id' => 'API_KEY_HARDCODED',
			'regex' => '/(api[_-]?key|secret|token)\s*=\s*[\'"][A-Za-z0-9_\-]{16,}[\'"]/i',
			'level' => 'high',
			'message' => 'Clé API ou token potentiellement codé en dur.'
		],

		// 35. JWT sans date d’expiration
		[
			'id' => 'JWT_WITHOUT_EXP',
			'regex' => '/JWT::encode\s*\(\s*\{(?:(?!\bexp\b).)*\}\s*,/is',
			'level' => 'medium',
			'message' => 'JWT créé sans date d’expiration.'
		],

		// 36. Génération de token non cryptographique
		[
			'id' => 'WEAK_RANDOM_TOKEN',
			'regex' => '/(mt_rand|rand)\s*\(/i',
			'level' => 'medium',
			'message' => 'Génération de token ou ID avec rand/mt_rand (non cryptographique).'
		],

		// 37. uniqid() non sécurisé
		[
			'id' => 'INSECURE_UUID',
			'regex' => '/uniqid\(/i',
			'level' => 'low',
			'message' => 'uniqid() n’est pas sécurisé pour générer des identifiants uniques sensibles.'
		],

		// 38. Envoi de mail avec input non validé
		[
			'id' => 'FILTER_VALIDATE_EMAIL_MISSING',
			'regex' => '/mail\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)/i',
			'level' => 'medium',
			'message' => 'Envoi d’e-mail avec entrée utilisateur sans validation.'
		],

		// 39. Extraction ZIP sans whitelist
		[
			'id' => 'ZIP_EXTRACT_WITHOUT_WHITELIST',
			'regex' => '/extractTo\s*\(/i',
			'level' => 'medium',
			'message' => 'Extraction ZIP sans whitelist des extensions. Risque ZIP Slip.'
		],

		// 40. Path traversal via séquence ../
		[
			'id' => 'PATH_TRAVERSAL_DOTDOT',
			'regex' => '/\b(include|require|fopen|file_get_contents|file_put_contents|scandir)\s*\([^)]*?\$_(GET|POST|REQUEST)[^)]*\.\.\//i',
			'level' => 'high',
			'message' => 'Séquence ../ construite avec données utilisateur — path traversal (OWASP A5).'
		],

		// 41. Exposition de données de session réellement sensibles
		[
			'id'      => 'SESSION_SENSITIVE_EXPOSED',
			'regex'   => '/echo\s+(\$_SESSION\[(\'|")(password|token|secret|key|auth|user|login)/i',
			'level'   => 'high',
			'message' => 'Affichage d’une donnée de session sensible (mot de passe, token, secret…).'
		],

		// 42. Comparaison de mot de passe en clair
		[
			'id' => 'PASSWORD_INSECURE_COMPARE',
			'regex' => '/\bif\s*\(.*\b\$password\b\s*==\s*[\'"][^\'"]+[\'"]/i',
			'level' => 'medium',
			'message' => 'Comparaison de mot de passe en clair avec ==. Utiliser password_verify().'
		],

		// 43. Mot de passe stocké en clair
		[
			'id' => 'PLAINTEXT_PASSWORD_STORAGE',
			'regex' => '/password\s*=\s*[\'"][^\'"]+[\'"]/i',
			'level' => 'high',
			'message' => 'Mot de passe stocké en clair dans le code.'
		],

		// 44. Hachage de mot de passe non sécurisé
		[
			'id' => 'CUSTOM_PASSWORD_HASH',
			'regex' => '/(sha1|md5)\s*\(\s*\$?password/i',
			'level' => 'high',
			'message' => 'Hachage de mot de passe avec SHA1/MD5 non sécurisé.'
		],

		// 45. Chiffrement OpenSSL en mode ECB
		[
			'id' => 'INSECURE_OPENSSL_MODE',
			'regex' => '/openssl_encrypt\s*\(.*(ecb|ECB)/i',
			'level' => 'high',
			'message' => 'Chiffrement OpenSSL en mode ECB non sécurisé.'
		],

		// 46. Utilisation de mcrypt obsolète
		[
			'id' => 'MCRYPT_USAGE',
			'regex' => '/mcrypt_/i',
			'level' => 'medium',
			'message' => 'mcrypt est obsolète depuis PHP 7.1.'
		],

		// 47. openssl_random_pseudo_bytes() potentiellement non sécurisé
		[
			'id' => 'RANDOM_IV_PREDICTABLE',
			'regex' => '/openssl_random_pseudo_bytes\s*\(/i',
			'level' => 'low',
			'message' => 'openssl_random_pseudo_bytes() peut être non sécurisé selon l’OS.'
		],

		// 48. cURL avec vérification SSL désactivée
		[
			'id' => 'CURL_INSECURE_SSL',
			'regex' => '/CURLOPT_SSL_VERIFYPEER\s*,\s*false/i',
			'level' => 'high',
			'message' => 'cURL désactive la vérification SSL.'
		],

		// 49. setcookie() sans HttpOnly/Secure — A2:2021
		[
			'id' => 'NO_HTTPONLY_COOKIE',
			'regex' => '/setcookie\s*\(\s*.*,\s*.*,\s*.*,\s*.*,\s*.*,\s*(false|0)\s*,\s*(false|0)/i',
			'level' => 'medium',
			'message' => 'setcookie() sans HttpOnly/Secure détecté — A2:2021. Ajouter HttpOnly, Secure et SameSite.'
		],

		// 50. Affichage des erreurs activé — A6:2021
		[
			'id' => 'DISPLAY_ERRORS_ON',
			'regex' => '/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]1[\'"]\)/i',
			'level' => 'medium',
			'message' => 'Affichage des erreurs activé — A6:2021. Peut divulguer des informations sensibles.'
		],

		// 51. error_reporting(E_ALL) actif — A6:2021
		[
			'id' => 'ERROR_REPORTING_ALL',
			'regex' => '/error_reporting\s*\(\s*E_ALL\s*\)/i',
			'level' => 'info',
			'message' => 'error_reporting(E_ALL) actif — A6:2021. Risque de fuite d’informations en production.'
		],

		// 52. var_dump/print_r détecté — A6:2021
		[
			'id' => 'VAR_DUMP_DEBUG',
			'regex' => '/(var_dump|print_r)\s*\(/i',
			'level' => 'low',
			'message' => 'var_dump/print_r détecté — A6:2021. Risque fuite d’informations en production.'
		],

		// 53. Affichage de backtrace — A6:2021
		[
			'id' => 'STACKTRACE_EXPOSURE',
			'regex' => '/debug_backtrace\s*\(/i',
			'level' => 'medium',
			'message' => 'Affichage de backtrace détecté — A6:2021. Ne jamais exposer la pile en production.'
		],

		// 54. Adresse IP codée en dur — A6:2021
		[
			'id' => 'HARDCODED_IP',
			'regex' => '/\b\d{1,3}(\.\d{1,3}){3}\b/',
			'level' => 'low',
			'message' => 'Adresse IP codée en dur détectée — A6:2021. Préférer une configuration centralisée.'
		],

		// 55. die() avec message potentiellement sensible — A6:2021
		[
			'id'      => 'USE_OF_DIE_WITH_DYNAMIC_MESSAGE',
			'regex'   => '/die\s*\(\s*(\$|\w+\s*\(|".*\$|\'.*\$)/i',
			'level'   => 'medium',
			'message' => 'die() avec message dynamique — risque de divulgation d’informations internes.'
		],

		// 56. allow_url_include activé — A6:2021
		[
			'id' => 'INSECURE_ALLOW_URL_INCLUDE',
			'regex' => '/ini_set\s*\(\s*[\'"]allow_url_include[\'"]\s*,\s*[\'"]1[\'"]\)/i',
			'level' => 'critical',
			'message' => 'allow_url_include activé — A6:2021. Risque RCE à distance.'
		],

		// 57. Tamponnage de sortie basé sur input — A7:2021
		[
			'id' => 'OB_START_ECHO_RAW',
			'regex' => '/ob_start\s*\(.*?\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'ob_start() avec input utilisateur — A7:2021. Risque XSS si echo direct.'
		],

		// 58. chmod/chown/chgrp permissif — A5:2021
		[
			'id' => 'DANGEROUS_CHMOD',
			'regex' => '/chmod\s*\(.*0(77|666|777)/i',
			'level' => 'high',
			'message' => 'chmod permissif détecté — A5:2021. Risque exposition fichiers.'
		],

		// 59. allow_url_fopen activé — A6:2021
		[
			'id' => 'URL_FOPEN_ENABLED',
			'regex' => '/ini_set\s*\(\s*[\'"]allow_url_fopen[\'"]\s*,\s*[\'"]1[\'"]\)/i',
			'level' => 'medium',
			'message' => 'allow_url_fopen activé — A6:2021. Risque inclusion distante.'
		],
		
		// 60. Utilisation de extract() globale
		[
			'id' => 'EXTRACT_GLOBAL',
			'regex' => '/\bextract\s*\(\s*\$GLOBALS/i',
			'level' => 'high',
			'message' => 'extract() sur $GLOBALS — risque critique : variables globales écrasées.'
		],
		
		// 61. Inclusion distante via URL
		[
			'id' => 'REMOTE_INCLUDE',
			'regex' => '/\b(include|require)(_once)?\s*\(\s*[\'"]https?:\/\//i',
			'level' => 'critical',
			'message' => 'Inclusion distante via URL — RCE possible. À éviter absolument.'
		],
		
		// 62. Utilisation de preg_match ou preg_replace avec input utilisateur et regex non bornée
		[
			'id' => 'REGEX_UNBOUNDED_INPUT',
			'regex' => '/preg_(match|replace)\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'medium',
			'message' => 'Regex construite sur input utilisateur non bornée — risque ReDoS.'
		],
		
		// 63. Inclusion de fichiers temporaires (tmp)
		[
			'id' => 'INCLUDE_TMP_FILE',
			'regex' => '/\b(include|require)(_once)?\s*\(\s*sys_get_temp_dir\(\)/i',
			'level' => 'high',
			'message' => 'Inclusion de fichiers temporaires — risque de code non fiable ou RCE.'
		],
		
		// 64. Autoload dynamique non sécurisé
		[
			'id' => 'AUTOLOAD_INSECURE',
			'regex' => '/spl_autoload_register\s*\(\s*\$?\w+\s*\)/i',
			'level' => 'medium',
			'message' => 'Autoload potentiellement non sécurisé — OWASP A5. Vérifier que le chemin est strictement contrôlé pour éviter les inclusions arbitraires.'
		],
	
		// 65. cURL sans timeout (risque DoS applicatif)
		[
			'id' => 'CURL_NO_TIMEOUT',
			'regex' => '/curl_setopt\s*\([^,]+,\s*CURLOPT_TIMEOUT\s*,\s*0\s*\)/i',
			'level' => 'medium',
			'message' => 'cURL configuré avec timeout illimité — risque DoS applicatif. Toujours définir un timeout raisonnable.'
		],

		// 66. Désactivation de SSL dans cURL (MITM)
		[
			'id' => 'CURL_SSL_DISABLED',
			'regex' => '/curl_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFYPEER\s*,\s*false\s*\)/i',
			'level' => 'high',
			'message' => 'SSL désactivé dans cURL — MITM possible. Toujours activer la vérification du certificat.'
		],

		// 67. fopen() de wrapper data:// (RCE potentiel)
		[
			'id' => 'DATA_WRAPPER_USAGE',
			'regex' => '/fopen\s*\(\s*[\'"]data:\/\//i',
			'level' => 'high',
			'message' => 'Ouverture de flux data:// — risque d’exécution ou d’exposition de données sensibles.'
		],

		// 68. Inclusion dynamique de fichier JSON externe (SSRF)
		[
			'id' => 'REMOTE_JSON_INCLUDE',
			'regex' => '/json_decode\s*\(\s*file_get_contents\s*\(\s*[\'"]https?:\/\//i',
			'level' => 'medium',
			'message' => 'Chargement JSON externe sans validation — risque SSRF/Injection. Toujours valider la source.'
		],

		// 69. Désérialisation igbinary sur input utilisateur (Injection)
		[
			'id' => 'IGBINARY_UNSERIALIZE_INPUT',
			'regex' => '/igbinary_unserialize\s*\(\s*\$_(GET|POST|REQUEST)/i',
			'level' => 'high',
			'message' => 'igbinary_unserialize() sur input utilisateur — injection d’objets possible.'
		],

		// 70. parse_url() sans validation du schéma (SSRF)
		[
			'id' => 'PARSE_URL_NO_SCHEME_CHECK',
			'regex' => '/parse_url\s*\(\s*\$_(GET|POST|REQUEST)[^)]*\)/i',
			'level' => 'medium',
			'message' => 'parse_url() utilisé sur input utilisateur sans validation du schéma — risque SSRF.'
		],
	
	];

function scan_project($root) {
    // ============================================
    // Scanner OWASP 2021 PHP
    // ============================================
    global $rules;
    $results = [];

    // Parcours récursif du projet
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($rii as $file) {
        if ($file->isDir()) continue;
        $path = $file->getPathname();

        // Scanner uniquement les fichiers PHP
        if (!preg_match('/\.php$/i', $path)) continue;

        $content = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$content) continue;

        $fileSize = filesize($path);

        foreach ($content as $lineNumber => $line) {
            $trimmedLine = trim($line);

            // ============================================
            // Détection via règles définies (format OWASP 2021)
            // ============================================
            foreach ($rules as $rule) {
                if (preg_match($rule['regex'], $line)) {
                    $results[] = [
                        'file'      => $path,
                        'line'      => $lineNumber + 1,
                        'excerpt'   => $trimmedLine,
                        'severity'  => $rule['level'],
                        'message'   => $rule['message'],
                        'id'        => $rule['id'],
                        'size'      => $fileSize
                    ];
                }
            }

            // ============================================
            // Heuristique : eval indirect via variable
            // ============================================
            if (preg_match('/\$\w+\s*=\s*[\'"]eval[\'"]/', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Eval indirect via variable détecté',
                    'id'        => 'EVAL_INDIRECT',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : include/require dynamique avec entrée utilisateur
            // ============================================
            if (preg_match('/\b(include|require|include_once|require_once)\s*\(\s*\$[^\)]+\)/i', $line) &&
                preg_match('/\$_(GET|POST|REQUEST|COOKIE)/i', $line)) {

                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'critical',
                    'message'   => 'Include/Require dynamique avec entrée utilisateur — risque RFI/LFI.',
                    'id'        => 'DYNAMIC_INCLUDE_USER',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : preg_replace avec /e
            // ============================================
            if (preg_match('/preg_replace\s*\(.*[\'"]\/e[\'"].*\)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Usage de preg_replace avec /e — exécution de code arbitraire possible.',
                    'id'        => 'PREG_REPLACE_E',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : shell_exec, exec, system, passthru avec variable utilisateur
            // ============================================
            if (preg_match('/\b(shell_exec|exec|system|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $line)) {
                $duplicate = false;
                foreach ($results as $r) {
                    if ($r['file'] === $path && $r['line'] === $lineNumber + 1 && $r['id'] === 'RCE_HEURISTIC') {
                        $duplicate = true; break;
                    }
                }
                if (!$duplicate) {
                    $results[] = [
                        'file'      => $path,
                        'line'      => $lineNumber + 1,
                        'excerpt'   => $trimmedLine,
                        'severity'  => 'critical',
                        'message'   => 'Exécution de commande système avec donnée utilisateur — risque RCE.',
                        'id'        => 'RCE_HEURISTIC',
                        'size'      => $fileSize
                    ];
                }
            }

            // ============================================
            // Heuristique AST : unserialize() sur entrée externe
            // ============================================
            if (preg_match('/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'critical',
                    'message'   => 'Unserialize de donnée externe — risque d’object injection.',
                    'id'        => 'UNSERIALIZE_EXTERNAL',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : die() avec concaténation
            // ============================================
            if (preg_match('/die\s*\(\s*\$[^)]*\./i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'medium',
                    'message'   => 'die() utilise une concaténation — message potentiellement sensible.',
                    'id'        => 'DIE_CONCAT_WARNING',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : echo $_SESSION indexé par entrée utilisateur
            // ============================================
            if (preg_match('/echo\s*\$_SESSION\[[^\]]*\]/i', $line) &&
                preg_match('/\$_(GET|POST|REQUEST|COOKIE)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Affichage d’une donnée de session indexée par entrée utilisateur.',
                    'id'        => 'SESSION_INDEXED_BY_USER_INPUT',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique AST : SQLi simple
            // ============================================
            if (preg_match('/\b(SELECT|INSERT|UPDATE|DELETE)\b/i', $line) &&
                preg_match('/\$_(GET|POST|REQUEST|COOKIE)/i', $line) &&
                !preg_match('/prepare|bind_param/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Construction dynamique de requête SQL avec données utilisateur',
                    'id'        => 'SQLI_HEURISTIC',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Heuristique XSS simple
            // ============================================
            if (preg_match('/\b(echo|print|printf|die|exit)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Données utilisateur affichées sans filtration — risque XSS.',
                    'id'        => 'XSS_UNFILTERED',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // CSRF manquant sur formulaire POST
            // ============================================
            if (preg_match('/<form.*method\s*=\s*["\']?post["\']?/i', $line) &&
                !preg_match('/csrf_token/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'medium',
                    'message'   => 'Formulaire POST sans protection CSRF détectée.',
                    'id'        => 'CSRF_MISSING',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Hashage faible détecté
            // ============================================
            if (preg_match('/\b(md5|sha1)\s*\(/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Hashage non sécurisé détecté (md5/sha1).',
                    'id'        => 'WEAK_PASSWORD_HASH',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Affichage ou suppression d’erreurs
            // ============================================
            if (preg_match('/error_reporting\s*\(\s*0\s*\)/i', $line) ||
                preg_match('/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*1\s*\)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'medium',
                    'message'   => 'Affichage ou suppression d’erreurs potentiellement dangereux.',
                    'id'        => 'ERROR_DISPLAY',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Session démarrée sans session_regenerate_id()
            // ============================================
            if (preg_match('/session_start\s*\(\s*\)/i', $line) &&
                !preg_match('/session_regenerate_id\s*\(\s*true\s*\)/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'medium',
                    'message'   => 'Session démarrée sans régénération d’ID — risque fixation session.',
                    'id'        => 'SESSION_FIXED',
                    'size'      => $fileSize
                ];
            }

            // ============================================
            // Upload de fichier non sécurisé
            // ============================================
            if (preg_match('/move_uploaded_file\s*\(/i', $line) &&
                !preg_match('/\.(jpg|png|gif|pdf)$/i', $line)) {
                $results[] = [
                    'file'      => $path,
                    'line'      => $lineNumber + 1,
                    'excerpt'   => $trimmedLine,
                    'severity'  => 'high',
                    'message'   => 'Upload de fichier potentiellement non filtré — risque RFI/malware.',
                    'id'        => 'FILE_UPLOAD_UNCHECKED',
                    'size'      => $fileSize
                ];
            }
        }
    }

    // Retour des résultats au format OWASP 2021
    return $results;
}
?>