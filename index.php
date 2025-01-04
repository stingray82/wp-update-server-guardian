<?php
// Configuration
$real_update_server_url = 'https://exampledomain.com/updates/'; // Replace with your real server URL where https://github.com/YahnisElsts/wp-update-server in installed i.e exampledomain.com/updates/
$api_keys_file = __DIR__ . '/api-keys.conf';
$whitelist_file = __DIR__ . '/whitelist.conf';
$blacklist_file = __DIR__ . '/blacklist.conf';
$bypass_file = __DIR__ . '/bypass.conf';
$log_dir = __DIR__ . '/logs'; // Directory for logs
$enable_api_key_check = true; // Switch to enable/disable API key check
$enable_whitelist_check = true; // Switch to enable/disable whitelist check
$enable_blacklist_check = true; // Switch to enable/disable blacklist check
$enable_bypass = false; // Switch to enable/disable bypass checking
$whitelist_check_mode = 'or'; // Set to 'and' or 'or' to control whitelist logic

// Ensure the log directory exists
if (!is_dir($log_dir)) {
    mkdir($log_dir, 0755, true);
}

// Extract domain from the User-Agent header
function extract_domain_from_user_agent() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (preg_match('/WordPress\/\d+\.\d+\.\d+;\s(https?:\/\/[^\s]+)/', $user_agent, $matches)) {
        return parse_url($matches[1], PHP_URL_HOST);
    }
    return null;
}

// Helper function to log requests
function log_request($status, $extra_info = '') {
    global $log_dir;
    $log_file = $log_dir . '/access_' . date('Y-m-d') . '.log';
    
    // Extract domain for logging
    $domain = extract_domain_from_user_agent() ?? 'No Domain';
    
    $log_entry = sprintf(
        "[%s] IP: %s | Referrer: %s | Domain: %s | Status: %s | Info: %s\n",
        date('Y-m-d H:i:s'),
        $_SERVER['REMOTE_ADDR'],
        $_SERVER['HTTP_REFERER'] ?? 'No Referrer',
        $domain,
        $status,
        $extra_info
    );
    file_put_contents($log_file, $log_entry, FILE_APPEND);
}

// Helper function to respond with errors and log them
function respond_with_error($status_code, $message, $extra_info = '') {
    log_request($message, $extra_info);
    http_response_code($status_code);
    echo json_encode(['error' => $message]);
    exit;
}

// Check if the request is from a blacklisted IP or domain
function check_blacklisted() {
    global $enable_blacklist_check, $blacklisted_ips_or_domains;
    
    if (!$enable_blacklist_check) {
        return false; // Skip check if blacklist check is disabled
    }
    
    $client_ip = $_SERVER['REMOTE_ADDR'];
    $domain = extract_domain_from_user_agent();
    
    if (in_array($client_ip, $blacklisted_ips_or_domains) || ($domain && in_array($domain, $blacklisted_ips_or_domains))) {
        respond_with_error(403, 'Forbidden: Blacklisted IP or domain.');
    }
    
    return false;
}

// Check if the request is from a whitelisted IP or domain
function check_whitelisted() {
    global $enable_whitelist_check, $whitelisted_ips_or_domains, $whitelist_check_mode;
    
    if (!$enable_whitelist_check) {
        return true; // Skip check if whitelist check is disabled
    }
    
    $client_ip = $_SERVER['REMOTE_ADDR'];
    $domain = extract_domain_from_user_agent();
    
    $ip_whitelisted = in_array($client_ip, $whitelisted_ips_or_domains);
    $domain_whitelisted = $domain && in_array($domain, $whitelisted_ips_or_domains);
    
    if ($whitelist_check_mode === 'and') {
        // Both IP and domain must be whitelisted
        if ($ip_whitelisted && $domain_whitelisted) {
            return true;
        }
    } elseif ($whitelist_check_mode === 'or') {
        // Either IP or domain must be whitelisted
        if ($ip_whitelisted || $domain_whitelisted) {
            return true;
        }
    }
    
    respond_with_error(403, 'Unauthorized: IP and/or domain not allowed.');
}

// Helper function to load and clean configuration files
function load_config_file($file_path) {
    if (!file_exists($file_path)) {
        return [];
    }
    
    $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $cleaned_lines = [];

    foreach ($lines as $line) {
        // Remove comments starting with // or ##
        $line = preg_replace('/\s*(\/\/|##).*$/', '', $line);
        
        // Trim whitespace and ensure it's not empty
        $line = trim($line);
        if (!empty($line)) {
            $cleaned_lines[] = $line;
        }
    }

    return $cleaned_lines;
}

// Load API keys, whitelist, and blacklist
$valid_api_keys = $enable_api_key_check ? load_config_file($api_keys_file) : [];
$whitelisted_ips_or_domains = $enable_whitelist_check ? load_config_file($whitelist_file) : [];
$blacklisted_ips_or_domains = $enable_blacklist_check ? load_config_file($blacklist_file) : [];
$bypass_ips_or_domains = $enable_bypass ? load_config_file($bypass_file) : [];


// Extract client details
$domain = extract_domain_from_user_agent();
$client_ip = $_SERVER['REMOTE_ADDR'];

// Check if the request is from a blacklisted IP or domain
check_blacklisted();

// Check if the request is from a bypass user
$is_bypass_user = (in_array($client_ip, $bypass_ips_or_domains) || ($domain && in_array($domain, $bypass_ips_or_domains)));

if (!$is_bypass_user) {
    // Check if the request has a valid API key
    if ($enable_api_key_check && (!isset($_GET['key']) || !in_array($_GET['key'], $valid_api_keys))) {
        respond_with_error(403, 'Unauthorized: Invalid API key.');
    }

    // Check if the request is from a whitelisted IP or domain
    check_whitelisted();
}


// Sanitize the query parameters
$query_params = [];
foreach ($_GET as $key => $value) {
    $sanitized_key = ltrim($key, '?'); // Remove any leading '?' from keys
    $query_params[$sanitized_key] = $value;
}

// Build the forward URL
$forward_url = $real_update_server_url . '?' . http_build_query($query_params, '', '&', PHP_QUERY_RFC3986);

// Log the URL being forwarded
log_request('Forwarding Request', 'Forward URL: ' . $forward_url);

// Forward the request to the real update server and fetch the JSON response
$response = file_get_contents($forward_url);

// Check if the response is false (indicating a failure)
if ($response === false) {
    respond_with_error(500, 'Error communicating with the update server.');
}

// Decode the JSON response
$json_response = json_decode($response, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    respond_with_error(500, 'Invalid JSON received from the update server.');
}

// Decode any escaped Unicode characters and HTML entities in the JSON content
array_walk_recursive($json_response, function (&$value) {
    if (is_string($value)) {
        $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
});

// Log successful request with forwarded URL
log_request('Success', 'Forward URL: ' . $forward_url);

// Return the cleaned JSON response
header('Content-Type: application/json');
echo json_encode($json_response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
exit;

// Cleanup logs older than 30 days
function cleanup_old_logs() {
    global $log_dir;
    
    // File to store the last cleanup timestamp
    $last_cleanup_file = $log_dir . '/last_cleanup.txt';
    
    // Check if last cleanup was done today
    $today = date('Y-m-d');
    if (file_exists($last_cleanup_file) && trim(file_get_contents($last_cleanup_file)) === $today) {
        return; // Cleanup already done today
    }

    // Perform cleanup
    $files = glob($log_dir . '/access_*.log');
    $now = time();
    
    foreach ($files as $file) {
        if (is_file($file) && $now - filemtime($file) > 30 * 24 * 60 * 60) { // 30 days in seconds
            unlink($file);
        }
    }

    // Update the last cleanup timestamp
    file_put_contents($last_cleanup_file, $today);
}

// Call the cleanup function
cleanup_old_logs();
