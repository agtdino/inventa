<?php
/**
 * index.php - AutoCRUD completo (con export CSV corregido)
 * - Usa inventa/config.php para la configuración
 * - Poner este archivo en /var/www/html/inventa/index.php
 */

/********** CARGAR CONFIGURACION **********/
$configFile = __DIR__ . '/config/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    echo "Falta config.php en " . __DIR__;
    exit;
}
$config = require $configFile;

// Defaults and safety
$basePath = rtrim($config['base_path'] ?? '/inventa', '/');
$itemsPerPage = intval($config['itemsPerPage'] ?? 15);
$dev_mode = !empty($config['dev_mode']) && $config['dev_mode'] == '1';

if ($dev_mode) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}

/********** CONEXIÓN PDO **********/
try {
    $dsn = "mysql:host={$config['db_host']};dbname={$config['db_name']};charset=utf8mb4";
    $pdo = new PDO($dsn, $config['db_user'], $config['db_pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    echo "Error de conexión: " . htmlspecialchars($e->getMessage());
    exit;
}

/********** UTILIDADES **********/
session_start();


function detectarSubred() {
    // Obtiene la puerta de enlace y la interfaz activa
    $route = trim(shell_exec("ip route | grep default"));

    if (!$route) return null;

    // Ejemplo de salida:
    // default via 192.168.1.1 dev eth0 proto dhcp metric 100
    if (preg_match('/dev\s+([a-zA-Z0-9]+)/', $route, $m)) {
        $iface = $m[1];
    } else {
        return null;
    }

    // Ahora obtenemos la IP y la máscara de esa interfaz
    $info = trim(shell_exec("ip -4 addr show $iface"));

    if (!$info) return null;

    // Extraer: inet 192.168.1.30/24
    if (preg_match('/inet\s+([\d\.]+)\/(\d+)/', $info, $m)) {
        $ip = $m[1];
        $cidr = $m[2];
        return "$ip/$cidr";
    }

    return null;
}

function scanNetworkNmap($subnet = "192.168.1.0/24") {
    
    $subnet ? $subnet : $subnet = obtenerSubredParaNmap();
    
    //TODO namp is installed
    $tmpFile = "/tmp/nmap_scan_" . md5($subnet) . ".xml";
    //$cmd = "sudo /usr/bin/nmap $subnet -sn -oX $tmpFile 2>&1";
    $cmd = "sudo /usr/bin/nmap -sn -PR --packet-trace $subnet -oX $tmpFile 2>&1";
    exec($cmd);

    if (!file_exists($tmpFile)) return [];

    $xml = simplexml_load_file($tmpFile);
    
    if (!$xml) return [];

    $hosts = [];

    foreach ($xml->host as $host) {
        $status = (string)$host->status['state'];
        if ($status !== 'up') continue;

        $ip = null;
        $mac = null;
        $vendor = null;
        $hostname = null;
        
        //echo "<pre>"; print_r($host); echo "</pre>"; die();
        foreach ($host->hostnames as $dns) {
            if (isset($hostname)) {
                $hostname .= " ".(string)$dns->hostname["name"];
            } else {
                $hostname = (string)$dns->hostname["name"];
            }
        }                

        foreach ($host->address as $addr) {
            if ((string)$addr['addrtype'] === 'ipv4') {
                $ip = (string)$addr['addr'];
            }
            if ((string)$addr['addrtype'] === 'mac') {
                $mac = (string)$addr['addr'];
                $vendor = (string)$addr['vendor'];
            }
            if ((string)$addr['addrtype'] === 'mac') {
                $mac = (string)$addr['addr'];
                $vendor = (string)$addr['vendor'];
            }
        }

        if ($ip) {
            $hosts[] = [
                'ip' => $ip,
                'mac' => $mac ?: "",
                'vendor' => $vendor ?: "",
                'hostname' => $hostname ?: ""
            ];
        }
    }
    if (file_exists($tmpFile)) {
        $cmd = "sudo rm $tmpFile 2>&1";
        exec($cmd);
    }
    
    return $hosts;
    
}
function cidrToNetwork($ipCidr) {
    list($ip, $cidr) = explode("/", $ipCidr);

    $mask = -1 << (32 - $cidr);
    $mask = $mask & 0xFFFFFFFF;

    $ipLong = ip2long($ip);

    $network = $ipLong & $mask;

    return long2ip($network) . "/" . $cidr;
}

function obtenerSubredParaNmap() {
    $cidr = detectarSubred();
    if (!$cidr) return "192.168.1.0/24"; // fallback seguro
    return cidrToNetwork($cidr);
}

function e($v){ return htmlspecialchars((string)$v, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }
function url($path=''){ global $basePath; return rtrim($basePath,'/') . '/' . ltrim($path,'/'); }

function csrf_token() { if (empty($_SESSION['_csrf'])) $_SESSION['_csrf'] = bin2hex(random_bytes(16)); return $_SESSION['_csrf']; }
function check_csrf($t) { return isset($_SESSION['_csrf']) && hash_equals($_SESSION['_csrf'], $t ?? ''); }

/********** TIEMPO HUMANO **********/
function timeAgoTs($ts) {
    if (!$ts) return 'Nunca';
    $diff = time() - $ts;
    if ($diff < 60) return $diff . 's';
    if ($diff < 3600) return round($diff/60) . 'm';
    if ($diff < 86400) return round($diff/3600) . 'h';
    if ($diff < 604800) return round($diff/86400) . 'd';
    if ($diff < 2592000) return round($diff/604800) . 'w';
    if ($diff < 31536000) return round($diff/2592000) . 'mo';
    return round($diff/31536000) . 'y';
}
function timeAgo($datetime) {
    if (!$datetime) return 'Nunca';
    $ts = is_numeric($datetime) ? intval($datetime) : strtotime($datetime);
    if (!$ts) return 'Nunca';
    return timeAgoTs($ts) . ' ago';
}

/********** INTROSPECCIÓN **********/
function getTables(PDO $pdo) {
    return $pdo->query("SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY TABLE_NAME")->fetchAll(PDO::FETCH_COLUMN);
}
function getColumns(PDO $pdo, $table) {
    $stmt = $pdo->prepare("SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH, COLUMN_KEY, COLUMN_DEFAULT, EXTRA FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :t ORDER BY ORDINAL_POSITION");
    $stmt->execute([':t'=>$table]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
function getPrimaryKey(PDO $pdo, $table) {
    $cols = getColumns($pdo, $table);
    foreach ($cols as $c) if ($c['COLUMN_KEY'] === 'PRI') return $c['COLUMN_NAME'];
    return $cols[0]['COLUMN_NAME'] ?? null;
}
function sanitizeOrderCol(array $colsMeta, $requested) {
    $valid = array_column($colsMeta, 'COLUMN_NAME');
    return in_array($requested, $valid) ? $requested : null;
}

/** Detección robusta de claves foráneas */
function getForeignKeys(PDO $pdo, $table) {
    $sql = "
        SELECT 
            k.COLUMN_NAME AS column_name,
            k.REFERENCED_TABLE_NAME AS referenced_table,
            k.REFERENCED_COLUMN_NAME AS referenced_column
        FROM information_schema.KEY_COLUMN_USAGE k
        WHERE 
            k.TABLE_SCHEMA = DATABASE()
            AND k.TABLE_NAME = :t
            AND k.REFERENCED_TABLE_NAME IS NOT NULL
            AND k.REFERENCED_COLUMN_NAME IS NOT NULL
        ORDER BY k.COLUMN_NAME
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([':t' => $table]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Normalizar a claves fijas que el resto del código espera
    $result = [];
    foreach ($rows as $r) {
        $result[] = [
            'COLUMN_NAME' => $r['column_name'],
            'REFERENCED_TABLE_NAME' => $r['referenced_table'],
            'REFERENCED_COLUMN_NAME' => $r['referenced_column'],
        ];
    }

    return $result;
}


/** Columna "display" preferida */
function getDisplayColumn(PDO $pdo, $table) {
    $cols = getColumns($pdo, $table);
    $preferred = ['nombre','name','title','descripcion','label'];
    foreach ($cols as $c) if (in_array(strtolower($c['COLUMN_NAME']), $preferred)) return $c['COLUMN_NAME'];
    foreach ($cols as $c) if (stripos($c['COLUMN_TYPE'],'varchar')!==false || stripos($c['COLUMN_TYPE'],'char')!==false) return $c['COLUMN_NAME'];
    return $cols[0]['COLUMN_NAME'] ?? null;
}

function trustDevice(PDO $pdo) {

    // Datos enviados desde el botón TRUST
    
    $ip = $_POST['ip'] ?? null;
    $hostname = $_POST['hostname'] ?? null;
    $mac = $_POST['mac'] ?? null;
    $vendor = $_POST['vendor'] ?? null;

    if (!$ip && !$mac) {
        die("Datos insuficientes para TRUST");
    }

    // ¿Existe ya un equipo con esa IP o MAC?
    $q = $pdo->prepare("SELECT id FROM equipos WHERE ip = ? OR mac = ? LIMIT 1");
    $q->execute([$ip, $mac]);
    $existing = $q->fetchColumn();

    if ($existing) {
        // 🔁 Actualizar
        $upd = $pdo->prepare(
            "UPDATE equipos 
             SET hostname=?, mac=?, vendor=?, ultima_vez_visto=NOW()
             WHERE id=?"
        );
        $upd->execute([$hostname, $mac, $vendor, $existing]);

    } else {
        // ➕ Insertar
        $ins = $pdo->prepare(
            "INSERT INTO equipos (hostname, ip, mac, vendor, ultima_vez_visto)
             VALUES (?, ?, ?, ?, NOW())"
        );
        $ins->execute([$hostname, $ip, $mac, $vendor]);
    }

    // Volver al listado
    header("Location: /inventa/equipos/list");
    exit;
}

/********** RENDER HTML **********/
function renderHead($title='AutoCRUD') {
    // bootstrap CDN, sin cambiar aspecto
    echo "<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>".e($title)."</title>";
    echo "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>";
    echo "<style>body{background:#f7f8fb}.container{max-width:1200px}.small-muted{font-size:0.9rem;color:#666}</style>";
    echo "</head><body><div class='container py-4'>";
}
function renderFoot(){ 
    echo "</div></body></html>"; 
}
function renderTrustConfirm($existing, $hostname, $ip, $mac) {

    renderHeader("Confirmar actualización");

    echo "<h2>⚠️ Equipo ya existente</h2>";

    echo "<p>Se ha detectado un equipo que ya existe en la base de datos.</p>";

    echo "<table border='1' cellpadding='6'>";
    echo "<tr><th></th><th>Actual</th><th>Detectado</th></tr>";
    echo "<tr><td>Hostname</td><td>".e($existing['hostname'])."</td><td>".e($hostname)."</td></tr>";
    echo "<tr><td>IP</td><td>".e($existing['ip'])."</td><td>".e($ip)."</td></tr>";
    echo "<tr><td>MAC</td><td>".e($existing['mac'])."</td><td>".e($mac)."</td></tr>";
    echo "</table><br>";

    // 🔁 Actualizar
    echo "<form method='POST' action='/inventa/equipos/trust' style='display:inline'>";
    echo "<input type='hidden' name='hostname' value='".e($hostname)."'>";
    echo "<input type='hidden' name='ip' value='".e($ip)."'>";
    echo "<input type='hidden' name='mac' value='".e($mac)."'>";
    echo "<input type='hidden' name='force' value='1'>";
    echo "<button class='button' style='background:orange'>Actualizar equipo existente</button>";
    echo "</form> ";

    // 🚫 Cancelar
    echo "<a class='button' href='/inventa/equipos/list' style='background:gray'>Cancelar</a>";

    renderFooter();
}

/********** ROUTER PARSING **********/
$rawPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = trim($rawPath, '/');
$parts = $path === '' ? [] : explode('/', $path);

// Remove base path if present
$baseDir = trim($basePath, '/');
if ($baseDir !== '' && isset($parts[0]) && $parts[0] === $baseDir) array_shift($parts);

$table = $parts[0] ?? null;
$action = $parts[1] ?? 'list';
$id = $parts[2] ?? null;

/********** INDEX / TABLE CHECK **********/
if (!$table) {
    renderHead($config['db_name'] .' 1.0');
    echo "<h1>".$config['db_name'] . " 1.0 ". "</h1><div class='mb-3'><a class='btn btn-primary' href='".e(url(''))."'>Índice</a></div><ul class='list-group'>";
    foreach (getTables($pdo) as $t) {
        echo "<li class='list-group-item d-flex justify-content-between align-items-center'><span>".e($t)."</span><a class='btn btn-sm btn-outline-primary' href='".e(url("$t/list"))."'>Abrir</a></li>";
    }
    echo "</ul>";
    renderFoot();
    exit;
}

$allTables = getTables($pdo);
if (!in_array($table, $allTables)) {
    http_response_code(404);
    renderHead('No encontrado');
    echo "<div class='alert alert-danger'>Tabla no encontrada: ".e($table)."</div>";
    echo "<a class='btn btn-secondary' href='".e(url())."'>Volver</a>";
    renderFoot();
    exit;
}

/********** CSV EXPORT HANDLER (must run BEFORE any HTML output) **********
 * This block will honor filters and sorting from $_GET (same logic as list)
 ***************************************************************/
if ($action === 'list' && isset($_GET['export']) && $_GET['export'] === 'csv') {
    // prepare meta
    $colsMeta = getColumns($pdo, $table);
    $pk = getPrimaryKey($pdo, $table);
    $fkMap = getForeignKeys($pdo, $table);

    // build WHERE and params from filters & global search (same as list)
    $where = []; $params = [];
    foreach ($colsMeta as $c) {
        $col = $c['COLUMN_NAME'];
        if (isset($_GET[$col]) && $_GET[$col] !== '') {
            $where[] = "`$col` LIKE :f_$col";
            $params["f_$col"] = '%' . $_GET[$col] . '%';
        }
    }
    if (!empty($_GET['q'])) {
        $q = $_GET['q'];
        $sub = [];
        foreach ($colsMeta as $c) {
            $col = $c['COLUMN_NAME'];
            $sub[] = "`$col` LIKE :g_$col";
            $params["g_$col"] = "%$q%";
        }
        if ($sub) $where[] = '(' . implode(' OR ', $sub) . ')';
    }
    $whereSQL = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    // ordering
    $reqSort = $_GET['sort'] ?? null;
    $reqDir = strtolower($_GET['dir'] ?? 'asc');
    $reqDir = $reqDir === 'desc' ? 'DESC' : 'ASC';
    $sortCol = sanitizeOrderCol($colsMeta, $reqSort);

    
    $orderSQL = $sortCol ? "ORDER BY `$sortCol` $reqDir" : '';

    // fetch all matching rows (no pagination for export)
    $sql = "SELECT * FROM `$table` $whereSQL $orderSQL";
    //print_r($sql);die();
    $stmt = $pdo->prepare($sql);
    foreach ($params as $k=>$v) $stmt->bindValue(':' . $k, $v);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Send CSV headers (must not have emitted any HTML before)
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=' . preg_replace('/[^a-z0-9._-]/i','_', $table) . '.csv');

    $out = fopen('php://output','w');
    // header row
    $header = array_column($colsMeta, 'COLUMN_NAME');
    // fputcsv with explicit escape parameter to avoid deprecation warnings in PHP 8.2+
    fputcsv($out, $header, ',', '"', "\\");

    // rows
    foreach ($rows as $r) {
        $line = [];
        foreach ($colsMeta as $c) {
            $col = $c['COLUMN_NAME'];
            $val = $r[$col] ?? '';

            if (isset($fkMap[$col])) {
                [$rt,$rc] = $fkMap[$col];
                $disp = getDisplayColumn($pdo, $rt);
                $qstmt = $pdo->prepare("SELECT `$disp` FROM `$rt` WHERE `$rc` = ? LIMIT 1");
                $qstmt->execute([$val]);
                $val = $qstmt->fetchColumn() ?: $val;
            }

            if ($col === 'ultima_vez_visto' || preg_match('/ultima|ultimo|visto|last|seen/i', $col)) {
                if ($val) {
                    $ts = strtotime($val);
                    $val = $ts ? timeAgoTs($ts) . ' ago' : $val;
                } else {
                    $val = 'Nunca';
                }
            }

            $line[] = $val;
        }
        fputcsv($out, $line, ',', '"', "\\");
    }

    fclose($out);
    exit;
}

/********** ACTION: LIST **********/
if ($action === 'list') {
    $colsMeta = getColumns($pdo, $table);
    $pk = getPrimaryKey($pdo, $table);
    
    $fksRaw = getForeignKeys($pdo, $table);
    $fkMap = [];
    
    if (is_array($fksRaw)) {
        foreach ($fksRaw as $fk) {
            // defender contra filas inesperadas
            if (!is_array($fk)) continue;
            if (!isset($fk['COLUMN_NAME']) || !isset($fk['REFERENCED_TABLE_NAME']) || !isset($fk['REFERENCED_COLUMN_NAME'])) {
                // fila inesperada: omitirla
                continue;
            }
            $fkMap[$fk['COLUMN_NAME']] = [$fk['REFERENCED_TABLE_NAME'], $fk['REFERENCED_COLUMN_NAME']];
        }
    }
    // Pagination
    $page = max(1, intval($_GET['page'] ?? 1));
    $limit = $itemsPerPage;
    $offset = ($page - 1) * $limit;

    // Sorting
    $reqSort = $_GET['sort'] ?? null;
    $reqDir = strtolower($_GET['dir'] ?? 'asc');
    $reqDir = $reqDir === 'desc' ? 'DESC' : 'ASC';
    $sortCol = sanitizeOrderCol($colsMeta, $reqSort);
    
    if ($sortCol === 'ip') {        
        $orderSQL = $sortCol ? "ORDER BY INET_ATON(`$sortCol`) $reqDir" : '';
    } else {
        $orderSQL = $sortCol ? "ORDER BY `$sortCol` $reqDir" : '';
    }
    
    // Filters & global search
    $where = []; $params = [];
    foreach ($colsMeta as $c) {
        $col = $c['COLUMN_NAME'];
        if (isset($_GET[$col]) && $_GET[$col] !== '') {
            $where[] = "`$col` LIKE :f_$col";
            $params["f_$col"] = '%' . $_GET[$col] . '%';
        }
    }
    if (!empty($_GET['q'])) {
        $q = $_GET['q'];
        $sub = [];
        foreach ($colsMeta as $c) {
            $col = $c['COLUMN_NAME'];
            $sub[] = "`$col` LIKE :g_$col";
            $params["g_$col"] = "%$q%";
        }
        if ($sub) $where[] = '(' . implode(' OR ', $sub) . ')';
    }
    $whereSQL = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

    // Count total
    $cntStmt = $pdo->prepare("SELECT COUNT(*) FROM `$table` $whereSQL");
    $cntStmt->execute($params);
    $total = (int)$cntStmt->fetchColumn();
    $pages = max(1, (int)ceil($total / $limit));

    // Fetch page
    $sql = "SELECT * FROM `$table` $whereSQL $orderSQL LIMIT :l OFFSET :o";
    $stmt = $pdo->prepare($sql);
    foreach ($params as $k=>$v) $stmt->bindValue(':' . $k, $v);
    $stmt->bindValue(':l', (int)$limit, PDO::PARAM_INT);
    $stmt->bindValue(':o', (int)$offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();

    // Render HTML (no change in aspect)
    renderHead("Listado: $table");
    echo "<div class='d-flex justify-content-between align-items-center mb-3'><h4>".e($table)."</h4><div><a class='btn btn-success btn-sm' href='".e(url("$table/create"))."'>Crear</a> <a class='btn btn-outline-secondary btn-sm' href='".e(url())."'>Tablas</a></div></div>";

    // Filters form
    echo "<form class='card card-body mb-3' method='GET' novalidate>";
    echo "<div class='row gx-2 gy-2 align-items-end'>";
    echo "<div class='col-auto'><label class='form-label small-muted'>Buscar</label><input class='form-control' name='q' value='".e($_GET['q'] ?? '')."' placeholder='texto libre'></div>";
    foreach ($colsMeta as $c) {
        $col = $c['COLUMN_NAME'];
        $val = $_GET[$col] ?? '';
        echo "<div class='col-auto'><label class='form-label small-muted'>".e($col)."</label><input class='form-control' name='".e($col)."' value='".e($val)."' placeholder=''></div>";
    }
    echo "<input type='hidden' name='sort' value='".e($_GET['sort'] ?? '')."'>";
    echo "<input type='hidden' name='dir' value='".e($_GET['dir'] ?? '')."'>";
    echo "<div class='col-auto'><button class='btn btn-primary'>Aplicar</button> <a class='btn btn-outline-secondary' href='".e(url("$table/list"))."'>Limpiar</a></div>";
    echo "</div></form>";

    // Export CSV button (preserves current filters & sort)
    $qsExport = $_GET;
    $qsExport['export'] = 'csv';
    $hrefExport = url("$table/list") . '?' . http_build_query($qsExport);
    echo "<div class='mb-2'><a class='btn btn-outline-success' href='".e($hrefExport)."'>Exportar CSV</a></div>";

    // Table
    echo "<div class='table-responsive'><table class='table table-striped table-bordered'>";
    echo "<thead class='table-light'><tr>";
    $baseQS = $_GET;
    foreach ($colsMeta as $c) {
        $col = $c['COLUMN_NAME'];
        $dirToggle = (($reqSort === $col && strtoupper($reqDir) === 'ASC') ? 'desc' : 'asc');
        $qs = $baseQS;
        $qs['sort'] = $col;
        $qs['dir'] = $dirToggle;
        $href = url($table . '/list') . '?' . http_build_query($qs);
        $arrow = ($reqSort === $col) ? (strtoupper($reqDir)==='ASC' ? ' ▲' : ' ▼') : '';
        echo "<th><a href='".e($href)."'>".e($col).$arrow."</a></th>";
    }
    echo "<th>Acciones</th></tr></thead><tbody>";

    foreach ($rows as $r) {
        echo "<tr>";
        foreach ($colsMeta as $c) {
            $col = $c['COLUMN_NAME'];
            $val = $r[$col] ?? '';

            // FK
            if (isset($fkMap[$col])) {
                [$refTable,$refCol] = $fkMap[$col];
                $disp = getDisplayColumn($pdo, $refTable);
                $qstmt = $pdo->prepare("SELECT `$disp` FROM `$refTable` WHERE `$refCol` = ? LIMIT 1");
                $qstmt->execute([$val]);
                $val = $qstmt->fetchColumn() ?: $val;
            }

            // ultima_vez_visto display
            if ($col === 'ultima_vez_visto' || preg_match('/ultima|ultimo|visto|last|seen/i', $col)) {
                if ($val) { $ts = strtotime($val); $val = $ts ? timeAgoTs($ts) . ' ago' : $val; } else { $val = 'Nunca'; }
            }

            echo "<td>".e($val)."</td>";
        }

        $idv = $pk ? $r[$pk] : '';
        echo "<td class='text-nowrap'>";
        echo "<a class='btn btn-sm btn-primary me-1' href='".e(url("$table/edit/".rawurlencode($idv)))."'>Editar</a>";
        echo "<form class='d-inline' method='POST' action='".e(url("$table/delete/".rawurlencode($idv)))."' onsubmit=\"return confirm('¿Borrar?');\">";
        echo "<input type='hidden' name='_csrf' value='".e(csrf_token())."'>";
        echo "<button class='btn btn-sm btn-danger' type='submit'>Borrar</button>";
        echo "</form>";
        echo "</td>";

        echo "</tr>";
        
    }
    echo "</tbody></table>";
    
    if ( $table == "equipos" ) {
    
        $subnet = obtenerSubredParaNmap();
                
        echo "<h3 style='margin-top:40px'>Equipos en la red ".e($subnet)."</h3>";
        echo "<p>Mediante escaneo Nmap ARP/Ping.</p>";
        
        $detected = scanNetworkNmap();
        
        // Obtener todos los equipos existentes en la BD
        $dbMacs = $pdo->query("SELECT ip,mac FROM equipos")->fetchAll();
        
        $nuevos = [];
        foreach ($detected as $h) {
            $mac = array_column($dbMacs, "mac");
            $ip = array_column($dbMacs, "ip");
            
            if (($h['mac'] && !in_array($h['mac'], $mac)) ||
                ($h['ip'] && !in_array($h['ip'], $ip))) {
                $nuevos[] = $h;            
            }
        }        
        if (!$nuevos) {
            echo "<p>No hay equipos nuevos detectados.</p>";
        } else {
            echo "<table class='table table-bordered table-striped'>";
            echo "<thead><tr>
                    <th>IP</th>
                    <th>HOSTNAME</th>
                    <th>MAC</th>
                    <th>Fabricante</th>
                    <th>Acción</th>
                  </tr></thead><tbody>";
        
            foreach ($nuevos as $n) {
                array_key_exists('ip', $n) ? : $n['ip'] = '';
                array_key_exists('hostname', $n) ? : $n['hostname'] = '';
                array_key_exists('mac', $n) ? : $n['mac'] = '';
                array_key_exists('vendor', $n) ? : $n['vendor'] = '';
                echo "<tr>";
                echo "<td>{$n['ip']}</td>";
                echo "<td>{$n['hostname']}</td>";
                echo "<td>{$n['mac']}</td>";
                echo "<td>{$n['vendor']}</td>";
        
                echo "<td>
                    <form method='POST' action='/inventa/equipos/trust' style='display:inline'>
                    <input type='hidden' name='ip'       value='".e($n['ip'])."'>
                    <input type='hidden' name='hostname' value='".e($n['hostname']),"'>
                    <input type='hidden' name='mac'      value='".e($n['mac'])."'>
                    <input type='hidden' name='vendor'      value='".e($n['vendor'])."'>
                    <button class='button' style='background:green'>TRUST</button>
                    </form>
                </td>";
        
                echo "</tr>";
            }
        }
        echo "</tbody></table></div>";
    
    }

    // Pagination
    echo "<nav aria-label='pager'><ul class='pagination'>";
    $pagesToShow = 7;
    $start = max(1, $page - intval($pagesToShow/2));
    $end = min($pages, $start + $pagesToShow - 1);
    if ($start > 1) { $baseQS['page'] = 1; echo "<li class='page-item'><a class='page-link' href='".e(url("$table/list").'?'.http_build_query($baseQS))."'>&laquo;</a></li>"; }
    for ($p = $start; $p <= $end; $p++) {
        $baseQS['page'] = $p;
        $active = $p == $page ? ' active' : '';
        echo "<li class='page-item$active'><a class='page-link' href='".e(url("$table/list").'?'.http_build_query($baseQS))."'>$p</a></li>";
    }
    if ($end < $pages) { $baseQS['page'] = $pages; echo "<li class='page-item'><a class='page-link' href='".e(url("$table/list").'?'.http_build_query($baseQS))."'>»</a></li>"; }
    echo "</ul></nav>";

    renderFoot();
    exit;
}

if ($action === 'trust') {
    trustDevice($pdo);
}

/********** ACTION: CREATE / EDIT **********/
if ($action === 'create' || $action === 'edit') {
    $colsMeta = getColumns($pdo, $table);
    $pk = getPrimaryKey($pdo, $table);
    $fksRaw = getForeignKeys($pdo, $table);
    $fkMap = [];
    foreach ($fksRaw as $fk) $fkMap[$fk['COLUMN_NAME']] = [$fk['REFERENCED_TABLE_NAME'],$fk['REFERENCED_COLUMN_NAME']];

    $entity = [];
    if ($action === 'edit') {
        if (!$id) { http_response_code(400); echo "ID faltante"; exit; }
        $stmt = $pdo->prepare("SELECT * FROM `$table` WHERE `$pk` = ? LIMIT 1");
        $stmt->execute([$id]);
        $entity = $stmt->fetch() ?: [];
    }

    // Process POST (create/update)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!check_csrf($_POST['_csrf'] ?? null)) { http_response_code(403); echo "CSRF inválido"; exit; }

        $data = [];
        foreach ($colsMeta as $c) {
            $name = $c['COLUMN_NAME'];
            if ($name === $pk) continue;
            $data[$name] = array_key_exists($name, $_POST) ? ($_POST[$name] === '' ? null : $_POST[$name]) : null;
        }

        $rules = buildValidationRules($colsMeta);
        $errors = validateData($data, $rules);
        if ($errors) {
            renderHead('Errores'); echo "<div class='alert alert-danger'><ul>";
            foreach ($errors as $f=>$m) echo "<li>".e($f).": ".e($m)."</li>";
            echo "</ul></div>";
            $entity = array_merge($entity, $data);
        } else {
            if ($action === 'create') {
                $fields = array_keys($data);
                $placeholders = implode(',', array_fill(0, count($fields), '?'));
                $sql = "INSERT INTO `$table` (`".implode('`,`',$fields)."`) VALUES ($placeholders)";
                $stmt = $pdo->prepare($sql);
                $stmt->execute(array_values($data));
                header('Location: ' . url("$table/list")); exit;
            } else {
                $set = implode(',', array_map(fn($n) => "`$n` = ?", array_keys($data)));
                $sql = "UPDATE `$table` SET $set WHERE `$pk` = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([...array_values($data), $id]);
                header('Location: ' . url("$table/list")); exit;
            }
        }
    }

    // Render form
    renderHead(($action==='create'?'Crear':'Editar')." $table");
    echo "<div class='card'><div class='card-body'>";
    echo "<h4 class='card-title'>".e($action === 'create' ? "Crear" : "Editar") . " ".e($table)."</h4>";
    echo "<form method='POST'>";
    echo "<input type='hidden' name='_csrf' value='".e(csrf_token())."'>";

    foreach ($colsMeta as $c) {
        $name = $c['COLUMN_NAME'];
        $colType = strtolower($c['DATA_TYPE']);
        if ($c['EXTRA'] && stripos($c['EXTRA'],'auto_increment')!==false && $action==='create') continue;

        $value = $_POST[$name] ?? ($entity[$name] ?? '');
        echo "<div class='mb-3'>";
        echo "<label class='form-label'>".e($name)."</label>";

        // FK -> select
        if (isset($fkMap[$name])) {
            [$refTable,$refCol] = $fkMap[$name];
            $disp = getDisplayColumn($pdo, $refTable);
            $opts = $pdo->query("SELECT `$refCol`, `$disp` FROM `$refTable` ORDER BY `$disp`")->fetchAll();
            echo "<select name='".e($name)."' class='form-select'><option value=''>--</option>";
            foreach ($opts as $opt) {
                $optVal = $opt[$refCol];
                $sel = ((string)$optVal === (string)$value) ? " selected" : "";
                $label = $opt[$disp] ?? $optVal;
                echo "<option value='".e($optVal)."'$sel>".e($label)."</option>";
            }
            echo "</select>";
            echo "</div>";
            continue;
        }

        // choose input type
        $inputType = 'text';
        if (in_array($colType, ['int','tinyint','smallint','mediumint','bigint'])) $inputType = 'number';
        if (in_array($colType, ['decimal','float','double'])) $inputType = 'number';
        if (in_array($colType, ['date'])) $inputType = 'date';
        if (in_array($colType, ['datetime','timestamp'])) $inputType = 'datetime-local';
        if (in_array($colType, ['time'])) $inputType = 'time';

        // format datetime-local
        if ($inputType === 'datetime-local' && $value !== '' && $value !== null) {
            try { $dt = new DateTime($value); $value = $dt->format('Y-m-d\TH:i:s'); } catch(Exception $ex){ $value = str_replace(' ','T',$value); }
        }

        if (stripos($c['COLUMN_TYPE'],'text') !== false) {
            echo "<textarea name='".e($name)."' class='form-control' rows='3'>".e($value)."</textarea>";
        } else {
            echo "<input class='form-control' type='".e($inputType)."' name='".e($name)."' value='".e($value)."'>";
        }
        echo "</div>";
    }

    echo "<div class='d-flex gap-2'><button class='btn btn-primary' type='submit'>".($action==='create'?'Crear':'Actualizar')."</button>";
    echo "<a class='btn btn-outline-secondary' href='".e(url("$table/list"))."'>Cancelar</a></div>";

    echo "</form></div></div>";
    renderFoot();
    exit;
}

/********** DELETE **********/
if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!check_csrf($_POST['_csrf'] ?? null)) { http_response_code(403); echo "CSRF inválido"; exit; }
    $pk = getPrimaryKey($pdo, $table);
    $stmt = $pdo->prepare("DELETE FROM `$table` WHERE `$pk` = ?");
    $stmt->execute([$id]);
    header('Location: ' . url("$table/list"));
    exit;
}

/********** VALIDATION HELPERS **********/
function buildValidationRules(array $columns) {
    $rules = [];
    foreach ($columns as $c) {
        $name = $c['COLUMN_NAME']; $type = $c['DATA_TYPE'];
        $rule = ['required' => $c['IS_NULLABLE'] === 'NO' && $c['COLUMN_DEFAULT'] === null && stripos($c['EXTRA'],'auto_increment')===false];
        if (in_array($type,['int','tinyint','smallint','mediumint','bigint'])) $rule['type']='int';
        elseif (in_array($type,['decimal','float','double'])) $rule['type']='float';
        elseif (in_array($type,['date','datetime','timestamp','time','year'])) $rule['type']='date';
        else $rule['type']='string';
        $rule['max'] = !empty($c['CHARACTER_MAXIMUM_LENGTH']) ? (int)$c['CHARACTER_MAXIMUM_LENGTH'] : null;
        $rules[$name] = $rule;
    }
    return $rules;
}
function validateData(array $input, array $rules) {
    $errors = [];
    foreach ($rules as $field=>$r){
        $val = array_key_exists($field,$input)?$input[$field]:null;
        if ($r['required'] && ($val === null || $val === '')) { $errors[$field]='Obligatorio.'; continue; }
        if ($val === null || $val === '') continue;
        switch ($r['type']) {
            case 'int': if (!filter_var($val,FILTER_VALIDATE_INT)) $errors[$field]='Debe ser entero.'; break;
            case 'float': if (!is_numeric($val)) $errors[$field]='Debe ser numérico.'; break;
            case 'date': if (!strtotime(str_replace('T',' ',$val))) $errors[$field]='Fecha inválida.'; break;
            case 'string': if ($r['max'] && mb_strlen($val) > $r['max']) $errors[$field]="Máximo {$r['max']} caracteres."; break;
        }
    }
    return $errors;
}

/********** FALLBACK 404 **********/
http_response_code(404);
renderHead('No encontrado');
echo "<div class='alert alert-warning'>Acción no encontrada</div>";
renderFoot();
exit;
?>
