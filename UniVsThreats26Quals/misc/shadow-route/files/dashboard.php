<?php
session_start();
if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    header('Location: index.php');
    exit;
}

$message = '';
$msg_type = '';

if (isset($_POST['upload_telemetry']) && isset($_FILES['datafile'])) {
    $target_dir = '/var/www/html/cosmos-data/';
    $filename = basename($_FILES['datafile']['name']);
    
    // "Security" filter - only allows certain extensions (but can be bypassed)
    $allowed = array('txt', 'csv', 'dat', 'log', 'php');
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    
    // Check file size (max 500KB)
    if ($_FILES['datafile']['size'] > 500000) {
        $message = "ERROR: File exceeds maximum telemetry packet size (500KB).";
        $msg_type = 'error';
    } elseif (!in_array($ext, $allowed)) {
        $message = "ERROR: Unsupported data format. Accepted: " . implode(', ', $allowed);
        $msg_type = 'error';
    } else {
        if (move_uploaded_file($_FILES['datafile']['tmp_name'], $target_dir . $filename)) {
            $message = "Telemetry data '$filename' uploaded to data pipeline successfully.";
            $msg_type = 'success';
        } else {
            $message = "ERROR: Upload failed. Data pipeline may be offline.";
            $msg_type = 'error';
        }
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Helios Stargate - Mission Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #050510;
            color: #c0c0d0;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
        }
        .topbar {
            background: rgba(10, 10, 30, 0.95);
            border-bottom: 1px solid #0a4a7a;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .topbar h1 { color: #00d4ff; font-size: 1.1em; }
        .topbar .user-info { color: #5a7a9a; font-size: 0.85em; }
        .topbar .user-info span { color: #00ff88; }
        .topbar a { color: #ff4444; text-decoration: none; font-size: 0.85em; }
        .topbar a:hover { text-decoration: underline; }
        .main { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
        .nav-tabs {
            display: flex; gap: 0;
            border-bottom: 2px solid #0a4a7a;
            margin-bottom: 30px;
        }
        .nav-tab {
            padding: 12px 25px;
            background: rgba(10, 10, 30, 0.8);
            border: 1px solid #0a3a5a;
            border-bottom: none;
            color: #5a7a9a;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }
        .nav-tab.active {
            color: #00d4ff;
            background: rgba(0, 212, 255, 0.1);
            border-color: #0a4a7a;
        }
        .panel {
            background: rgba(10, 10, 30, 0.95);
            border: 1px solid #1a3a5a;
            padding: 30px;
            display: none;
        }
        .panel.active { display: block; }
        .panel h2 {
            color: #00d4ff; font-size: 1.1em; margin-bottom: 20px;
            border-bottom: 1px solid #1a3a5a; padding-bottom: 10px;
        }
        .upload-zone {
            border: 2px dashed #1a3a5a;
            padding: 30px;
            text-align: center;
            margin: 20px 0;
            background: rgba(0, 0, 20, 0.5);
        }
        .upload-zone:hover { border-color: #00d4ff; }
        input[type="file"] { color: #5a7a9a; margin: 15px 0; }
        .btn {
            padding: 10px 25px;
            background: linear-gradient(135deg, #0a4a7a, #00d4ff);
            border: none;
            color: #fff;
            font-family: 'Courier New', monospace;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn:hover { opacity: 0.8; }
        .msg-success { background: rgba(0,255,136,0.1); border: 1px solid #00ff88; padding: 12px; color: #00ff88; margin-bottom: 20px; }
        .msg-error { background: rgba(255,0,0,0.1); border: 1px solid #ff4444; padding: 12px; color: #ff4444; margin-bottom: 20px; }
        .data-table { width: 100%; border-collapse: collapse; }
        .data-table th { text-align: left; color: #00d4ff; padding: 8px; border-bottom: 1px solid #1a3a5a; font-size: 0.85em; }
        .data-table td { padding: 8px; border-bottom: 1px solid #0a1a2a; color: #7a7a9a; font-size: 0.85em; }
        .status-badge { padding: 3px 8px; border-radius: 3px; font-size: 0.75em; }
        .badge-ok { background: rgba(0,255,136,0.2); color: #00ff88; }
        .badge-warn { background: rgba(255,170,0,0.2); color: #ffaa00; }
        .profile-info { line-height: 2; }
        .profile-info span.label { color: #5a7a9a; display: inline-block; width: 200px; }
        .profile-info span.value { color: #00d4ff; }
        .hint { color: #2a3a4a; font-size: 0.75em; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>⬡ HELIOS STARGATE - MISSION DASHBOARD</h1>
        <div class="user-info">
            Logged in as: <span><?php echo htmlspecialchars($_SESSION['username']); ?></span>
            [<?php echo htmlspecialchars($_SESSION['role']); ?>]
            &nbsp;|&nbsp;
            <a href="?logout=1">[ DISCONNECT ]</a>
        </div>
    </div>

    <div class="main">
        <div class="nav-tabs">
            <div class="nav-tab active" onclick="showPanel('overview')">Mission Overview</div>
            <div class="nav-tab" onclick="showPanel('telemetry')">Telemetry Upload</div>
            <div class="nav-tab" onclick="showPanel('crew')">Crew Profile</div>
            <div class="nav-tab" onclick="showPanel('systems')">Systems</div>
        </div>

        <!-- OVERVIEW PANEL -->
        <div class="panel active" id="panel-overview">
            <h2>[MISSION OVERVIEW - CLASSIFIED]</h2>
            <table class="data-table">
                <tr><th>System</th><th>Status</th><th>Last Check</th></tr>
                <tr><td>Life Support</td><td><span class="status-badge badge-ok">NOMINAL</span></td><td>2 min ago</td></tr>
                <tr><td>Navigation</td><td><span class="status-badge badge-ok">ONLINE</span></td><td>5 min ago</td></tr>
                <tr><td>External Sensors</td><td><span class="status-badge badge-warn">DEGRADED</span></td><td>12 min ago</td></tr>
                <tr><td>Data Pipeline (cosmos-data)</td><td><span class="status-badge badge-ok">ACTIVE</span></td><td>1 min ago</td></tr>
                <tr><td>Orbital Sync (nova)</td><td><span class="status-badge badge-ok">RUNNING</span></td><td>cron: every 60s</td></tr>
            </table>
        </div>

        <!-- TELEMETRY UPLOAD PANEL -->
        <div class="panel" id="panel-telemetry">
            <h2>[TELEMETRY DATA UPLOAD]</h2>
            <p style="color: #5a7a9a; margin-bottom: 20px;">
                Upload sensor data, telemetry logs, or analysis scripts to the station's 
                data pipeline. Files are stored in the <span style="color:#00d4ff">/cosmos-data/</span> 
                directory for automated processing.
            </p>

            <?php if ($message): ?>
                <div class="msg-<?php echo $msg_type; ?>"><?php echo htmlspecialchars($message); ?></div>
            <?php endif; ?>

            <form method="POST" enctype="multipart/form-data">
                <div class="upload-zone">
                    <p style="color: #00d4ff; margin-bottom: 15px;">★ DROP TELEMETRY DATA HERE ★</p>
                    <input type="file" name="datafile" required>
                    <p style="color: #3a5a7a; font-size: 0.8em; margin-top: 10px;">
                        Accepted formats: .txt, .csv, .dat, .log, .php
                    </p>
                    <p style="color: #2a3a4a; font-size: 0.7em; margin-top: 5px;">
                        Max size: 500KB | Files processed by station AI
                    </p>
                </div>
                <button type="submit" name="upload_telemetry" class="btn">★ Upload to Pipeline ★</button>
            </form>
        </div>

        <!-- CREW PROFILE PANEL -->
        <div class="panel" id="panel-crew">
            <h2>[CREW PROFILE]</h2>
            <div class="profile-info">
                <p><span class="label">Crew ID:</span> <span class="value"><?php echo htmlspecialchars($_SESSION['username']); ?></span></p>
                <p><span class="label">Role:</span> <span class="value"><?php echo htmlspecialchars($_SESSION['role']); ?></span></p>
                <p><span class="label">Station Assignment:</span> <span class="value">Helios Prime</span></p>
                <p><span class="label">Division:</span> <span class="value">Telemetry & Data Analysis</span></p>
                <p><span class="label">Clearance Level:</span> <span class="value">LEVEL 2</span></p>
                <p><span class="label">File Archive Access:</span> <span class="value">Enabled</span></p>
                <p><span class="label">Last Login:</span> <span class="value"><?php echo date('Y-m-d H:i:s'); ?> UTC</span></p>
            </div>
        </div>

        <!-- SYSTEMS PANEL -->
        <div class="panel" id="panel-systems">
            <h2>[STATION SYSTEMS - RESTRICTED]</h2>
            <p style="color: #ff4444; margin-bottom: 20px;">
                ⚠ Some systems require LEVEL 3+ clearance. Your current level: LEVEL 2.
            </p>
        </div>
    </div>

    <script>
        function showPanel(name) {
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
            document.getElementById('panel-' + name).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
