<?php

session_start();

$db_path = '/var/www/data/helios.db';

if (isset($_POST['username']) && isset($_POST['password'])) {
    $db = new SQLite3($db_path);
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $stmt = $db->prepare("SELECT * FROM crew WHERE username = :user");
    $stmt->bindValue(':user', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    
    if ($row = $result->fetchArray()) {
        $stored_hash = $row['password_hash'];
        if (crypt($password, $stored_hash) === $stored_hash) {
            $_SESSION['authenticated'] = true;
            $_SESSION['username'] = $row['username'];
            $_SESSION['role'] = $row['role'];
            header('Location: dashboard.php');
            exit;
        }
    }
    $error = "ACCESS DENIED - Invalid credentials or insufficient clearance level.";
    $db->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Helios Stargate - Crew Authentication</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #050510;
            color: #c0c0d0;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .gate-container {
            width: 420px;
            background: rgba(10, 10, 30, 0.95);
            border: 2px solid #0a4a7a;
            padding: 40px;
            position: relative;
        }
        .gate-container::before {
            content: '';
            position: absolute;
            top: -2px; left: -2px; right: -2px; bottom: -2px;
            background: linear-gradient(45deg, #00d4ff, #0a4a7a, #00ff88, #0a4a7a);
            z-index: -1;
            animation: glow 3s ease-in-out infinite;
        }
        @keyframes glow {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #00d4ff;
            font-size: 1.5em;
            text-shadow: 0 0 15px rgba(0, 212, 255, 0.5);
        }
        .logo p {
            color: #3a5a7a;
            font-size: 0.75em;
            margin-top: 5px;
        }
        .warning-bar {
            background: rgba(255, 170, 0, 0.1);
            border: 1px solid #ffaa00;
            padding: 10px;
            text-align: center;
            margin-bottom: 25px;
            font-size: 0.75em;
            color: #ffaa00;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #5a7a9a;
            font-size: 0.8em;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px;
            background: #0a0a2a;
            border: 1px solid #1a3a5a;
            color: #00d4ff;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            outline: none;
        }
        input:focus {
            border-color: #00d4ff;
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.2);
        }
        .btn-auth {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #0a4a7a, #00d4ff);
            border: none;
            color: #fff;
            font-family: 'Courier New', monospace;
            font-size: 1em;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-top: 10px;
        }
        .btn-auth:hover {
            background: linear-gradient(135deg, #00d4ff, #0a4a7a);
        }
        .error {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff4444;
            padding: 10px;
            color: #ff4444;
            font-size: 0.8em;
            margin-bottom: 20px;
            text-align: center;
        }
        .footer-note {
            text-align: center;
            margin-top: 20px;
            font-size: 0.7em;
            color: #2a2a4a;
        }
    </style>
</head>
<body>
    <div class="gate-container">
        <div class="logo">
            <h1>⬡ STARGATE PORTAL ⬡</h1>
            <p>HELIOS STATION INTERNAL SYSTEMS</p>
        </div>
        
        <div class="warning-bar">
            ⚠ RESTRICTED ACCESS - CREW AUTHENTICATION REQUIRED ⚠
        </div>

        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <form method="POST" action="">
            <div class="form-group">
                <label>Crew Identifier</label>
                <input type="text" name="username" placeholder="Enter crew ID..." required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Access Code</label>
                <input type="password" name="password" placeholder="Enter access code..." required>
            </div>
            <button type="submit" class="btn-auth">★ Authenticate ★</button>
        </form>

        <div class="footer-note">
            <p>Helios Station Security Protocol v2.1</p>
            <p>All access attempts are logged.</p>
        </div>
    </div>
</body>
</html>
