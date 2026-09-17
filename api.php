<?php
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

/* =========================================================
   1. KONEKSI DATABASE
========================================================= */
$host = "localhost";
$user = "root";
$pass = "";
$db   = "savely";

$conn = mysqli_connect($host, $user, $pass, $db);

if (!$conn) {
    echo json_encode(["status" => false, "message" => "Koneksi database gagal: " . mysqli_connect_error()]);
    exit();
}

mysqli_set_charset($conn, "utf8mb4");

/* =========================================================
   2. HELPER RESPON & INPUT
========================================================= */
function sendResponse(int $statusCode, bool $status, string $message, $data = null): void 
{
    http_response_code($statusCode);
    echo json_encode([
        "status"  => $status,
        "message" => $message,
        "data"    => $data
    ]);
    exit();
}

// Mengambil request body berupa JSON
$inputData = json_decode(file_get_contents("php://input"), true) ?? [];

$requestMethod = $_SERVER['REQUEST_METHOD'];
$action        = $_GET['action'] ?? '';

/* =========================================================
   3. ROUTING & CONTROLLER
========================================================= */

switch ($action) {

    /* -----------------------------------------------------
       A. AUTHENTICATION
    ----------------------------------------------------- */
    case 'register':
        if ($requestMethod !== 'POST') sendResponse(405, false, "Method tidak diizinkan");

        $username = trim($inputData['username'] ?? '');
        $email    = trim($inputData['email'] ?? '');
        $password = $inputData['password'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            sendResponse(400, false, "Semua data (username, email, password) wajib diisi!");
        } elseif (strlen($username) < 3) {
            sendResponse(400, false, "Username minimal 3 karakter!");
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            sendResponse(400, false, "Format email tidak valid!");
        } elseif (strlen($password) < 6) {
            sendResponse(400, false, "Password minimal 6 karakter!");
        }

        // Cek ketersediaan email
        $check_stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ? LIMIT 1");
        mysqli_stmt_bind_param($check_stmt, "s", $email);
        mysqli_stmt_execute($check_stmt);
        $check_result = mysqli_stmt_get_result($check_stmt);

        if (mysqli_num_rows($check_result) > 0) {
            sendResponse(400, false, "Email sudah terdaftar!");
        }

        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $insert_stmt    = mysqli_prepare($conn, "INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        mysqli_stmt_bind_param($insert_stmt, "sss", $username, $email, $hashedPassword);

        if (mysqli_stmt_execute($insert_stmt)) {
            sendResponse(201, true, "Pendaftaran berhasil! Silakan login.");
        } else {
            sendResponse(500, false, "Gagal membuat akun!");
        }
        break;

    case 'login':
        if ($requestMethod !== 'POST') sendResponse(405, false, "Method tidak diizinkan");

        $email    = trim($inputData['email'] ?? '');
        $password = $inputData['password'] ?? '';

        if ($email === '' || $password === '') {
            sendResponse(400, false, "Email dan password wajib diisi!");
        }

        $stmt = mysqli_prepare($conn, "SELECT id, username, password FROM users WHERE email = ? LIMIT 1");
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result   = mysqli_stmt_get_result($stmt);
        $userData = mysqli_fetch_assoc($result);

        if ($userData && password_verify($password, $userData['password'])) {
            unset($userData['password']);
            sendResponse(200, true, "Login berhasil!", $userData);
        } else {
            sendResponse(401, false, "Email atau password salah!");
        }
        break;


    /* -----------------------------------------------------
       B. GOALS (TARGET)
    ----------------------------------------------------- */
    case 'get_goals':
        if ($requestMethod !== 'GET') sendResponse(405, false, "Method tidak diizinkan");

        $user_id = (int)($_GET['user_id'] ?? 0);
        if ($user_id <= 0) sendResponse(400, false, "Parameter user_id tidak valid");

        $stmt = mysqli_prepare(
            $conn,
            "SELECT g.id, g.title, g.target_amount, g.deadline, 
                    COALESCE(SUM(s.amount), 0) AS collected
             FROM goals g
             LEFT JOIN savings s ON g.id = s.goal_id
             WHERE g.user_id = ?
             GROUP BY g.id, g.title, g.target_amount, g.deadline
             ORDER BY g.created_at DESC"
        );
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        $goals = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $row['target_amount'] = (float)$row['target_amount'];
            $row['collected']     = (float)$row['collected'];
            $goals[]              = $row;
        }

        sendResponse(200, true, "Data target berhasil diambil", $goals);
        break;

    case 'add_goal':
        if ($requestMethod !== 'POST') sendResponse(405, false, "Method tidak diizinkan");

        $user_id       = (int)($inputData['user_id'] ?? 0);
        $title         = trim($inputData['title'] ?? '');
        $target_amount = (float)($inputData['target_amount'] ?? 0);
        $deadline      = $inputData['deadline'] ?? '';

        if ($user_id <= 0 || $title === '' || $target_amount <= 0 || $deadline === '') {
            sendResponse(400, false, "Data input target tidak lengkap atau tidak valid!");
        }

        $stmt = mysqli_prepare($conn, "INSERT INTO goals (user_id, title, target_amount, deadline) VALUES (?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, "isds", $user_id, $title, $target_amount, $deadline);

        if (mysqli_stmt_execute($stmt)) {
            sendResponse(201, true, "Target berhasil ditambahkan");
        } else {
            sendResponse(500, false, "Gagal menambahkan target");
        }
        break;

    case 'delete_goal':
        if ($requestMethod !== 'DELETE') sendResponse(405, false, "Method tidak diizinkan");

        $id      = (int)($_GET['id'] ?? 0);
        $user_id = (int)($_GET['user_id'] ?? 0);

        if ($id <= 0 || $user_id <= 0) sendResponse(400, false, "Parameter id atau user_id tidak valid");

        // Hapus tabungan terkait lebih dahulu
        $stmt_s = mysqli_prepare($conn, "DELETE FROM savings WHERE goal_id = ? AND user_id = ?");
        mysqli_stmt_bind_param($stmt_s, "ii", $id, $user_id);
        mysqli_stmt_execute($stmt_s);

        // Hapus target
        $stmt_g = mysqli_prepare($conn, "DELETE FROM goals WHERE id = ? AND user_id = ?");
        mysqli_stmt_bind_param($stmt_g, "ii", $id, $user_id);

        if (mysqli_stmt_execute($stmt_g)) {
            sendResponse(200, true, "Target dan riwayat tabungan terkait berhasil dihapus");
        } else {
            sendResponse(500, false, "Gagal menghapus target");
        }
        break;


    /* -----------------------------------------------------
       C. SAVINGS (TABUNGAN)
    ----------------------------------------------------- */
    case 'get_savings':
        if ($requestMethod !== 'GET') sendResponse(405, false, "Method tidak diizinkan");

        $user_id = (int)($_GET['user_id'] ?? 0);
        if ($user_id <= 0) sendResponse(400, false, "Parameter user_id tidak valid");

        $stmt = mysqli_prepare(
            $conn,
            "SELECT s.id, s.goal_id, s.amount, s.savings_date, s.note, g.title AS goal_title
             FROM savings s
             INNER JOIN goals g ON s.goal_id = g.id
             WHERE s.user_id = ? AND g.user_id = ?
             ORDER BY s.savings_date DESC, s.id DESC"
        );
        mysqli_stmt_bind_param($stmt, "ii", $user_id, $user_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);

        $savings = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $row['amount'] = (float)$row['amount'];
            $savings[]     = $row;
        }

        sendResponse(200, true, "Data riwayat tabungan berhasil diambil", $savings);
        break;

    case 'add_saving':
        if ($requestMethod !== 'POST') sendResponse(405, false, "Method tidak diizinkan");

        $user_id = (int)($inputData['user_id'] ?? 0);
        $goal_id = (int)($inputData['goal_id'] ?? 0);
        $amount  = (float)($inputData['amount'] ?? 0);
        $date    = $inputData['savings_date'] ?? date('Y-m-d');
        $note    = trim($inputData['note'] ?? '');

        if ($user_id <= 0 || $goal_id <= 0 || $amount <= 0) {
            sendResponse(400, false, "Data input tabungan tidak valid!");
        }

        // Verifikasi kepemilikan target
        $check_goal = mysqli_prepare($conn, "SELECT id FROM goals WHERE id = ? AND user_id = ? LIMIT 1");
        mysqli_stmt_bind_param($check_goal, "ii", $goal_id, $user_id);
        mysqli_stmt_execute($check_goal);
        if (mysqli_num_rows(mysqli_stmt_get_result($check_goal)) === 0) {
            sendResponse(403, false, "Target tidak ditemukan atau bukan milik pengguna ini");
        }

        $stmt = mysqli_prepare($conn, "INSERT INTO savings (user_id, goal_id, amount, savings_date, note) VALUES (?, ?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, "iidss", $user_id, $goal_id, $amount, $date, $note);

        if (mysqli_stmt_execute($stmt)) {
            sendResponse(201, true, "Catatan tabungan berhasil ditambahkan");
        } else {
            sendResponse(500, false, "Gagal menambahkan tabungan");
        }
        break;

    case 'delete_saving':
        if ($requestMethod !== 'DELETE') sendResponse(405, false, "Method tidak diizinkan");

        $id      = (int)($_GET['id'] ?? 0);
        $user_id = (int)($_GET['user_id'] ?? 0);

        if ($id <= 0 || $user_id <= 0) sendResponse(400, false, "Parameter id atau user_id tidak valid");

        $stmt = mysqli_prepare($conn, "DELETE FROM savings WHERE id = ? AND user_id = ?");
        mysqli_stmt_bind_param($stmt, "ii", $id, $user_id);

        if (mysqli_stmt_execute($stmt)) {
            sendResponse(200, true, "Catatan tabungan berhasil dihapus");
        } else {
            sendResponse(500, false, "Gagal menghapus tabungan");
        }
        break;

    /* -----------------------------------------------------
       D. SUMMARY (DASHBOARD)
    ----------------------------------------------------- */
    case 'get_summary':
        if ($requestMethod !== 'GET') sendResponse(405, false, "Method tidak diizinkan");

        $user_id = (int)($_GET['user_id'] ?? 0);
        if ($user_id <= 0) sendResponse(400, false, "Parameter user_id tidak valid");

        // Total saved
        $stmt1 = mysqli_prepare($conn, "SELECT COALESCE(SUM(amount), 0) AS total FROM savings WHERE user_id = ?");
        mysqli_stmt_bind_param($stmt1, "i", $user_id);
        mysqli_stmt_execute($stmt1);
        $total_saved = (float)(mysqli_fetch_assoc(mysqli_stmt_get_result($stmt1))['total'] ?? 0);

        // Total target
        $stmt2 = mysqli_prepare($conn, "SELECT COALESCE(SUM(target_amount), 0) AS total FROM goals WHERE user_id = ?");
        mysqli_stmt_bind_param($stmt2, "i", $user_id);
        mysqli_stmt_execute($stmt2);
        $total_target = (float)(mysqli_fetch_assoc(mysqli_stmt_get_result($stmt2))['total'] ?? 0);

        // Main Goal (Target Utama)
        $stmt3 = mysqli_prepare(
            $conn,
            "SELECT g.id, g.title, g.target_amount, g.deadline, COALESCE(SUM(s.amount), 0) AS collected
             FROM goals g
             LEFT JOIN savings s ON g.id = s.goal_id
             WHERE g.user_id = ?
             GROUP BY g.id, g.title, g.target_amount, g.deadline
             ORDER BY g.created_at DESC LIMIT 1"
        );
        mysqli_stmt_bind_param($stmt3, "i", $user_id);
        mysqli_stmt_execute($stmt3);
        $main_goal = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt3));

        if ($main_goal) {
            $main_goal['target_amount'] = (float)$main_goal['target_amount'];
            $main_goal['collected']     = (float)$main_goal['collected'];
        }

        sendResponse(200, true, "Ringkasan data berhasil diambil", [
            "total_saved"  => $total_saved,
            "total_target" => $total_target,
            "main_goal"    => $main_goal
        ]);
        break;

    default:
        sendResponse(404, false, "Endpoint atau aksi tidak ditemukan!");
        break;
}