<?php
session_start();

/* =========================================================
   1. KONEKSI DATABASE
========================================================= */
$host = "localhost";
$user = "root";
$pass = "";
$db   = "savely";

$conn = mysqli_connect($host, $user, $pass, $db);

if (!$conn) {
    die("Koneksi database gagal: " . mysqli_connect_error());
}

mysqli_set_charset($conn, "utf8mb4");


/* =========================================================
   2. HELPER
========================================================= */
function e($text): string
{
    return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
}

function rupiah($number): string
{
    return 'Rp' . number_format((float)$number, 0, ',', '.');
}

function redirectTo(string $url): void
{
    header("Location: $url");
    exit();
}


/* =========================================================
function redirectTo(string $url): void
{
    if (strpos($url, 'index.php') === 0) {
        $url = '/' . substr($url, 9);
    }
    
    header("Location: $url");
    exit();
}

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();

    redirectTo("index.php");
}


/* =========================================================
   4. AUTHENTICATION
========================================================= */
$auth_error   = '';
$auth_success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['auth_type'])) {

    $auth_type = $_POST['auth_type'];

    /* =========================
       LOGIN
    ========================= */
    if ($auth_type === 'login') {

        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($email === '' || $password === '') {

            $auth_error = "Email dan password wajib diisi!";

        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

            $auth_error = "Format email tidak valid!";

        } else {

            $stmt = mysqli_prepare(
                $conn,
                "SELECT id, username, password 
                 FROM users 
                 WHERE email = ? 
                 LIMIT 1"
            );

            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);

            $result = mysqli_stmt_get_result($stmt);
            $userData = mysqli_fetch_assoc($result);

            if ($userData && password_verify($password, $userData['password'])) {

                session_regenerate_id(true);

                $_SESSION['user_id']  = (int)$userData['id'];
                $_SESSION['username'] = $userData['username'];

                mysqli_stmt_close($stmt);

                redirectTo("index.php");

            } else {

                $auth_error = "Email atau password salah!";
            }

            mysqli_stmt_close($stmt);
        }
    }


    /* =========================
       REGISTER
    ========================= */
    elseif ($auth_type === 'register') {

        $username = trim($_POST['username'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === '' || $email === '' || $password === '') {

            $auth_error = "Semua data wajib diisi!";

        } elseif (strlen($username) < 3) {

            $auth_error = "Username minimal 3 karakter!";

        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

            $auth_error = "Format email tidak valid!";

        } elseif (strlen($password) < 6) {

            $auth_error = "Password minimal 6 karakter!";

        } else {

            /* Cek email */
            $check_stmt = mysqli_prepare(
                $conn,
                "SELECT id FROM users WHERE email = ? LIMIT 1"
            );

            mysqli_stmt_bind_param($check_stmt, "s", $email);
            mysqli_stmt_execute($check_stmt);

            $check_result = mysqli_stmt_get_result($check_stmt);

            if (mysqli_num_rows($check_result) > 0) {

                $auth_error = "Email sudah terdaftar!";

            } else {

                $hashedPassword = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );

                $insert_stmt = mysqli_prepare(
                    $conn,
                    "INSERT INTO users 
                    (username, email, password) 
                    VALUES (?, ?, ?)"
                );

                mysqli_stmt_bind_param(
                    $insert_stmt,
                    "sss",
                    $username,
                    $email,
                    $hashedPassword
                );

                if (mysqli_stmt_execute($insert_stmt)) {

                    $auth_success = "Pendaftaran berhasil! Silakan login.";

                } else {

                    $auth_error = "Gagal membuat akun!";
                }

                mysqli_stmt_close($insert_stmt);
            }

            mysqli_stmt_close($check_stmt);
        }
    }
}

/* =========================================================
   5. FORM LOGIN JIKA BELUM LOGIN
========================================================= */
if (!isset($_SESSION['user_id'])):
?>

<!DOCTYPE html>
<html lang="id">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>SAVEUP - Masuk</title>

    <script src="https://cdn.tailwindcss.com"></script>

</head>

<body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">

    <div
        class="w-full max-w-md bg-white rounded-3xl shadow-xl border border-gray-100 p-8"
    >

        <!-- LOGO -->
        <div class="text-center mb-7">

            <div
                class="w-16 h-16 mx-auto rounded-2xl
                bg-gradient-to-br from-green-500 to-emerald-400
                flex items-center justify-center
                text-white text-3xl font-black
                shadow-lg shadow-green-500/30"
            >
                S
            </div>

            <h1 class="text-2xl font-black text-gray-800 mt-3">
                SAVEUP
            </h1>

            <p class="text-xs text-gray-400 mt-1">
                Sedikit demi sedikit, jadi impian.
            </p>

        </div>


        <!-- ERROR -->
        <?php if ($auth_error): ?>

            <div
                class="bg-red-50 border border-red-100
                text-red-500 text-sm p-3 rounded-xl
                text-center mb-4"
            >
                <?= e($auth_error) ?>
            </div>

        <?php endif; ?>


        <!-- SUCCESS -->
        <?php if ($auth_success): ?>

            <div
                class="bg-green-50 border border-green-100
                text-green-600 text-sm p-3 rounded-xl
                text-center mb-4"
            >
                <?= e($auth_success) ?>
            </div>

        <?php endif; ?>


        <!-- LOGIN -->
        <form
            method="POST"
            id="formLogin"
            class="space-y-4"
        >

            <input
                type="hidden"
                name="auth_type"
                value="login"
            >

            <div>

                <label class="text-sm font-semibold text-gray-600">
                    Email
                </label>

                <input
                    type="email"
                    name="email"
                    required
                    autocomplete="email"
                    placeholder="nama@email.com"
                    class="w-full p-3 mt-1 rounded-xl
                    border border-gray-200
                    focus:outline-none
                    focus:ring-2 focus:ring-green-500"
                >

            </div>


            <div>

                <label class="text-sm font-semibold text-gray-600">
                    Password
                </label>

                <input
                    type="password"
                    name="password"
                    required
                    autocomplete="current-password"
                    placeholder="Masukkan password"
                    class="w-full p-3 mt-1 rounded-xl
                    border border-gray-200
                    focus:outline-none
                    focus:ring-2 focus:ring-green-500"
                >

            </div>


            <button
                type="submit"
                class="w-full py-3 rounded-xl
                bg-green-500 hover:bg-green-600
                text-white font-bold
                shadow-lg shadow-green-500/30
                transition"
            >
                Masuk
            </button>


            <p class="text-center text-sm text-gray-400">

                Belum punya akun?

                <button
                    type="button"
                    onclick="toggleAuth(true)"
                    class="text-green-500 font-bold"
                >
                    Daftar
                </button>

            </p>

        </form>


        <!-- REGISTER -->
        <form
            method="POST"
            id="formRegister"
            class="space-y-4 hidden"
        >

            <input
                type="hidden"
                name="auth_type"
                value="register"
            >


            <div>

                <label class="text-sm font-semibold text-gray-600">
                    Username
                </label>

                <input
                    type="text"
                    name="username"
                    required
                    minlength="3"
                    placeholder="Nama kamu"
                    class="w-full p-3 mt-1 rounded-xl
                    border border-gray-200
                    focus:outline-none
                    focus:ring-2 focus:ring-green-500"
                >

            </div>


            <div>

                <label class="text-sm font-semibold text-gray-600">
                    Email
                </label>

                <input
                    type="email"
                    name="email"
                    required
                    placeholder="nama@email.com"
                    class="w-full p-3 mt-1 rounded-xl
                    border border-gray-200
                    focus:outline-none
                    focus:ring-2 focus:ring-green-500"
                >

            </div>


            <div>

                <label class="text-sm font-semibold text-gray-600">
                    Password
                </label>

                <input
                    type="password"
                    name="password"
                    required
                    minlength="6"
                    placeholder="Minimal 6 karakter"
                    class="w-full p-3 mt-1 rounded-xl
                    border border-gray-200
                    focus:outline-none
                    focus:ring-2 focus:ring-green-500"
                >

            </div>


            <button
                type="submit"
                class="w-full py-3 rounded-xl
                bg-green-500 hover:bg-green-600
                text-white font-bold
                shadow-lg shadow-green-500/30
                transition"
            >
                Buat Akun
            </button>


            <p class="text-center text-sm text-gray-400">

                Sudah punya akun?

                <button
                    type="button"
                    onclick="toggleAuth(false)"
                    class="text-green-500 font-bold"
                >
                    Masuk
                </button>

            </p>

        </form>

    </div>


<script>

function toggleAuth(registerMode)
{
    const loginForm =
        document.getElementById('formLogin');

    const registerForm =
        document.getElementById('formRegister');

    if (registerMode) {

        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');

    } else {

        loginForm.classList.remove('hidden');
        registerForm.classList.add('hidden');

    }
}

</script>

</body>
</html>

<?php
endif;
exit();
?>


/* =========================================================
   6. USER LOGIN
========================================================= */

$user_id = (int)$_SESSION['user_id'];


/* =========================================================
   7. TAMBAH TARGET & TABUNGAN
========================================================= */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {


    /* =====================================================
       TAMBAH TARGET
    ===================================================== */

    if (isset($_POST['add_target'])) {

        $title = trim($_POST['title'] ?? '');

        $target_amount =
            (float)($_POST['target_amount'] ?? 0);

        $deadline =
            $_POST['deadline'] ?? '';


        if (
            $title === '' ||
            $target_amount <= 0 ||
            $deadline === ''
        ) {

            redirectTo("index.php?tab=targets&error=target");

        }


        $stmt = mysqli_prepare(
            $conn,
            "INSERT INTO goals
            (user_id, title, target_amount, deadline)
            VALUES (?, ?, ?, ?)"
        );

        mysqli_stmt_bind_param(
            $stmt,
            "isds",
            $user_id,
            $title,
            $target_amount,
            $deadline
        );

        mysqli_stmt_execute($stmt);

        mysqli_stmt_close($stmt);

        redirectTo("index.php?tab=targets");
    }


    /* =====================================================
       TAMBAH TABUNGAN
    ===================================================== */

    if (isset($_POST['add_saving'])) {

        $goal_id =
            (int)($_POST['goal_id'] ?? 0);

        $amount =
            (float)($_POST['amount'] ?? 0);

        $date =
            $_POST['savings_date'] ?? '';

        $note =
            trim($_POST['note'] ?? '');


        if (
            $goal_id <= 0 ||
            $amount <= 0 ||
            $date === ''
        ) {

            redirectTo("index.php?tab=savings&error=saving");

        }


        /*
         * PENTING:
         * Pastikan target memang milik user
         */

        $check_goal = mysqli_prepare(
            $conn,
            "SELECT id
             FROM goals
             WHERE id = ?
             AND user_id = ?
             LIMIT 1"
        );

        mysqli_stmt_bind_param(
            $check_goal,
            "ii",
            $goal_id,
            $user_id
        );

        mysqli_stmt_execute($check_goal);

        $goal_result =
            mysqli_stmt_get_result($check_goal);

        $goal_exists =
            mysqli_num_rows($goal_result) > 0;

        mysqli_stmt_close($check_goal);


        if (!$goal_exists) {

            redirectTo("index.php?tab=savings&error=goal");

        }


        $stmt = mysqli_prepare(
            $conn,
            "INSERT INTO savings
            (user_id, goal_id, amount, savings_date, note)
            VALUES (?, ?, ?, ?, ?)"
        );

        mysqli_stmt_bind_param(
            $stmt,
            "iidss",
            $user_id,
            $goal_id,
            $amount,
            $date,
            $note
        );

        mysqli_stmt_execute($stmt);

        mysqli_stmt_close($stmt);

        redirectTo("index.php?tab=savings");
    }
}


/* =========================================================
   8. DELETE TARGET
========================================================= */

if (isset($_GET['delete_target'])) {

    $id = (int)$_GET['delete_target'];


    /*
     * Hapus tabungan yang berkaitan terlebih dahulu
     */

    $stmt = mysqli_prepare(
        $conn,
        "DELETE FROM savings
         WHERE goal_id = ?
         AND user_id = ?"
    );

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $id,
        $user_id
    );

    mysqli_stmt_execute($stmt);

    mysqli_stmt_close($stmt);


    /*
     * Hapus target
     */

    $stmt = mysqli_prepare(
        $conn,
        "DELETE FROM goals
         WHERE id = ?
         AND user_id = ?"
    );

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $id,
        $user_id
    );

    mysqli_stmt_execute($stmt);

    mysqli_stmt_close($stmt);

    redirectTo("index.php?tab=targets");
}


/* =========================================================
   9. DELETE TABUNGAN
========================================================= */

if (isset($_GET['delete_saving'])) {

    $id =
        (int)$_GET['delete_saving'];


    $stmt = mysqli_prepare(
        $conn,
        "DELETE FROM savings
         WHERE id = ?
         AND user_id = ?"
    );

    mysqli_stmt_bind_param(
        $stmt,
        "ii",
        $id,
        $user_id
    );

    mysqli_stmt_execute($stmt);

    mysqli_stmt_close($stmt);

    redirectTo("index.php?tab=savings");
}


/* =========================================================
   10. TOTAL TABUNGAN
========================================================= */

$stmt = mysqli_prepare(
    $conn,
    "SELECT COALESCE(SUM(amount), 0) AS total
     FROM savings
     WHERE user_id = ?"
);

mysqli_stmt_bind_param(
    $stmt,
    "i",
    $user_id
);

mysqli_stmt_execute($stmt);

$result =
    mysqli_stmt_get_result($stmt);

$row =
    mysqli_fetch_assoc($result);

$total_saved =
    (float)($row['total'] ?? 0);

mysqli_stmt_close($stmt);


/* =========================================================
   11. TOTAL TARGET
========================================================= */

$stmt = mysqli_prepare(
    $conn,
    "SELECT COALESCE(SUM(target_amount), 0) AS total
     FROM goals
     WHERE user_id = ?"
);

mysqli_stmt_bind_param(
    $stmt,
    "i",
    $user_id
);

mysqli_stmt_execute($stmt);

$result =
    mysqli_stmt_get_result($stmt);

$row =
    mysqli_fetch_assoc($result);

$total_target =
    (float)($row['total'] ?? 0);

mysqli_stmt_close($stmt);


/* =========================================================
   12. TARGET UTAMA
========================================================= */

$stmt = mysqli_prepare(
    $conn,
    "SELECT
        g.id,
        g.title,
        g.target_amount,
        g.deadline,
        COALESCE(SUM(s.amount), 0) AS collected
     FROM goals g
     LEFT JOIN savings s
        ON g.id = s.goal_id
     WHERE g.user_id = ?
     GROUP BY
        g.id,
        g.title,
        g.target_amount,
        g.deadline
     ORDER BY g.created_at DESC
     LIMIT 1"
);

mysqli_stmt_bind_param(
    $stmt,
    "i",
    $user_id
);

mysqli_stmt_execute($stmt);

$result =
    mysqli_stmt_get_result($stmt);

$main_goal =
    mysqli_fetch_assoc($result);

mysqli_stmt_close($stmt);


/* =========================================================
   13. DAFTAR TARGET
========================================================= */

$stmt = mysqli_prepare(
    $conn,
    "SELECT
        g.id,
        g.title,
        g.target_amount,
        g.deadline,
        COALESCE(SUM(s.amount), 0) AS collected
     FROM goals g
     LEFT JOIN savings s
        ON g.id = s.goal_id
     WHERE g.user_id = ?
     GROUP BY
        g.id,
        g.title,
        g.target_amount,
        g.deadline
     ORDER BY g.created_at DESC"
);

mysqli_stmt_bind_param(
    $stmt,
    "i",
    $user_id
);

mysqli_stmt_execute($stmt);

$goals_res =
    mysqli_stmt_get_result($stmt);


/* =========================================================
   14. RIWAYAT TABUNGAN
========================================================= */

$stmt = mysqli_prepare(
    $conn,
    "SELECT
        s.id,
        s.amount,
        s.savings_date,
        s.note,
        g.title
     FROM savings s
     INNER JOIN goals g
        ON s.goal_id = g.id
     WHERE s.user_id = ?
     AND g.user_id = ?
     ORDER BY s.savings_date DESC, s.id DESC"
);

mysqli_stmt_bind_param(
    $stmt,
    "ii",
    $user_id,
    $user_id
);

mysqli_stmt_execute($stmt);

$savings_res =
    mysqli_stmt_get_result($stmt);


/* =========================================================
   15. TAB AKTIF
========================================================= */

$active_tab =
    $_GET['tab'] ?? 'dashboard';

$allowed_tabs = [
    'dashboard',
    'targets',
    'savings',
    'calculator'
];

if (!in_array($active_tab, $allowed_tabs, true)) {

    $active_tab = 'dashboard';
}

?>

<!DOCTYPE html>
<html lang="id" class="light">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>SAVEUP - Tabungan Impian</title>

<script src="https://cdn.tailwindcss.com"></script>

<script>

tailwind.config = {

    darkMode: 'class',

    theme: {

        extend: {

            colors: {

                brand: {

                    50: '#f0fdf4',
                    500: '#22c55e',
                    600: '#16a34a'

                },

                darkbg: '#0f172a',

                darkcard: '#1e293b'

            }

        }

    }

}

</script>

<link
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
    rel="stylesheet"
>

</head>


<body
class="bg-gray-50 text-gray-800
dark:bg-darkbg dark:text-gray-100
min-h-screen flex flex-col
font-sans transition-colors duration-300"
>


<!-- =====================================================
     NAVBAR
===================================================== -->

<nav
class="bg-white/90 dark:bg-darkcard/90
backdrop-blur-md
border-b border-gray-100 dark:border-gray-800
sticky top-0 z-50"
>

<div
class="max-w-5xl mx-auto px-4 py-3
flex justify-between items-center"
>

    <!-- LOGO -->

    <a
        href="index.php"
        class="flex items-center gap-2"
    >

        <div
            class="w-9 h-9 rounded-xl
            bg-gradient-to-tr
            from-brand-500 to-emerald-300
            flex items-center justify-center
            text-white font-black text-lg
            shadow-lg shadow-brand-500/30"
        >
            S
        </div>

        <span
            class="font-black text-xl
            tracking-tight
            bg-gradient-to-r
            from-brand-600 to-emerald-500
            bg-clip-text text-transparent"
        >
            SAVEUP
        </span>

    </a>


    <!-- DESKTOP MENU -->

    <div
        class="hidden md:flex items-center gap-6
        text-sm font-semibold"
    >

        <a
            href="?tab=dashboard"
            class="<?= $active_tab === 'dashboard'
                ? 'text-brand-500'
                : 'hover:text-brand-500' ?>"
        >
            Dashboard
        </a>

        <a
            href="?tab=targets"
            class="<?= $active_tab === 'targets'
                ? 'text-brand-500'
                : 'hover:text-brand-500' ?>"
        >
            Target
        </a>

        <a
            href="?tab=savings"
            class="<?= $active_tab === 'savings'
                ? 'text-brand-500'
                : 'hover:text-brand-500' ?>"
        >
            Riwayat
        </a>

        <a
            href="?tab=calculator"
            class="<?= $active_tab === 'calculator'
                ? 'text-brand-500'
                : 'hover:text-brand-500' ?>"
        >
            Kalkulator
        </a>

    </div>


    <!-- RIGHT -->

    <div class="flex items-center gap-2">

        <button
            id="themeToggle"
            class="w-9 h-9 rounded-xl
            bg-gray-100 dark:bg-gray-700
            text-gray-600 dark:text-gray-300"
            title="Ganti tema"
        >

            <i
                class="fa-solid fa-moon dark:hidden"
            ></i>

            <i
                class="fa-solid fa-sun hidden dark:block"
            ></i>

        </button>


        <a
            href="?action=logout"
            onclick="return confirm('Yakin ingin logout?')"
            class="text-xs font-bold
            bg-red-50 text-red-500
            dark:bg-red-500/10 dark:text-red-400
            px-3 py-2 rounded-xl"
        >
            Logout
        </a>

    </div>

</div>


<!-- MOBILE MENU -->

<div
class="md:hidden grid grid-cols-4
border-t border-gray-100 dark:border-gray-800"
>

    <a
        href="?tab=dashboard"
        class="py-3 text-center text-xs
        <?= $active_tab === 'dashboard'
            ? 'text-brand-500 font-bold'
            : 'text-gray-500' ?>"
    >
        <i class="fa-solid fa-house block mb-1"></i>
        Dashboard
    </a>

    <a
        href="?tab=targets"
        class="py-3 text-center text-xs
        <?= $active_tab === 'targets'
            ? 'text-brand-500 font-bold'
            : 'text-gray-500' ?>"
    >
        <i class="fa-solid fa-bullseye block mb-1"></i>
        Target
    </a>

    <a
        href="?tab=savings"
        class="py-3 text-center text-xs
        <?= $active_tab === 'savings'
            ? 'text-brand-500 font-bold'
            : 'text-gray-500' ?>"
    >
        <i class="fa-solid fa-clock-rotate-left block mb-1"></i>
        Riwayat
    </a>

    <a
        href="?tab=calculator"
        class="py-3 text-center text-xs
        <?= $active_tab === 'calculator'
            ? 'text-brand-500 font-bold'
            : 'text-gray-500' ?>"
    >
        <i class="fa-solid fa-calculator block mb-1"></i>
        Kalkulator
    </a>

</div>

</nav>


<!-- =====================================================
     MAIN
===================================================== -->

<main
class="flex-grow max-w-5xl w-full mx-auto p-4 md:p-6"
>


<?php if ($active_tab === 'dashboard'): ?>


<!-- =====================================================
     DASHBOARD
===================================================== -->

<div class="space-y-6">

    <div
        class="flex flex-col md:flex-row
        justify-between items-start
        md:items-center gap-4"
    >

        <div>

            <p
                class="text-xs text-brand-500
                font-bold mb-1"
            >
                SELAMAT DATANG 👋
            </p>

            <h1 class="text-2xl font-black">
                Halo, <?= e($_SESSION['username']) ?>!
            </h1>

            <p class="text-xs text-gray-400 mt-1">
                "Konsistensi adalah kunci
                dari setiap pencapaian besar."
            </p>

        </div>


        <button
            onclick="openModal('modalSaving')"
            class="px-5 py-3
            bg-brand-500 hover:bg-brand-600
            text-white rounded-2xl
            font-bold text-sm
            shadow-lg shadow-brand-500/30
            flex items-center gap-2"
        >

            <i class="fa-solid fa-plus"></i>

            Tambah Tabungan

        </button>

    </div>


    <!-- STATISTIK -->

    <div
        class="grid grid-cols-1 md:grid-cols-2 gap-4"
    >

        <div
            class="p-6 rounded-3xl
            bg-white dark:bg-darkcard
            border border-gray-100 dark:border-gray-800
            shadow-sm"
        >

            <div class="flex justify-between">

                <span
                    class="text-xs font-bold text-gray-400"
                >
                    TOTAL TABUNGAN
                </span>

                <i
                    class="fa-solid fa-wallet
                    text-green-500"
                ></i>

            </div>

            <h2 class="text-3xl font-black mt-3">
                <?= rupiah($total_saved) ?>
            </h2>

        </div>


        <div
            class="p-6 rounded-3xl
            bg-white dark:bg-darkcard
            border border-gray-100 dark:border-gray-800
            shadow-sm"
        >

            <div class="flex justify-between">

                <span
                    class="text-xs font-bold text-gray-400"
                >
                    TOTAL TARGET
                </span>

                <i
                    class="fa-solid fa-bullseye
                    text-emerald-500"
                ></i>

            </div>

            <h2 class="text-3xl font-black mt-3">
                <?= rupiah($total_target) ?>
            </h2>

        </div>

    </div>


    <!-- TARGET UTAMA -->

    <?php if ($main_goal): ?>

        <?php

        $main_target =
            (float)$main_goal['target_amount'];

        $main_collected =
            (float)$main_goal['collected'];

        $percent =
            $main_target > 0
            ? min(
                100,
                round(
                    ($main_collected / $main_target) * 100
                )
            )
            : 0;

        ?>

        <div
            class="p-6 rounded-3xl
            bg-gradient-to-br
            from-gray-900 to-gray-800
            text-white
            shadow-xl space-y-5"
        >

            <div
                class="flex justify-between
                items-start gap-3"
            >

                <div>

                    <span
                        class="inline-block
                        bg-brand-500/20
                        text-brand-400
                        text-xs px-3 py-1
                        rounded-full font-bold
                        border border-brand-500/30"
                    >
                        🎯 Target Utama
                    </span>

                    <h3 class="text-xl font-black mt-3">
                        <?= e($main_goal['title']) ?>
                    </h3>

                    <p class="text-xs text-gray-400 mt-1">
                        Deadline:
                        <?= date(
                            'd M Y',
                            strtotime($main_goal['deadline'])
                        ) ?>
                    </p>

                </div>


                <span
                    class="text-3xl font-black
                    text-brand-400"
                >
                    <?= $percent ?>%
                </span>

            </div>


            <div class="space-y-2">

                <div
                    class="flex justify-between
                    text-xs text-gray-300"
                >

                    <span>
                        Terkumpul:
                        <strong>
                            <?= rupiah($main_collected) ?>
                        </strong>
                    </span>

                    <span>
                        Target:
                        <strong>
                            <?= rupiah($main_target) ?>
                        </strong>
                    </span>

                </div>


                <div
                    class="w-full bg-gray-700
                    rounded-full h-3 overflow-hidden"
                >

                    <div
                        class="bg-brand-500 h-full
                        rounded-full transition-all"
                        style="width: <?= $percent ?>%"
                    ></div>

                </div>

            </div>

        </div>

    <?php else: ?>

        <div
            class="p-8 rounded-3xl
            bg-white dark:bg-darkcard
            border border-dashed
            border-gray-200 dark:border-gray-700
            text-center"
        >

            <div
                class="w-14 h-14 rounded-2xl
                bg-green-50 dark:bg-green-500/10
                text-green-500
                flex items-center justify-center
                mx-auto mb-3"
            >

                <i class="fa-solid fa-bullseye text-xl"></i>

            </div>

            <h3 class="font-bold">
                Belum ada target
            </h3>

            <p class="text-xs text-gray-400 mt-1 mb-4">
                Buat target pertama kamu
                dan mulai menabung.
            </p>

            <button
                onclick="openModal('modalTarget')"
                class="px-4 py-2
                bg-brand-500 text-white
                rounded-xl text-xs font-bold"
            >
                + Buat Target
            </button>

        </div>

    <?php endif; ?>

</div>


<?php elseif ($active_tab === 'targets'): ?>


<!-- =====================================================
     TARGET
===================================================== -->

<div class="space-y-6">

    <div
        class="flex justify-between
        items-center gap-3"
    >

        <div>

            <h1 class="text-2xl font-black">
                Target Impian
            </h1>

            <p class="text-xs text-gray-400 mt-1">
                Tentukan sesuatu yang ingin kamu capai.
            </p>

        </div>


        <button
            onclick="openModal('modalTarget')"
            class="px-4 py-2.5
            bg-brand-500 text-white
            rounded-xl text-sm font-bold"
        >
            + Target Baru
        </button>

    </div>


    <div
        class="grid grid-cols-1 md:grid-cols-2 gap-4"
    >

    <?php if (mysqli_num_rows($goals_res) === 0): ?>

        <div
            class="md:col-span-2
            p-10 text-center
            bg-white dark:bg-darkcard
            rounded-3xl
            border border-dashed
            border-gray-200 dark:border-gray-700"
        >

            <i
                class="fa-solid fa-bullseye
                text-3xl text-green-500 mb-3"
            ></i>

            <h3 class="font-bold">
                Belum ada target
            </h3>

            <p class="text-xs text-gray-400 mt-1">
                Klik "Target Baru" untuk mulai.
            </p>

        </div>

    <?php endif; ?>


    <?php while ($g = mysqli_fetch_assoc($goals_res)): ?>

        <?php

        $target =
            (float)$g['target_amount'];

        $collected =
            (float)$g['collected'];

        $percent =
            $target > 0
            ? min(
                100,
                round(($collected / $target) * 100)
            )
            : 0;

        ?>

        <div
            class="p-5 rounded-3xl
            bg-white dark:bg-darkcard
            border border-gray-100
            dark:border-gray-800
            space-y-4
            hover:-translate-y-1
            transition"
        >

            <div
                class="flex justify-between
                items-start"
            >

                <div>

                    <h3 class="font-black text-lg">
                        <?= e($g['title']) ?>
                    </h3>

                    <span
                        class="text-xs text-gray-400"
                    >
                        <i class="fa-regular fa-calendar"></i>

                        <?= date(
                            'd M Y',
                            strtotime($g['deadline'])
                        ) ?>

                    </span>

                </div>


                <a
                    href="?tab=targets&delete_target=<?= (int)$g['id'] ?>"
                    onclick="return confirm(
                        'Hapus target ini? Semua riwayat tabungan target ini juga akan dihapus.'
                    )"
                    class="w-8 h-8
                    flex items-center justify-center
                    rounded-lg
                    text-gray-300
                    hover:bg-red-50
                    hover:text-red-500"
                >

                    <i class="fa-solid fa-trash"></i>

                </a>

            </div>


            <div
                class="flex justify-between
                text-xs font-bold"
            >

                <span>
                    <?= rupiah($collected) ?>
                </span>

                <span class="text-gray-400">
                    <?= rupiah($target) ?>
                </span>

            </div>


            <div
                class="w-full bg-gray-100
                dark:bg-gray-700
                rounded-full h-2.5 overflow-hidden"
            >

                <div
                    class="bg-brand-500 h-full
                    rounded-full"
                    style="width: <?= $percent ?>%"
                ></div>

            </div>


            <div
                class="flex justify-between
                items-center"
            >

                <span
                    class="text-xs
                    <?= $percent >= 100
                        ? 'text-green-500'
                        : 'text-gray-400' ?>"
                >

                    <?= $percent >= 100
                        ? '🎉 Target tercapai!'
                        : 'Masih berproses...' ?>

                </span>

                <span
                    class="text-xs font-black
                    text-brand-500"
                >
                    <?= $percent ?>%
                </span>

            </div>

        </div>

    <?php endwhile; ?>

    </div>

</div>


<?php elseif ($active_tab === 'savings'): ?>


<!-- =====================================================
     RIWAYAT
===================================================== -->

<div class="space-y-6">

    <div
        class="flex justify-between
        items-center gap-3"
    >

        <div>

            <h1 class="text-2xl font-black">
                Riwayat Tabungan
            </h1>

            <p class="text-xs text-gray-400 mt-1">
                Semua catatan tabungan kamu.
            </p>

        </div>


        <button
            onclick="openModal('modalSaving')"
            class="px-4 py-2.5
            bg-brand-500 text-white
            rounded-xl text-sm font-bold"
        >
            + Catat
        </button>

    </div>


    <?php if (mysqli_num_rows($savings_res) === 0): ?>

        <div
            class="p-10 text-center
            bg-white dark:bg-darkcard
            rounded-3xl
            border border-dashed
            border-gray-200 dark:border-gray-700"
        >

            <i
                class="fa-solid fa-wallet
                text-3xl text-green-500 mb-3"
            ></i>

            <h3 class="font-bold">
                Belum ada tabungan
            </h3>

            <p class="text-xs text-gray-400 mt-1">
                Catat tabungan pertama kamu.
            </p>

        </div>

    <?php else: ?>


    <!-- DESKTOP TABLE -->

    <div
        class="hidden md:block
        bg-white dark:bg-darkcard
        rounded-3xl
        border border-gray-100
        dark:border-gray-800
        overflow-hidden"
    >

        <table class="w-full text-left">

            <thead
                class="bg-gray-50
                dark:bg-gray-800/50
                text-xs text-gray-400"
            >

                <tr>

                    <th class="p-4">
                        Tanggal
                    </th>

                    <th class="p-4">
                        Target
                    </th>

                    <th class="p-4">
                        Nominal
                    </th>

                    <th class="p-4">
                        Catatan
                    </th>

                    <th class="p-4 text-center">
                        Aksi
                    </th>

                </tr>

            </thead>


            <tbody
                class="divide-y
                divide-gray-100
                dark:divide-gray-800"
            >

            <?php while ($s = mysqli_fetch_assoc($savings_res)): ?>

                <tr
                    class="hover:bg-gray-50
                    dark:hover:bg-gray-800/40"
                >

                    <td class="p-4 text-xs">

                        <?= date(
                            'd M Y',
                            strtotime($s['savings_date'])
                        ) ?>

                    </td>


                    <td class="p-4 font-bold">

                        <?= e($s['title']) ?>

                    </td>


                    <td
                        class="p-4
                        font-black
                        text-brand-500"
                    >

                        <?= rupiah($s['amount']) ?>

                    </td>


                    <td
                        class="p-4 text-xs
                        text-gray-400"
                    >

                        <?= e(
                            $s['note'] ?: '-'
                        ) ?>

                    </td>


                    <td class="p-4 text-center">

                        <a
                            href="?tab=savings&delete_saving=<?= (int)$s['id'] ?>"
                            onclick="return confirm(
                                'Hapus catatan tabungan ini?'
                            )"
                            class="text-red-400
                            hover:text-red-600"
                        >

                            <i class="fa-solid fa-trash"></i>

                        </a>

                    </td>

                </tr>

            <?php endwhile; ?>

            </tbody>

        </table>

    </div>


    <!-- MOBILE CARD -->

    <div class="md:hidden space-y-3">

    <?php

    /*
     * Result sudah dikonsumsi oleh table.
     * Query ulang untuk mobile.
     */

    $mobile_stmt = mysqli_prepare(
        $conn,
        "SELECT
            s.id,
            s.amount,
            s.savings_date,
            s.note,
            g.title
         FROM savings s
         INNER JOIN goals g
            ON s.goal_id = g.id
         WHERE s.user_id = ?
         AND g.user_id = ?
         ORDER BY s.savings_date DESC, s.id DESC"
    );

    mysqli_stmt_bind_param(
        $mobile_stmt,
        "ii",
        $user_id,
        $user_id
    );

    mysqli_stmt_execute($mobile_stmt);

    $mobile_result =
        mysqli_stmt_get_result($mobile_stmt);

    ?>

    <?php while ($s = mysqli_fetch_assoc($mobile_result)): ?>

        <div
            class="p-4 rounded-2xl
            bg-white dark:bg-darkcard
            border border-gray-100
            dark:border-gray-800"
        >

            <div
                class="flex justify-between
                items-start"
            >

                <div>

                    <p
                        class="font-bold text-sm"
                    >
                        <?= e($s['title']) ?>
                    </p>

                    <p
                        class="text-xs text-gray-400 mt-1"
                    >
                        <?= date(
                            'd M Y',
                            strtotime($s['savings_date'])
                        ) ?>
                    </p>

                </div>


                <a
                    href="?tab=savings&delete_saving=<?= (int)$s['id'] ?>"
                    onclick="return confirm(
                        'Hapus catatan ini?'
                    )"
                    class="text-red-400"
                >

                    <i class="fa-solid fa-trash"></i>

                </a>

            </div>


            <p
                class="text-lg font-black
                text-brand-500 mt-3"
            >
                <?= rupiah($s['amount']) ?>
            </p>


            <?php if ($s['note']): ?>

                <p
                    class="text-xs text-gray-400
                    mt-1"
                >
                    <?= e($s['note']) ?>
                </p>

            <?php endif; ?>

        </div>

    <?php endwhile; ?>

    <?php
    mysqli_stmt_close($mobile_stmt);
    ?>

    </div>


    <?php endif; ?>

</div>


<?php elseif ($active_tab === 'calculator'): ?>


<!-- =====================================================
     KALKULATOR
===================================================== -->

<div
    class="max-w-xl mx-auto space-y-6"
>

    <div class="text-center">

        <div
            class="w-14 h-14
            bg-green-50 dark:bg-green-500/10
            text-green-500
            rounded-2xl
            flex items-center justify-center
            mx-auto"
        >

            <i
                class="fa-solid fa-calculator text-xl"
            ></i>

        </div>

        <h1 class="text-2xl font-black mt-3">
            Kalkulator Impian
        </h1>

        <p class="text-xs text-gray-400 mt-1">
            Hitung berapa yang perlu kamu tabung.
        </p>

    </div>


    <div
        class="p-6 rounded-3xl
        bg-white dark:bg-darkcard
        border border-gray-100
        dark:border-gray-800
        space-y-5"
    >

        <div>

            <label
                class="text-xs font-bold
                text-gray-500"
            >
                Target Nominal
            </label>

            <div class="relative">

                <span
                    class="absolute left-3
                    top-3 text-gray-400 text-sm"
                >
                    Rp
                </span>

                <input
                    type="number"
                    id="calcTarget"
                    min="1"
                    step="1"
                    placeholder="1.500.000"
                    class="w-full p-3 pl-10
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>

        </div>


        <div>

            <label
                class="text-xs font-bold
                text-gray-500"
            >
                Deadline
            </label>

            <input
                type="date"
                id="calcDate"
                class="w-full p-3
                rounded-xl
                border border-gray-200
                dark:border-gray-700
                dark:bg-gray-800
                text-sm mt-1
                focus:outline-none
                focus:ring-2
                focus:ring-green-500"
            >

        </div>


        <button
            onclick="calculateSaving()"
            class="w-full py-3
            bg-brand-500
            hover:bg-brand-600
            text-white
            rounded-xl
            font-bold text-sm"
        >
            Hitung Tabungan
        </button>

    </div>


    <!-- HASIL -->

    <div
        id="calcResult"
        class="hidden
        p-5 rounded-3xl
        bg-green-50
        dark:bg-gray-800
        space-y-4"
    >

        <p
            class="text-center
            text-xs font-bold
            text-gray-500"
        >
            KAMU PERLU MENABUNG
        </p>


        <div
            class="grid grid-cols-2 gap-3"
        >

            <div
                class="bg-white
                dark:bg-darkcard
                p-4 rounded-2xl
                text-center"
            >

                <span
                    class="text-xs text-gray-400"
                >
                    Per Hari
                </span>

                <p
                    id="perDay"
                    class="text-lg
                    font-black
                    text-brand-500 mt-1"
                >
                    Rp0
                </p>

            </div>


            <div
                class="bg-white
                dark:bg-darkcard
                p-4 rounded-2xl
                text-center"
            >

                <span
                    class="text-xs text-gray-400"
                >
                    Per Bulan
                </span>

                <p
                    id="perMonth"
                    class="text-lg
                    font-black
                    text-brand-500 mt-1"
                >
                    Rp0
                </p>

            </div>

        </div>

    </div>

</div>

<?php endif; ?>

</main>


<!-- =====================================================
     MODAL TARGET
===================================================== -->

<div
    id="modalTarget"
    class="fixed inset-0
    bg-black/50
    backdrop-blur-sm
    hidden items-center justify-center
    p-4 z-[100]"
>

    <div
        class="bg-white dark:bg-darkcard
        p-6 rounded-3xl
        max-w-sm w-full
        shadow-2xl"
    >

        <div
            class="flex justify-between
            items-center mb-5"
        >

            <div>

                <h3 class="font-black text-lg">
                    Buat Target
                </h3>

                <p class="text-xs text-gray-400">
                    Apa yang ingin kamu capai?
                </p>

            </div>


            <button
                onclick="closeModal('modalTarget')"
                class="w-8 h-8
                rounded-lg
                bg-gray-100
                dark:bg-gray-700
                text-gray-500"
            >
                ×
            </button>

        </div>


        <form
            method="POST"
            class="space-y-4"
        >

            <input
                type="hidden"
                name="add_target"
                value="1"
            >


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Nama Target
                </label>

                <input
                    type="text"
                    name="title"
                    required
                    maxlength="100"
                    placeholder="Contoh: Beli Laptop"
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Nominal Target
                </label>

                <input
                    type="number"
                    name="target_amount"
                    required
                    min="1"
                    step="1"
                    placeholder="5000000"
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Deadline
                </label>

                <input
                    type="date"
                    name="deadline"
                    required
                    id="targetDeadline"
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div class="flex gap-2 pt-2">

                <button
                    type="button"
                    onclick="closeModal('modalTarget')"
                    class="flex-1 py-3
                    text-sm font-bold
                    text-gray-500
                    bg-gray-100
                    dark:bg-gray-700
                    rounded-xl"
                >
                    Batal
                </button>


                <button
                    type="submit"
                    class="flex-1 py-3
                    bg-brand-500
                    text-white
                    rounded-xl
                    text-sm font-bold"
                >
                    Simpan
                </button>

            </div>

        </form>

    </div>

</div>


<!-- =====================================================
     MODAL TABUNGAN
===================================================== -->

<div
    id="modalSaving"
    class="fixed inset-0
    bg-black/50
    backdrop-blur-sm
    hidden items-center justify-center
    p-4 z-[100]"
>

    <div
        class="bg-white dark:bg-darkcard
        p-6 rounded-3xl
        max-w-sm w-full
        shadow-2xl"
    >

        <div
            class="flex justify-between
            items-center mb-5"
        >

            <div>

                <h3 class="font-black text-lg">
                    Catat Tabungan
                </h3>

                <p class="text-xs text-gray-400">
                    Tambahkan uang yang kamu simpan.
                </p>

            </div>


            <button
                onclick="closeModal('modalSaving')"
                class="w-8 h-8
                rounded-lg
                bg-gray-100
                dark:bg-gray-700
                text-gray-500"
            >
                ×
            </button>

        </div>


        <?php

        $option_stmt = mysqli_prepare(
            $conn,
            "SELECT id, title
             FROM goals
             WHERE user_id = ?
             ORDER BY created_at DESC"
        );

        mysqli_stmt_bind_param(
            $option_stmt,
            "i",
            $user_id
        );

        mysqli_stmt_execute($option_stmt);

        $options =
            mysqli_stmt_get_result($option_stmt);

        ?>


        <?php if (mysqli_num_rows($options) === 0): ?>

            <div
                class="text-center py-5"
            >

                <i
                    class="fa-solid fa-bullseye
                    text-3xl
                    text-gray-300 mb-3"
                ></i>

                <p
                    class="text-sm
                    font-bold"
                >
                    Belum ada target
                </p>

                <p
                    class="text-xs
                    text-gray-400 mt-1"
                >
                    Buat target terlebih dahulu.
                </p>


                <button
                    type="button"
                    onclick="
                        closeModal('modalSaving');
                        openModal('modalTarget');
                    "
                    class="mt-4 px-4 py-2
                    bg-brand-500
                    text-white
                    rounded-xl
                    text-xs font-bold"
                >
                    + Buat Target
                </button>

            </div>

        <?php else: ?>


        <form
            method="POST"
            class="space-y-4"
        >

            <input
                type="hidden"
                name="add_saving"
                value="1"
            >


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Pilih Target
                </label>

                <select
                    name="goal_id"
                    required
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

                <?php while ($opt = mysqli_fetch_assoc($options)): ?>

                    <option
                        value="<?= (int)$opt['id'] ?>"
                    >
                        <?= e($opt['title']) ?>
                    </option>

                <?php endwhile; ?>

                </select>

            </div>


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Nominal Tabungan
                </label>

                <input
                    type="number"
                    name="amount"
                    required
                    min="1"
                    step="1"
                    placeholder="50000"
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Tanggal
                </label>

                <input
                    type="date"
                    name="savings_date"
                    value="<?= date('Y-m-d') ?>"
                    required
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div>

                <label
                    class="text-xs font-bold
                    text-gray-500"
                >
                    Catatan
                </label>

                <input
                    type="text"
                    name="note"
                    maxlength="255"
                    placeholder="Contoh: Uang jajan"
                    class="w-full p-3
                    rounded-xl
                    border border-gray-200
                    dark:border-gray-700
                    dark:bg-gray-800
                    text-sm mt-1
                    focus:outline-none
                    focus:ring-2
                    focus:ring-green-500"
                >

            </div>


            <div class="flex gap-2 pt-2">

                <button
                    type="button"
                    onclick="closeModal('modalSaving')"
                    class="flex-1 py-3
                    text-sm font-bold
                    text-gray-500
                    bg-gray-100
                    dark:bg-gray-700
                    rounded-xl"
                >
                    Batal
                </button>


                <button
                    type="submit"
                    class="flex-1 py-3
                    bg-brand-500
                    text-white
                    rounded-xl
                    text-sm font-bold"
                >
                    Simpan
                </button>

            </div>

        </form>

        <?php endif; ?>


        <?php
        mysqli_stmt_close($option_stmt);
        ?>

    </div>

</div>


<!-- =====================================================
     FOOTER
===================================================== -->

<footer
class="text-center py-6
text-xs text-gray-400"
>

    <p>
        &copy; <?= date('Y') ?> SAVEUP.
        Sedikit demi sedikit, jadi impian.
    </p>

</footer>


<!-- =====================================================
     JAVASCRIPT
===================================================== -->

<script>

/* ========================================================
   DARK MODE
======================================================== */

const htmlElement =
    document.documentElement;

const themeToggle =
    document.getElementById('themeToggle');


if (
    localStorage.theme === 'dark' ||
    (
        !('theme' in localStorage) &&
        window.matchMedia(
            '(prefers-color-scheme: dark)'
        ).matches
    )
) {

    htmlElement.classList.add('dark');

} else {

    htmlElement.classList.remove('dark');

}


themeToggle?.addEventListener(
    'click',
    function()
    {

        if (
            htmlElement.classList.contains('dark')
        ) {

            htmlElement.classList.remove('dark');

            localStorage.theme = 'light';

        } else {

            htmlElement.classList.add('dark');

            localStorage.theme = 'dark';

        }

    }
);


/* ========================================================
   MODAL
======================================================== */

function openModal(id)
{

    const modal =
        document.getElementById(id);

    if (!modal) return;

    modal.classList.remove('hidden');

    modal.classList.add('flex');

}


function closeModal(id)
{

    const modal =
        document.getElementById(id);

    if (!modal) return;

    modal.classList.add('hidden');

    modal.classList.remove('flex');

}


/* Klik area luar modal */

document.querySelectorAll(
    '[id^="modal"]'
).forEach(function(modal)
{

    modal.addEventListener(
        'click',
        function(event)
        {

            if (
                event.target === modal
            ) {

                closeModal(modal.id);

            }

        }
    );

});


/* ESC untuk menutup modal */

document.addEventListener(
    'keydown',
    function(event)
    {

        if (event.key === 'Escape') {

            document.querySelectorAll(
                '[id^="modal"]'
            ).forEach(function(modal)
            {

                if (
                    !modal.classList.contains('hidden')
                ) {

                    closeModal(modal.id);

                }

            });

        }

    }
);


/* ========================================================
   SET MINIMUM DEADLINE
======================================================== */

const today =
    new Date().toISOString().split('T')[0];

const targetDeadline =
    document.getElementById('targetDeadline');

if (targetDeadline) {

    targetDeadline.min = today;

}


/* ========================================================
   KALKULATOR
======================================================== */

function calculateSaving()
{

    const targetInput =
        document.getElementById('calcTarget');

    const dateInput =
        document.getElementById('calcDate');


    const target =
        Number(targetInput.value);

    const dateValue =
        dateInput.value;


    if (
        !target ||
        target <= 0 ||
        !dateValue
    ) {

        alert(
            'Harap masukkan nominal dan deadline.'
        );

        return;

    }


    /*
     * Gunakan tanggal tanpa jam
     * agar tidak terpengaruh timezone.
     */

    const todayDate =
        new Date();

    todayDate.setHours(
        0, 0, 0, 0
    );


    const deadline =
        new Date(
            dateValue + 'T00:00:00'
        );


    const diffTime =
        deadline - todayDate;


    const diffDays =
        Math.ceil(
            diffTime /
            (1000 * 60 * 60 * 24)
        );


    if (diffDays <= 0) {

        alert(
            'Deadline harus lebih besar dari hari ini.'
        );

        return;

    }


    const perDay =
        Math.ceil(
            target / diffDays
        );


    const perMonth =
        Math.ceil(
            perDay * 30
        );


    document.getElementById(
        'perDay'
    ).innerText =
        'Rp ' +
        perDay.toLocaleString('id-ID');


    document.getElementById(
        'perMonth'
    ).innerText =
        'Rp ' +
        perMonth.toLocaleString('id-ID');


    document.getElementById(
        'calcResult'
    ).classList.remove('hidden');

}


/* ========================================================
   SET MINIMUM TANGGAL KALKULATOR
======================================================== */

const calcDate =
    document.getElementById('calcDate');

if (calcDate) {

    calcDate.min = today;

}

</script>

</body>
</html>

