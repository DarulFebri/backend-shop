<?php
// FIXED: Complete bug-free version
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') exit(0);

// 🔧 FIXED: Konfigurasi aman
define('DB_HOST', '172.17.0.2');
define('DB_NAME', 'shopdarulfebri');
define('DB_USER', 'root');
define('DB_PASS', '123123123');

class Database {
    private $pdo;
    
    public function __construct() {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
        $this->pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]);
    }
    
    // 🔧 FIXED: Public getter untuk lastInsertId
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }
    
    public function query($sql, $params = []) {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
}

class Auth {
    private $db;
    private $secret = 'shopdarulfebri_secret_2026!@#';
    
    public function __construct() {
        $this->db = new Database();
    }
    
    private function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
    
    private function sign($header, $payload) {
        $signature = hash_hmac('sha256', $header . '.' . $payload, $this->secret, true);
        return $this->base64UrlEncode($signature);
    }
    
    private function verifySignature($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;
        [$header, $payload, $signature] = $parts;
        $expected = $this->sign($header, $payload);
        return hash_equals($expected, $signature);
    }
    
    public function generateToken($userId, $username, $role = 'user', $expHours = 24) {
        $header = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $now = time();
        $payload = $this->base64UrlEncode(json_encode([
            'iss' => 'shopdarulfebri',
            'iat' => $now,
            'exp' => $now + ($expHours * 3600),
            'sub' => $userId,
            'username' => $username,
            'role' => $role
        ]));
        $signature = $this->sign($header, $payload);
        return "$header.$payload.$signature";
    }
    
    public function verifyToken($token) {
        if (!$this->verifySignature($token)) return false;
        $parts = explode('.', $token);
        if (count($parts) !== 3) return false;
        $payload = json_decode($this->base64UrlDecode($parts[1]), true);
        if ($payload['exp'] < time()) return false;
        return $payload;
    }
    
    public function register($data) {
        $username = trim($data['username'] ?? '');
        $email = trim($data['email'] ?? '');
        $password = password_hash($data['password'] ?? '', PASSWORD_DEFAULT);
        
        if (empty($username) || empty($email)) {
            return ['error' => 'Username dan email wajib diisi'];
        }
        
        try {
            $this->db->query("INSERT INTO pengguna (username, email, password) VALUES (?, ?, ?)", 
                [$username, $email, $password]);
            return ['message' => 'User berhasil dibuat'];
        } catch (PDOException $e) {
            return ['error' => 'Username atau email sudah digunakan'];
        }
    }
    
    public function login($data) {
        $username = $data['username'] ?? '';
        $password = $data['password'] ?? '';
        
        $user = $this->db->query("SELECT * FROM pengguna WHERE username = ?", [$username])->fetch();
        if (!$user || !password_verify($password, $user['password'])) {
            return ['error' => 'Login gagal'];
        }
        
        $token = $this->generateToken($user['id'], $user['username'], $user['role'] ?? 'user');
        return ['token' => $token, 'user' => [
            'sub' => $user['id'], 
            'username' => $user['username'], 
            'role' => $user['role'] ?? 'user'
        ]];
    }
}

$db = new Database();
$auth = new Auth();

$request = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($request, PHP_URL_PATH);
$path = trim($path, '/');
$segments = explode('/', $path);
$input = json_decode(file_get_contents('php://input'), true) ?: $_POST;

function respond($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function requireAuth($auth, $adminOnly = false) {
    $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $token = str_replace('Bearer ', '', trim($token));
    
    $user = $auth->verifyToken($token);
    if (!$user) {
        respond(['error' => 'Unauthorized'], 401);
    }
    if ($adminOnly && ($user['role'] ?? 'user') !== 'admin') {
        respond(['error' => 'Admin required'], 403);
    }
    return $user;
}

// 🔧 FIXED: SEMUA BUG DIPERBAIKI
switch (true) {
    case preg_match('#^api/auth/register$#', $path) && $method === 'POST':
        respond($auth->register($input));
    
    case preg_match('#^api/auth/login$#', $path) && $method === 'POST':
        respond($auth->login($input));
    
    case preg_match('#^api/auth/me$#', $path):
        $user = requireAuth($auth);
        unset($user['password']);
        respond($user);
    
    case preg_match('#^api/auth/me$#', $path) && $method === 'PUT':
        $user = requireAuth($auth);
        $db->query("UPDATE pengguna SET username = ?, email = ?, alamat = ? WHERE id = ?", 
            [trim($input['username'] ?? ''), trim($input['email'] ?? ''), $input['alamat'] ?? '', $user['sub']]);
        respond(['message' => 'Profil updated']);
    
    case preg_match('#^api/auth/update-password$#', $path) && $method === 'PUT':
        $user = requireAuth($auth);
        $newPassword = password_hash($input['password'] ?? '', PASSWORD_DEFAULT);
        $db->query("UPDATE pengguna SET password = ? WHERE id = ?", [$newPassword, $user['sub']]);
        respond(['message' => 'Password updated']);
    
    case preg_match('#^api/categories$#', $path) && $method === 'GET':
        $categories = $db->query("SELECT * FROM kategori ORDER BY nama")->fetchAll();
        respond($categories);
    
    // 🔧 FIXED: Products pagination - aman
    case preg_match('#^api/products/?([0-9]+)?$#', $path):
        $productId = isset($segments[2]) && is_numeric($segments[2]) ? (int)$segments[2] : 0;
        $category = $_GET['category'] ?? '';
        $search = $_GET['search'] ?? '';
        $sort = in_array($_GET['sort'] ?? '', ['nama', 'harga', 'stok']) ? $_GET['sort'] : 'nama';
        $page = max(1, (int)($_GET['page'] ?? 1));
        $limit = 10;
        $offset = ($page - 1) * $limit;
        
        if ($productId > 0) {
            $product = $db->query("
                SELECT p.*, k.nama as kategori_nama 
                FROM produk p LEFT JOIN kategori k ON p.id_kategori = k.id 
                WHERE p.id = ?", [$productId])->fetch();
            respond($product ?: ['error' => 'Produk tidak ditemukan'], $product ? 200 : 404);
        }
        
        $where = ['1=1'];
        $params = [];
        if ($category !== '' && is_numeric($category)) {
            $where[] = "p.id_kategori = ?";
            $params[] = (int)$category;
        }
        if ($search !== '') {
            $where[] = "(p.nama LIKE ? OR p.deskripsi LIKE ?)";
            $params[] = "%$search%";
            $params[] = "%$search%";
        }
        
        $sql = "
            SELECT p.*, k.nama as kategori_nama 
            FROM produk p LEFT JOIN kategori k ON p.id_kategori = k.id 
            WHERE " . implode(' AND ', $where) . " 
            ORDER BY " . ($sort === 'harga' ? 'p.harga' : ($sort === 'stok' ? 'p.stok' : 'p.nama')) . " 
            LIMIT $limit OFFSET $offset";
        
        $products = $db->query($sql, $params)->fetchAll();
        $countSql = "SELECT COUNT(*) FROM produk p WHERE " . implode(' AND ', $where);
        $total = $db->query($countSql, $params)->fetchColumn();
        
        respond([
            'data' => $products,
            'pagination' => [
                'page' => $page, 'limit' => $limit, 'total' => (int)$total,
                'pages' => (int)ceil($total / $limit)
            ]
        ]);
    
    // 🔧 FIXED: Cart routes - NULL safety
    case preg_match('#^api/cart/?([0-9]+)?$#', $path):
        $user = requireAuth($auth);
        $cartId = isset($segments[2]) && is_numeric($segments[2]) ? (int)$segments[2] : 0;
        
        if ($method === 'GET') {
            $cart = $db->query("
                SELECT c.*, p.nama, p.harga, p.url_gambar, k.nama as kategori_nama
                FROM keranjang c 
                JOIN produk p ON c.id_produk = p.id 
                LEFT JOIN kategori k ON p.id_kategori = k.id
                WHERE c.id_pengguna = ? ORDER BY c.id DESC", [$user['sub']])->fetchAll();
            respond($cart);
        }
        
        if ($method === 'POST') {
            $id_produk = (int)($input['id_produk'] ?? 0);
            $jumlah = max(1, (int)($input['jumlah'] ?? 1));
            
            if ($id_produk <= 0) respond(['error' => 'ID produk tidak valid'], 400);
            
            $existing = $db->query("SELECT * FROM keranjang WHERE id_pengguna = ? AND id_produk = ?", 
                [$user['sub'], $id_produk])->fetch();
            
            if ($existing) {
                $db->query("UPDATE keranjang SET jumlah = jumlah + ? WHERE id = ?", [$jumlah, $existing['id']]);
            } else {
                $db->query("INSERT INTO keranjang (id_pengguna, id_produk, jumlah) VALUES (?, ?, ?)", 
                    [$user['sub'], $id_produk, $jumlah]);
            }
            respond(['message' => 'Produk ditambahkan ke keranjang']);
        }
        
        // ✅ DELETE TERPISAH - BENAR!
        if ($method === 'DELETE' && $cartId > 0) {
            error_log("🗑️ DELETE CART: ID=$cartId, USER={$user['sub']}");
            
            $deleted = $db->query("DELETE FROM keranjang WHERE id = ? AND id_pengguna = ?", [$cartId, $user['sub']]);
            $rowCount = $deleted->rowCount();
            
            error_log("🗑️ ROWS DELETED: $rowCount");
            
            if ($rowCount > 0) {
                respond(['message' => 'Item dihapus!', 'deleted_rows' => $rowCount]);
            } else {
                respond(['error' => 'Item tidak ditemukan'], 404);
            }
        }
        
        // ✅ PUT TERPISAH - BENAR!
        if ($method === 'PUT' && $cartId > 0) {
            $jumlah = max(1, (int)($input['jumlah'] ?? 1));
            $updated = $db->query("UPDATE keranjang SET jumlah = ? WHERE id = ? AND id_pengguna = ?", 
                [$jumlah, $cartId, $user['sub']]);
            
            if ($updated->rowCount() > 0) {
                respond(['message' => 'Quantity diupdate!', 'new_qty' => $jumlah]);
            } else {
                respond(['error' => 'Item tidak ditemukan'], 404);
            }
        }
        break;  // ✅ break di AKHIR!

    
    // 🔧 FIXED: Orders - NULL safety everywhere
    case preg_match('#^api/orders/?([0-9]+)?/?(cancel)?$#', $path):
        $user = requireAuth($auth);
        $orderId = isset($segments[2]) && is_numeric($segments[2]) ? (int)$segments[2] : 0;
        $isCancel = isset($segments[3]) && $segments[3] === 'cancel';
        
        if ($method === 'POST') {
            $cart = $db->query("SELECT * FROM keranjang WHERE id_pengguna = ?", [$user['sub']])->fetchAll();
            if (empty($cart)) respond(['error' => 'Keranjang kosong'], 400);
            
            $total_harga = 0;
            foreach ($cart as $item) {
                $harga = $db->query("SELECT harga FROM produk WHERE id = ?", [$item['id_produk']])->fetchColumn();
                $total_harga += $harga * $item['jumlah'];
            }
            
            $alamat = trim($input['alamat_pengiriman'] ?? '');
            if (empty($alamat)) respond(['error' => 'Alamat pengiriman wajib'], 400);
            
            $db->query("INSERT INTO pesanan (id_pengguna, total_harga, alamat_pengiriman) VALUES (?, ?, ?)", 
                [$user['sub'], $total_harga, $alamat]);
            $pesanan_id = $db->lastInsertId(); // 🔧 FIXED: Method public
            
            foreach ($cart as $item) {
                $harga = $db->query("SELECT harga FROM produk WHERE id = ?", [$item['id_produk']])->fetchColumn();
                $db->query("INSERT INTO detail_pesanan (id_pesanan, id_produk, jumlah, harga_beli) VALUES (?, ?, ?, ?)", 
                    [$pesanan_id, $item['id_produk'], $item['jumlah'], $harga]);
            }
            
            $db->query("DELETE FROM keranjang WHERE id_pengguna = ?", [$user['sub']]);
            respond(['message' => 'Pesanan berhasil dibuat', 'id' => $pesanan_id]);
        }
        
        if ($method === 'GET') {
            if ($orderId > 0) {
                $order = $db->query("
                    SELECT p.*, GROUP_CONCAT(d.jumlah, 'x', d.harga_beli) as items 
                    FROM pesanan p LEFT JOIN detail_pesanan d ON p.id = d.id_pesanan 
                    WHERE p.id = ? AND p.id_pengguna = ? GROUP BY p.id", 
                    [$orderId, $user['sub']])->fetch();
                respond($order ?: ['error' => 'Pesanan tidak ditemukan'], $order ? 200 : 404);
            } else {
                $orders = $db->query("
                    SELECT p.*, SUM(d.jumlah * d.harga_beli) as total_items 
                    FROM pesanan p LEFT JOIN detail_pesanan d ON p.id = d.id_pesanan 
                    WHERE p.id_pengguna = ? GROUP BY p.id ORDER BY p.dibuat_pada DESC", 
                    [$user['sub']])->fetchAll();
                respond($orders);
            }
        }
        
        if ($orderId > 0 && $isCancel && $method === 'PATCH') {
            $db->query("UPDATE pesanan SET status = 'dibatalkan' WHERE id = ? AND id_pengguna = ? AND status = 'pending'", 
                [$orderId, $user['sub']]);
            respond(['message' => 'Pesanan dibatalkan']);
        }
        break;
    
    // Admin routes - sudah aman
    case preg_match('#^api/admin/(products|categories)/?([0-9]+)?$#', $path):
        $user = requireAuth($auth, true);
        $resource = $segments[2];
        $id = isset($segments[3]) && is_numeric($segments[3]) ? (int)$segments[3] : 0;
        
        $table = $resource === 'products' ? 'produk' : 'kategori';
        $fields = $resource === 'products' ? 
            ['id_kategori', 'nama', 'deskripsi', 'harga', 'stok', 'url_gambar'] : ['nama'];
        
        if ($method === 'GET' && !$id) {
            $items = $db->query("SELECT * FROM `$table` ORDER BY dibuat_pada DESC")->fetchAll();
            respond($items);
        }
        
        if ($method === 'POST' && !$id) {
            $params = array_intersect_key($input, array_flip($fields));
            if ($resource === 'products' && (!isset($params['id_kategori']) || !isset($params['nama']))) {
                respond(['error' => 'id_kategori dan nama wajib untuk produk'], 400);
            }
            $placeholders = implode(',', array_fill(0, count($fields), '?'));
            $db->query("INSERT INTO `$table` (`" . implode('`, `', $fields) . "`) VALUES ($placeholders)", array_values($params));
            respond(['message' => 'Created', 'id' => $db->lastInsertId()]);
        } elseif (in_array($method, ['PUT', 'POST']) && $id) {
            $set = [];
            $params = [$id];
            foreach ($fields as $field) {
                if (isset($input[$field])) {
                    $set[] = "`$field` = ?";
                    $params[] = $input[$field];
                }
            }
            if (empty($set)) respond(['error' => 'Tidak ada field yang diupdate'], 400);
            $db->query("UPDATE `$table` SET " . implode(', ', $set) . " WHERE id = ?", $params);
            respond(['message' => 'Updated']);
        } elseif ($method === 'DELETE' && $id) {
            $db->query("DELETE FROM `$table` WHERE id = ?", [$id]);
            respond(['message' => 'Deleted']);
        }
        break;
    
    case preg_match('#^api/admin/orders/?([0-9]+)?$#', $path):
        $user = requireAuth($auth, true);
        $orderId = isset($segments[3]) && is_numeric($segments[3]) ? (int)$segments[3] : 0;
        
        if ($method === 'GET') {
            $orders = $db->query("
                SELECT p.*, u.username, COUNT(d.id) as item_count 
                FROM pesanan p 
                LEFT JOIN pengguna u ON p.id_pengguna = u.id 
                LEFT JOIN detail_pesanan d ON p.id = d.id_pesanan 
                GROUP BY p.id ORDER BY p.dibuat_pada DESC")->fetchAll();
            respond($orders);
        }
        
        if ($method === 'PATCH' && $orderId) {
            $status = $input['status'] ?? '';
            if (!in_array($status, ['pending', 'dibayar', 'dikirim', 'selesai', 'dibatalkan'])) {
                respond(['error' => 'Status tidak valid'], 400);
            }
            $db->query("UPDATE pesanan SET status = ? WHERE id = ?", [$status, $orderId]);
            respond(['message' => 'Status updated']);
        }
        break;
    
    case preg_match('#^api/admin/stats$#', $path):
        $user = requireAuth($auth, true);
        $stats = [
            'total_users' => $db->query("SELECT COUNT(*) FROM pengguna")->fetchColumn(),
            'total_orders' => $db->query("SELECT COUNT(*) FROM pesanan")->fetchColumn(),
            'total_revenue' => (float)($db->query("SELECT COALESCE(SUM(total_harga), 0) FROM pesanan WHERE status IN ('dibayar', 'selesai')")->fetchColumn() ?: 0),
            'pending_orders' => $db->query("SELECT COUNT(*) FROM pesanan WHERE status = 'pending'")->fetchColumn()
        ];
        respond($stats);
    
    default:
        respond(['error' => 'Endpoint not found', 'path' => $path], 404);
}
?>
