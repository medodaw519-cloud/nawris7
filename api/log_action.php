<?php
declare(strict_types=1);

require __DIR__ . '/db.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['success' => false, 'message' => 'Method not allowed'], 405);
}

session_start();

$employeeId = $_SESSION['employee_id'] ?? null;
$employeeName = $_SESSION['employee_name'] ?? null;

if (!$employeeId || !$employeeName) {
    json_response(['success' => false, 'message' => 'Unauthorized session'], 401);
}

$raw = file_get_contents('php://input');
$payload = json_decode($raw ?: '{}', true);
if (!is_array($payload)) {
    json_response(['success' => false, 'message' => 'Invalid JSON body'], 400);
}

$packageRaw = (string)($payload['package_id'] ?? '');
$packageId = preg_replace('/[^0-9]/', '', $packageRaw);
$actionType = trim((string)($payload['action_type'] ?? ''));
$status = trim((string)($payload['status'] ?? ''));

if ($packageId === '' || $actionType === '') {
    json_response(['success' => false, 'message' => 'package_id and action_type are required'], 400);
}

try {
    $pdo = crm_pdo();
    $stmt = $pdo->prepare(
        'INSERT INTO package_logs (package_id, employee_id, employee_name, action_type, status)
         VALUES (:package_id, :employee_id, :employee_name, :action_type, :status)'
    );
    $stmt->execute([
        ':package_id' => $packageId,
        ':employee_id' => (int)$employeeId,
        ':employee_name' => (string)$employeeName,
        ':action_type' => $actionType,
        ':status' => $status !== '' ? $status : null,
    ]);

    json_response([
        'success' => true,
        'message' => 'Action logged',
        'id' => (int)$pdo->lastInsertId(),
    ], 200);
} catch (Throwable $e) {
    json_response([
        'success' => false,
        'message' => 'Failed to log action',
        'error' => $e->getMessage(),
    ], 500);
}
