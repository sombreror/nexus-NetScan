<?php
declare(strict_types=1);

namespace Nexus\Db;

use PDO;
use PDOException;

class Database
{
    private static ?PDO $instance = null;

    public static function get(): PDO
    {
        if (self::$instance !== null) return self::$instance;

        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            DB_HOST, DB_PORT, DB_NAME
        );

        self::$instance = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        return self::$instance;
    }

    public static function scalar(string $sql, array $p = []): mixed
    {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($p);
        $v = $stmt->fetchColumn();
        return $v === false ? null : $v;
    }

    public static function fetchAll(string $sql, array $p = []): array
    {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($p);
        return $stmt->fetchAll();
    }

    public static function fetchOne(string $sql, array $p = []): ?array
    {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($p);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function execute(string $sql, array $p = []): int
    {
        $stmt = self::get()->prepare($sql);
        $stmt->execute($p);
        return $stmt->rowCount();
    }

    public static function lastInsertId(): string
    {
        return self::get()->lastInsertId();
    }
}
