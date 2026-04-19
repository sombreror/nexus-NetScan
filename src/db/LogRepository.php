<?php
declare(strict_types=1);

namespace Nexus\Db;

class LogRepository
{
    private const VALID_LEVELS = ['INFO','WARN','ERROR','SUCCESS'];
    private const VALID_TOOLS  = [
        'ping','dns','traceroute','whois','ssl','headers',
        'uptime','latency','ipinfo','subdomains','status',
        'portscan','redirect',
    ];

    public static function list(string $level, string $tool, int $page, string $search = ''): array
    {
        $where  = ['1=1'];
        $params = [];

        if ($level !== 'ALL' && in_array($level, self::VALID_LEVELS, true)) {
            $where[] = 'level = ?'; $params[] = $level;
        }
        if ($tool !== 'ALL' && in_array($tool, self::VALID_TOOLS, true)) {
            $where[] = 'tool = ?'; $params[] = $tool;
        }
        if ($search !== '') {
            $where[] = 'target LIKE ?'; $params[] = '%' . $search . '%';
        }

        $wc     = implode(' AND ', $where);
        $limit  = LOG_PAGE_SIZE;
        $offset = ($page - 1) * $limit;

        $total = (int)Database::scalar("SELECT COUNT(*) FROM logs WHERE $wc", $params);

        $rows = Database::fetchAll(
            "SELECT id,created_at,level,tool,target,ip,user_id,result,duration_ms
             FROM logs WHERE $wc ORDER BY created_at DESC LIMIT $limit OFFSET $offset",
            $params
        );

        return ['logs' => $rows, 'total' => $total, 'page' => $page,
                'pages' => max(1, (int)ceil($total / $limit))];
    }

    public static function stats(): array
    {
        $db      = Database::get();
        $total   = (int)$db->query("SELECT COUNT(*) FROM logs")->fetchColumn();
        $errors  = (int)$db->query("SELECT COUNT(*) FROM logs WHERE level='ERROR'")->fetchColumn();
        $success = (int)$db->query("SELECT COUNT(*) FROM logs WHERE level='SUCCESS'")->fetchColumn();
        $today   = (int)$db->query("SELECT COUNT(*) FROM logs WHERE DATE(created_at)=CURDATE()")->fetchColumn();

        $byTool = [];
        foreach ($db->query("SELECT tool, COUNT(*) AS cnt FROM logs GROUP BY tool") as $r) {
            $byTool[$r['tool']] = (int)$r['cnt'];
        }

        $avgDur = [];
        foreach ($db->query("SELECT tool, ROUND(AVG(duration_ms),1) AS avg FROM logs
                              WHERE created_at >= NOW() - INTERVAL 24 HOUR GROUP BY tool") as $r) {
            $avgDur[$r['tool']] = (float)$r['avg'];
        }

        return compact('total','errors','success','today','byTool','avgDur') +
               ['by_tool' => $byTool, 'avg_dur' => $avgDur];
    }
}
