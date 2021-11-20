<?php
require_once dirname(__DIR__)."/apps.inc.php";
define("PAGE", true);
define("APP_NAME", "Explorer");

$peers = Peer::getAll();

function truncate_hash($hash) {
    return substr($hash, 0, 8) . "..." . substr($hash, -8);
}

?>

<?php
require_once __DIR__. '/../common/include/top.php';
?>

<ol class="breadcrumb m-0 ps-0 h4">
    <li class="breadcrumb-item"><a href="/apps/explorer">Explorer</a></li>
    <li class="breadcrumb-item active">Peers</li>
</ol>

<h3>Peers <span class="float-end badge bg-primary"><?php echo count($peers) ?></span> </h3>

<div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead class="table-light">
            <tr>
                <th>Hostname</th>
                <th>Ip</th>
                <th>Ping</th>
                <th>Height</th>
                <th>Apps hash</th>
                <th>Score</th>
            </tr>
        </thead>
        <tbody>
            <?php
                $blacklisted_cnt = 0;
                foreach($peers as $peer) {
                $blacklisted = $peer['blacklisted'] > time();
                if($blacklisted) {
	                $blacklisted_cnt++;
                    continue;
                }
                ?>
                <tr>
                    <td><a href="<?php echo $peer['hostname'] ?>" target="_blank"><?php echo $peer['hostname'] ?></a></td>
                    <td><?php echo $peer['ip'] ?></td>
                    <td><?php echo display_date($peer['ping']) ?></td>
                    <td><?php echo $peer['height'] ?></td>
                    <td class="">
                        <?php if($peer['appshash']) { ?>
                            <?php echo truncate_hash($peer['appshash']) ?>
                            <div class="app-hash">
                                <?php echo hashimg($peer['appshash'], "Apps hash: ". $peer['appshash']) ?>
                            </div>
                        <?php } ?>
                    </td>
                    <td>
                        <?php if ($peer['score']) { ?>
                            <div class="ns">
                                <div class="progress progress-lg node-score me-1">
                                    <div class="progress-bar bg-<?php echo ($peer['score'] < MIN_NODE_SCORE / 2 ? 'danger' : ($peer['score'] < MIN_NODE_SCORE ? 'warning' : 'success')) ?>" role="progressbar" style="width: <?php echo $peer['score'] ?>%;" aria-valuenow="<?php echo $peer['score'] ?>" aria-valuemin="0" aria-valuemax="100"></div>
                                </div>
                            </div>
                            <?php echo $peer['score'] ?>
                        <?php } ?>
                    </td>
                </tr>
            <?php } ?>
        </tbody>
    </table>
</div>
<?php if ($blacklisted_cnt> 0) { ?>
    <div><?php echo $blacklisted_cnt ?> blacklisted</div>
<?php } ?>

<div>Node score: <?php echo round($_config['node_score'],2); ?>%</div>

<?php
require_once __DIR__ . '/../common/include/bottom.php';
?>
<style>
    .app-hash, .ns {
        display:inline-block;
    }
</style>
