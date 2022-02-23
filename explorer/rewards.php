<?php
require_once dirname(__DIR__)."/apps.inc.php";
define("PAGE", true);
define("APP_NAME", "Explorer");

$rows = Blockchain::calculateRewardsScheme(false);
$real = Blockchain::calculateRewardsScheme(true);

?>

<?php
require_once __DIR__. '/../common/include/top.php';
?>

<ol class="breadcrumb m-0 ps-0 h4">
	<li class="breadcrumb-item"><a href="/apps/explorer">Explorer</a></li>
	<li class="breadcrumb-item active">Rewards scheme</li>
</ol>

<div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead class="table-light">
        <tr>
            <th>Phase</th>
            <th>Start block</th>
            <th>End block</th>
            <th>Total reward</th>
            <th>Miner</th>
            <th>Generator</th>
            <th>Masternode</th>
            <th>Days duration</th>
            <th>Projected time end</th>
            <th>Real time end</th>
            <th>Total supply</th>
        </tr>
        </thead>
        <tbody>
            <?php foreach($rows as $key=> $row) { ?>
                <tr>
                    <td><?php echo $row['phase'] ?></td>
                    <td><?php echo $row['block'] ?></td>
                    <td><?php echo $row['end_block'] ?></td>
                    <td><?php echo $row['total'] ?></td>
                    <td><?php echo $row['miner'] ?></td>
                    <td><?php echo $row['gen'] ?></td>
                    <td><?php echo $row['mn'] ?></td>
                    <td><?php echo round($row['days'],2) ?></td>
                    <td><?php echo display_date($row['time']) ?></td>
                    <td><?php if(isset($real[$key])) echo display_date($real[$key]['time'])  ?></td>
                    <td><?php echo $row['supply'] ?></td>
                </tr>
            <?php } ?>
        </tbody>
    </table>
</div>




<?php
require_once __DIR__ . '/../common/include/bottom.php';
?>
