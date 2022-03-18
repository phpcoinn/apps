<?php
require_once dirname(__DIR__)."/apps.inc.php";
require_once ROOT. '/web/apps/explorer/include/functions.php';
define("PAGE", true);
define("APP_NAME", "Explorer");

$masternodes = Masternode::getAll();
$block =  Block::current();
$height = $block['height'];
$elapsed = time() - $block['date'];

$winner = Masternode::getWinner($height+1);

$total = count($masternodes);
$valid = 0;
$invalid = 0;
$not_started = 0;
foreach($masternodes as &$masternode) {
	$dbMasternode = Masternode::fromDB($masternode);
	$verified = $dbMasternode->verify($height+1);
	$next_winner = $winner['public_key'] == $masternode['public_key'];
	$row_class="";
    $status = "";
	if($verified && $next_winner) {
		$valid++;
		$row_class = "primary fw-bold";
		$status = "Next winner";
	} else if (empty($masternode['ip'])) {
        $not_started++;
        $row_class = "danger";
		$status = "Not started";
    } else if (!$verified) {
        $invalid++;
		$row_class = "warning";
		$status = "Invalid";
    } else {
		$valid++;
		$row_class = "success";
		$status = "Valid";
    }
	$masternode['row_class']=$row_class;
	$masternode['status']=$status;
}


?>
<?php
require_once __DIR__. '/../common/include/top.php';
?>

<div class="d-flex">
    <ol class="breadcrumb m-0 ps-0 h4">
        <li class="breadcrumb-item"><a href="/apps/explorer">Explorer</a></li>
        <li class="breadcrumb-item active">Masternodes</li>
    </ol>
    <span class="badge font-size-18 bg-primary m-auto me-0"><?php echo $total ?></span>
</div>

<div class="ms-2 mb-2">
    Last block: <?php echo $height ?> Elapsed: <?php echo $elapsed ?>
</div>

<div class="d-flex mb-2">
    <div class="flex-grow-1 d-flex">
        <div class="ms-2">
            <div class="badge rounded-pill badge-soft-danger font-size-16 fw-medium"><?php echo $not_started ?></div> Not started
        </div>
        <div class="ms-2">
            <div class="badge rounded-pill badge-soft-success font-size-16 fw-medium"><?php echo $valid ?></div> Valid
        </div>
        <div class="ms-2">
            <div class="badge rounded-pill badge-soft-warning font-size-16 fw-medium"><?php echo $invalid ?></div> Invalid
        </div>
    </div>
    <div class="me-2 fw-bold">
        <div class="badge rounded-pill badge-soft-primary font-size-16 fw-medium">&nbsp;</div> Next winner
    </div>
</div>

<div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead class="table-light">
            <tr>
                <th>Public key</th>
                <th>Address</th>
                <th>Status</th>
                <th>IP</th>
                <th>Signature</th>
                <th>Height</th>
                <th>Win height</th>
            </tr>
        </thead>
        <tbody>
                <?php foreach($masternodes as $masternode) { ?>
                <tr>
                    <td><?php echo explorer_address_pubkey($masternode['public_key']) ?></td>
                    <td><?php echo explorer_address_link($masternode['id']) ?></td>
                    <td><span class="badge rounded-pill badge-soft-<?php echo $masternode['row_class'] ?> font-size-12"><?php echo $masternode['status'] ?></span></td>
                    <td><?php echo $masternode['ip'] ?></td>
                    <td><?php echo display_short($masternode['signature']) ?></td>
                    <td>
                        <a href="/apps/explorer/block.php?height=<?php echo $masternode['height'] ?>">
			                <?php echo $masternode['height'] ?>
                        </a>
                    </td>
                    <td><?php echo $masternode['win_height'] ?></td>
                </tr>
            <?php } ?>
        </tbody>
    </table>
</div>


<?php
require_once __DIR__ . '/../common/include/bottom.php';
?>
