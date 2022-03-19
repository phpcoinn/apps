<?php
require_once dirname(__DIR__)."/apps.inc.php";
require_once ROOT. '/web/apps/explorer/include/functions.php';
define("PAGE", true);
define("APP_NAME", "Explorer");


$dm = get_data_model(-1, "/apps/explorer/masternodes.php?");

$sorting = '';
if(isset($dm['sort'])) {
	$sorting = ' order by '.$dm['sort'];
	if(isset($dm['order'])){
		$sorting.= ' ' . $dm['order'];
	}
}

global $db;
$sql = "select * from masternode $sorting ";
$masternodes = $db->run($sql);

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
	$status_class = "";
	if($verified) {
		$valid++;
		$status = "Valid";
		$status_class = "success";
	} else if (empty($masternode['ip'])) {
        $not_started++;
		$status = "Not started";
		$status_class = "danger";
    } else  {
        $invalid++;
		$status = "Invalid";
		$status_class = "warning";
    }
    if($next_winner) {
	    $row_class = "primary fw-bold";
    }
	$masternode['row_class']=$row_class;
	$masternode['status']=$status;
	$masternode['status_class']=$status_class;
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
    <table class="table table-sm table-striped dataTable">
        <thead class="table-light">
            <tr>
                <th>Public key</th>
	            <?php echo sort_column("/apps/explorer/masternodes.php?", $dm, 'id', 'Address' ,'') ?>
                <th>Status</th>
                <th>IP</th>
                <th>Signature</th>
	            <?php echo sort_column("/apps/explorer/masternodes.php?", $dm, 'height', 'Height' ,'') ?>
                <?php echo sort_column("/apps/explorer/masternodes.php?", $dm, 'win_height', 'Win Height', '') ?>
            </tr>
        </thead>
        <tbody>
                <?php foreach($masternodes as $masternode) { ?>
                <tr class="table-<?php echo $masternode['row_class'] ?>">
                    <td><?php echo explorer_address_pubkey($masternode['public_key']) ?></td>
                    <td><?php echo explorer_address_link($masternode['id']) ?></td>
                    <td><span class="badge rounded-pill badge-soft-<?php echo $masternode['status_class'] ?> font-size-12"><?php echo $masternode['status'] ?></span></td>
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
