<?php
require_once dirname(__DIR__)."/apps.inc.php";
require_once ROOT. '/web/apps/explorer/include/functions.php';
define("PAGE", true);
define("APP_NAME", "Explorer");

$masternodes = Masternode::getAll();
$height =  Block::getHeight();

$winner = Masternode::getWinner($height+1);

?>
<?php
require_once __DIR__. '/../common/include/top.php';
?>

<ol class="breadcrumb m-0 ps-0 h4">
	<li class="breadcrumb-item"><a href="/apps/explorer">Explorer</a></li>
	<li class="breadcrumb-item active">Masternodes</li>
</ol>

<div class="table-responsive">
    <table class="table table-sm table-striped">
        <thead class="table-light">
            <tr>
                <th>Public key</th>
                <th>Address</th>
                <th>Signature</th>
                <th>Height</th>
                <th>Win height</th>
            </tr>
        </thead>
        <tbody>
                <?php foreach($masternodes as $masternode) { 
                    
                    $dbMasternode = Masternode::fromDB($masternode);
                    $valid = $dbMasternode->verify($height+1);
                    $next_winner = $winner['public_key'] == $masternode['public_key'];
                    ?>
                <tr class="<?php if (!$valid) { ?>table-danger<?php } ?> <?php if ($valid && $next_winner) { ?>table-success<?php } ?>">
                    <td><?php echo explorer_address_pubkey($masternode['public_key']) ?></td>
                    <td><?php echo explorer_address_link($masternode['id']) ?></td>
                    <td><?php echo $masternode['signature'] ?></td>
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
    Last block: <?php echo $height ?>
</div>


<?php
require_once __DIR__ . '/../common/include/bottom.php';
?>
