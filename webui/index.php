<?php
require_once '.common.php';

$workproof = array();
$address_ids = array();
$block_ids = array();
$addresses = array();

$input_hours = min(max(intval(param('hours')), 1), 12);
$now = time();
$stamp_begin = $now - ($input_hours * (60 * 60));

$sql = "SELECT * FROM blocks WHERE stamp >= $stamp_begin ORDER BY id DESC, stamp DESC";
$block_list = $db->query($sql)->fetchAll();
if( 0 == count($block_list) ) {
	die('FATAL ERROR');
}

$latest_block = $block_list[0];
$blocks_end = $block_list[0]['stamp'];
$blocks_begin = $block_list[ count($block_list) - 1 ]['stamp'];
$reward_total = 0;
foreach( $block_list AS $block ) {
	if( $block['won'] ) {
		$reward_total += $block['reward'];
	}
	$block_ids []= intval($block['id']);
}

$sql = sprintf("SELECT * FROM workproof WHERE block_id IN (%s)", implode(',', $block_ids));
$proof_list = $db->query($sql)->fetchAll();
foreach( $proof_list AS $proof ) {
	$address_ids []= $proof['address_id'];
	if( ! isset($workproof[$proof['block_id']]) ) {
		$workproof[$proof['block_id']] = array();
	}
	$workproof[$proof['block_id']][$proof['address_id']] = $proof;
}

$sql = sprintf("SELECT id, address FROM addresses WHERE id IN (%s)", implode(',', $address_ids));
foreach( $db->query($sql)->fetchAll() AS $row ) {
	$addresses[$row['id']] = $row['address'];
}

/*
SELECT (SUM(wp.shmeckles) / (MAX(b.stamp) - MIN(b.stamp))) * 60 * 60, wp.addr                                                                              GROUP BY address_id;
*/
?>

<html>
	<head>
		<title>1 Hour Pool Statistics</title>
		<!-- Google Fonts -->
		<link rel="stylesheet" href="//fonts.googleapis.com/css?family=Roboto:300,300italic,700,700italic">

		<!-- CSS Reset -->
		<link rel="stylesheet" href="//cdn.rawgit.com/necolas/normalize.css/master/normalize.css">

		<!-- Milligram CSS minified -->
		<link rel="stylesheet" href="//cdn.rawgit.com/milligram/milligram/master/dist/milligram.min.css">

		<style>
		.win {
			background-color: #c0ffa5;
			border-top: 10px solid #333 !important;
		}
		.lose {
			background-color: #f9d4d4;
		}
		</style>
	</head>
	<body>
			<main class="wrapper">

			<section class="container">
				<table>
					<tr>
						<th style="text-align: right;">Mining Rate</th>
						<td><?= round(($reward_total / ($blocks_end - $blocks_begin)) * 60 * 60,2) ?> BIS/hour</td>

						<th style="text-align: right;">Exchange Rate</th>
						<td>1 SHM = <?= round($latest_block['pool_balance'] / $latest_block['pool_shmeckles'], 2) ?> BIS</td>
					</tr>
				</table>
			</section>

			<section class="container">
				<h3>Most Recent Blocks</h3>
				<table>

				<?php
				foreach( $block_list AS $idx => $row ):
					$proofs = NULL;
					if( isset($workproof[$row['id']]) ) {
						$proofs = $workproof[$row['id']];
					}
				?>
					<?php if( ! ($idx % 25) ): ?>
					<tr>
						<th>Timestamp</th>
						<th>Height</th>
						<th>Diff</th>
						<th>Reward</th>
						<th>Address</th>
						<th>Nonce</th>
						<th>POW</th>
						<th>Anon%</th>
					</tr>
					<?php endif; ?>

					<tr class="<?= $row['won'] ? 'win' : 'lose' ?>">
						<td><?= $row['stamp'] ?></td>
						<td><?= $row['id'] ?></td>
						<td><?= $row['difficulty'] ?></td>
						<td><?= round($row['reward'], 2) ?></td>
						<td><?= htmlspecialchars(substr($row['address'], 0, 10)) ?></td>
						<td><?= htmlspecialchars($row['nonce']) ?></td>
						<td><?= $row['total_work'] ?></td>
						<td>
							<?php if( $row['total_shares'] > 0 ): ?>
								<?= sprintf("%.1f%%", 100 - ($row['named_shares'] / $row['total_shares']) * 100) ?>
							<?php else: ?>
								0%
							<?php endif; ?>
						</td>
					</tr>
					<?php if( $proofs ): ?>
					<tr>
						<td colspan="6">
							<table style="margin-left: 50px;">
								<tr>
									<th>Address</th>
									<th>Shmeckles</th>
									<th>Bismuth</th>
								</tr>
							<?php foreach( $proofs AS $proof ): ?>
								<?php $address = $addresses[$proof['address_id']]; ?>
								<tr>
									<td><?= htmlspecialchars($address) ?></td>
									<td><?= sprintf("%.2f", $proof['shmeckles']); ?></td>
									<td><?= sprintf("%.2f", ($proof['shmeckles'] / $row['pool_shmeckles']) * $row['pool_balance'] ); ?></td>
								</tr>
							<?php endforeach; ?>

								<tr>
									<th>Total</th>
									<th><?= sprintf("%.2f", $row['pool_shmeckles']) ?></th>
									<th><?= sprintf("%.2f", $row['pool_balance']) ?></th>
								</tr>
							</table>
							<br />
						</td>
					</tr>
					<?php endif; ?>
				<?php endforeach ?>				
				</table>
			</section>
	</body>
</html>
