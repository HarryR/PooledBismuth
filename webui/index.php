<?php
require_once '.common.php';

$workproof = array();
$address_ids = array();
$block_ids = array();
$addresses = array();

$input_hours = max(intval(param('hours')), 1);
$now = time();
$stamp_begin = $now - ($input_hours * (60 * 60));

$sql = "SELECT * FROM blocks WHERE stamp >= $stamp_begin ORDER BY id DESC, stamp DESC";
$block_list = $db->query($sql)->fetchAll();
foreach( $block_list AS $block ) {
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

			<header class="header" id="home">
				<section class="container">
					<br />
					<h1>Pool Statistics</h1>
				</section>
			</header>

			<section class="container">
				<h3>Stats</h3>
				<table>
					<tr>
						<th>Blocks Mined</th>
					</tr>
				</table>
			</section>

			<section class="container">
				<h3>Most Recent Blocks</h3>
				<table>
					<tr>
						<th>Height</th>
						<th>Diff</th>
						<th>Reward</th>
						<th>Nonce</th>
						<th>Shares</th>
						<th>Work</th>
						<th>Bonus</th>
					</tr>

				<?php
				foreach( $block_list AS $row ):
					$proofs = NULL;
					if( isset($workproof[$row['id']]) ) {
						$proofs = $workproof[$row['id']];
					}
				?>
					<tr class="<?= $row['won'] ? 'win' : 'lose' ?>">
						<td><?= $row['id'] ?></td>
						<td><?= $row['difficulty'] ?></td>
						<td><?= round($row['reward'], 2) ?></td>
						<td><?= $row['nonce'] ?></td>
						<td><?= $row['total_shares'] ?></td>
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
						<td colspan="4">
							<table style="margin-left: 50px;">
								<tr>
									<th>Payout Address</th>
									<th>Shares</th>
									<th>Reward</th>
									<th>Pct</th>
								</tr>
							<?php foreach( $proofs AS $proof ): ?>
								<?php $address = $addresses[$proof['address_id']]; ?>
								<tr>
									<td><?= $address ?></td>
									<td><?= $proof['shares']; ?></td>
									<td style="text-align: right;"><?= round($proof['reward'], 2); ?></td>
									<td>
										<?= round($proof['shares'] / ($row['named_shares'] / 100), 2) ?>%
									</td>
								</tr>
							<?php endforeach; ?>
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