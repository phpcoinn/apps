<?php

global $_config;
if($_config['testnet']) {
	define("APPS_REPO_SERVER","https://repo.testnet.phpcoin.net");
	define("APPS_REPO_SERVER_PUBLIC_KEY","PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSCwUKtSuRJEs8RrRrkZbND1WxVNomPtvowAo5hzQr6xe2TUyHYLnzu2ubVMfBAYM4cBZJLckvxWenHB2nULzmU8VHz");
	define("APPS_WALLET_SERVER_NAME","wallet.testnet.phpcoin.net");
	define("APPS_WALLET_SERVER_PUBLIC_KEY","PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSCxxo8UaTrKLceuCRRC4YopodMLvtPp31Bq1JJBmva3StkHMPa2WhgXhPyPLG9GiwEW3PwXDyroZGfNLE4ioqRtwyp");
} else {
	define("APPS_REPO_SERVER","https://repo.phpcoin.net");
	define("APPS_REPO_SERVER_PUBLIC_KEY","PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSCyHWjnG15LHdWRRbNEmAPiYcyCqFZm1VKi8QziKYbMtrXUw8rqhrS3EEoyJxXASNZid9CsB1dg64u5sYgnUsrZg7C");
	define("APPS_WALLET_SERVER_NAME","wallet.phpcoin.net");
	define("APPS_WALLET_SERVER_PUBLIC_KEY","PZ8Tyr4Nx8MHsRAGMpZmZ6TWY63dXWSD1SfcgMjJaHdx6p3BT9Jft9NXyh57c1EnisRgbtLDzXfEwddq6i717adJKkw82HMJDfRD8PZikraaq1HnBdCVxLsY");
}


function calcAppsHash() {
	$cmd = "cd ".ROOT."/web && tar -cf - apps --owner=0 --group=0 --sort=name --mode=744 --mtime='2020-01-01 00:00:00 UTC' | sha256sum";
	$res = shell_exec($cmd);
	$arr = explode(" ", $res);
	$appsHash = trim($arr[0]);
	_log("Executing calcAppsHash appsHash=$appsHash", 5);
	return $appsHash;
}

function buildAppsArchive() {
	$cmd = "cd ".ROOT." && tar -czf tmp/apps.tar.gz web/apps --owner=0 --group=0 --sort=name --mode=744 --mtime='2020-01-01 00:00:00 UTC'";
	shell_exec($cmd);
}
