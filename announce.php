<?
// Switch-Torrents - Announce.php - Replaced/Upgraded August/2020
require_once '../site.php';
require_once '../bencoding.php';
$db->connect();

$db->query_params('DELETE FROM peers WHERE last_announce + ' . $db->interval('1 hour') . ' < CURRENT_TIMESTAMP');

header('Content-Type: text/plain');

function fail($reason) {
    die(bencode(array('failure reason' => $reason)));
}

function ip2bytes($ip) {
    $res = '';
    $parts = explode('.', $ip);
    if (count($parts) !== 4) return null;
    for ($i = 0; $i < 4; $i++) {
        $b = $parts[$i];
        if (!is_numeric($b)) return null;
        $b = intval($b);
        if ($b < 0 || $b >= 256) return null;
        $res .= chr($b);
    }
    return $res;
}

// Check Peer ID if banned - Sep 5, 2020
function isPeerIDBanned($peer_id, $torrent_id, $passkey)
{
    global $db, $CONFIG;
    if (array_key_exists('ban_peer_ids', $CONFIG)) {
        $valid = $db->query_params('SELECT chosen_peer_id, torrent_id, passkey FROM peers WHERE torrent_id = :torrent_id AND passkey = :passkey', array('torrent_id' => $torrent_id,'passkey' => $passkey)) or fail('db error');
        foreach ($CONFIG as $key) {
            foreach ($valid as $peer) {
                if ($CONFIG['ban_peer_ids'] == $peer['chosen_peer_id']) {
	                $message = sprintf('Peer ID banned - %s', $peer['chosen_peer_id']);
	                $db->query_params('INSERT INTO announcelogs (message) VALUES (:message)', array('message' => $message)); // Log the event
                    fail(sprintf('Peer ID banned - %s', $peer['chosen_peer_id']));
                }
            }
        }
    } else {
        return;
    }
}

// Max Slots - Improved/updated - Sep 5, 2020 - DISABLED FOR SEED BONUS SLOTS UPGRADE/PLANS
/*
function avail_slots($user_id, $user_class)
{
    global $db;
    $checkslots  = $db->query_params('SELECT u.class, u.warned, u.user_id, g.group_id, g.level, g.maxslots AS totalslots FROM groups g LEFT JOIN users u ON u.class = g.group_id WHERE g.group_id = :user_class AND u.user_id = :user_id', array('user_class' => $user_class, 'user_id' => $user_id));
    $row      	 = $checkslots->fetch();
    if (array_key_exists('warned', $row)) {
    	if ($row['warned'] == 'yes'): $maxslot = 1; else: $maxslot = $row['maxslots']; endif;
		return $row['totalslots'];
	}
}
*/

function isConnectable($ip, $port) {
    $fp = @fsockopen($ip, $port, $errno, $errstr, 0.1);
    if (!$fp) {
        return false;
    } else {
        fclose($fp);
        return true;
    }
}

$keys = array(
	'downloaded' => true,
	'uploaded' => true,
	'passkey' => true,
    'username' => false,
    'torrent_id' => false,
    'token' => false,
    'info_hash' => true,
    'peer_id' => true,
    'port' => true,
    'no_peer_id' => false,
    'ip' => false,
    'numwant' => false,
    'event' => false, // Keep off. This kills the seedbox from connecting out!
    'left' => true,
    'compact' => false,
);

$data = array();
foreach ($keys as $key => $req) {
    if (array_key_exists($key, $_GET)) {
        $data[$key] = $_GET[$key];
    } else if ($req) {
        fail(sprintf('missing key: %s', $key));
    }
}

// Client banning
/*
$agentarray = trim(explode(',', $CONFIG['client_bans'])));
$useragent = substr($data['peer_id'], 0, 8);
	foreach($agentarray as $bannedclient)
		if (array_key_exists($key, $_GET)) {
		if (strpos($useragent, $bannedclient) !== false) fail('Client is banned.');
*/

// TODO : Update so torrent uploaded/downloaded is counted. Grant users extra GB for inconvience. 

// Get client info
$client = substr($data['peer_id'], 0, 8);

$data['info_hash'] = bin2hex($data['info_hash']);
$data['peer_id'] = bin2hex($data['peer_id']);

$res = $db->query_params('SELECT user_id, passkey, username, class FROM users WHERE passkey = :passkey', array('passkey' => $data['passkey'])) or fail('db error line 56');
$user_row = $res->fetch() or fail("access denied line 57");

// Max download slots check - Sep 5, 2020
$maxslots = $db->query_params("SELECT COUNT(DISTINCT torrent_id) AS total FROM peers WHERE user_id = :user_id AND seeder = 'no'", array('user_id' => $user_row['user_id']));
foreach ($maxslots as $slots) {
	$totalslots = $slots['total'];
	$maxslot = avail_slots($user_row['user_id'], $user_row['class']); 
	if ($totalslots >= $maxslot){ // removed >= as it was reducing downloads by only 1 at a time (2/2, 1 downloading) transfer for regular class. 
		fail("Maximum $totalslots/$maxslot download slots exceeded! Finish current transfers to reclaim slots.");
	}
}

// TODO: Deal with tokens / config
if (array_key_exists('token', $data)) {
	$token = md5('token{' . $data['torrent_id'] . ',' . $user_row['passkey'] . '}');
	if (!hash_equals($token, $data['token'])) fail('access denied line 67');
}

if (!is_numeric($data['port'])) fail('invalid port');
$data['port'] = intval($data['port']);
if ($data['port'] < 1 || $data['port'] >= 65536) fail('invalid port');

if (array_key_exists('left', $data)) {
    if (!is_numeric($data['left'])) fail('invalid left');
    $data['left'] = intval($data['left']);
    if ($data['left'] < 0) fail('invalid left');
}

if (!array_key_exists('ip', $data)) {
	$data['ip'] = getip();

    $try_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP');
    foreach ($try_keys as $key) {
        if (array_key_exists($key, $_SERVER)) {
            $potential_ip = trim(explode(',', $_SERVER[$key])[0]);

            // Ignore private IP addresses
            if (strpos($potential_ip, '10.') === 0) continue;
            if (strpos($potential_ip, '192.168.') === 0) continue;
            // TODO: 172.16.0.0/12 is also private

            $data['ip'] = $potential_ip;
            break;
        }
    }
}

if (array_key_exists('numwant', $data)) {
    if (!is_numeric($data['numwant'])) fail('invalid numwant');
    $data['numwant'] = intval($data['numwant']);
    if ($data['numwant'] < 0) $data['numwant'] = 1000;
    if ($data['numwant'] > 1000) $data['numwant'] = 1000;
} else {
    $data['numwant'] = 30;
}

$seeder = ($data['left'] == 0) ? 'yes' : 'no';

if (isConnectable($data['ip'], $data['port'])): $connectable = 'yes'; else: $connectable = 'no'; endif;

$res = $db->query_params('SELECT torrent_id FROM torrents WHERE info_hash = :info_hash', array('info_hash' => $data['info_hash'])) or fail('db error'); 
$torrent_row = $res->fetch() or fail('no such torrent');


$valid = $db->query_params('SELECT * FROM peers WHERE torrent_id = :torrent_id AND passkey = :passkey', array('torrent_id' => $torrent_row['torrent_id'], 'passkey' => $data['passkey'])) or fail('db error'); 
$active = $valid->fetch();
/*
$findseeders   = $db->query_params("SELECT COUNT(*) FROM peers WHERE seeder = 'yes' AND torrent_id = :torrent_id", array('torrent_id' => $torrent_row['torrent_id'])); // Perfect!
$findleechers  = $db->query_params("SELECT COUNT(*) FROM peers WHERE seeder = 'no' AND torrent_id = :torrent_id", array('torrent_id' => $torrent_row['torrent_id'])); // Reflecting seeder count - wrong!
$checkifseeder = $db->query_params("SELECT seeder FROM peers WHERE seeder = 'yes' AND connectable = 'yes' AND torrent_id = :torrent_id", array('torrent_id' => $torrent_row['torrent_id']));

foreach ($checkifseeder->fetch() as $row) {
	if ($row['seeder'] == 'yes'){
		$is_seeder = true;
	}else{
		$is_seeder = false;
	}
}

foreach ($findseeders->fetch() as $row) {
	$getseeders = $row;
	foreach ($findleechers->fetch() as $row2){
		$getleechers = $row2;
	}
}
*/
$res = $db->query_params('SELECT peer_id, completed, seeder FROM peers WHERE user_id = :user_id AND torrent_id = :torrent_id AND chosen_peer_id = :chosen_peer_id', array('user_id' => $user_row['user_id'], 'torrent_id' => $torrent_row['torrent_id'], 'chosen_peer_id' => $data['peer_id'])) or fail('db error');
	
if (!($peer_row = $res->fetch())) {	
	isPeerIDBanned($peer_row['peer_id'], $torrent_row['torrent_id'], $data['passkey']);
	$res = $db->query_params('INSERT INTO peers (started, passkey, connectable, user_id, torrent_id, chosen_peer_id, ip, port, client) VALUES (now(), :passkey, :connectable, :user_id, :torrent_id, :chosen_peer_id, :ip, :port, :client)', array('passkey' => $data['passkey'], 'connectable' => $connectable, 'user_id' => $user_row['user_id'], 'torrent_id' => $torrent_row['torrent_id'], 'chosen_peer_id' => $data['peer_id'], 'ip' => $data['ip'], 'port' => $data['port'], 'client' => $client), 'peer_id') or fail('Cant insert peer.');
    $peer_row = array('peer_id' => $res);
    // BEGIN user upload/download stats
	$db->query_params('UPDATE users SET uploaded = uploaded + :uploaded, downloaded = downloaded + :downloaded WHERE user_id = :user_id', array('uploaded' => $data['uploaded'], 'downloaded' => $data['downloaded'], 'user_id' => $user_row['user_id']));
	// END user upload/download stats
	//$db->query_params('UPDATE torrents SET seeders = :seeder, leechers = :leecher + 1 WHERE torrent_id = :torrent_id', array('seeder' => $getseeders, 'leecher' => $getleechers, 'torrent_id' => $torrent_row['torrent_id']));
} else {
	
	isPeerIDBanned($peer_row['peer_id'], $torrent_row['torrent_id'], $data['passkey']);    
	//$db->query_params('UPDATE torrents SET seeders = seeders + :seeder, leechers = leechers + 1 WHERE torrent_id = :torrent_id', array('seeder' => $getseeders, 'torrent_id' => $torrent_row['torrent_id']));
	// BEGIN user upload/download stats
	$db->query_params('UPDATE users SET uploaded = uploaded + :uploaded, downloaded = downloaded + :downloaded WHERE user_id = :user_id', array('uploaded' => $data['uploaded'], 'downloaded' => $data['downloaded'], 'user_id' => $user_row['user_id']));
	// END user upload/download stats
	$db->query_params('UPDATE peers SET connectable = :connectable, to_go = :to_go, uploaded = :uploaded, downloaded = :downloaded, seeder = :seeder, client = :client, ip = :ip, port = :port, last_announce = CURRENT_TIMESTAMP WHERE peer_id = :peer_id', array('connectable' => $connectable, 'to_go' => $data['left'], 'uploaded' => $data['uploaded'], 'downloaded' => $data['downloaded'], 'seeder' => $seeder, 'client' => $client, 'ip' => $data['ip'], 'port' => $data['port'], 'peer_id' => $peer_row['peer_id'])) or fail('db error');
	
}

if (array_key_exists('left', $data)) {
	$db->query_params('UPDATE peers SET completed = :completed, seeder = :seeder WHERE peer_id = :peer_id', array('completed' => $db->encode_bool($data['left'] === 0), 'seeder' => $seeder, 'peer_id' => $peer_row['peer_id']));
}

if ($data['event'] === 'stopped') {
	$db->query_params('DELETE FROM peers WHERE peer_id = :peer_id', array('peer_id' => $peer_row['peer_id']));	
	/*
	if ($is_seeder){
		$db->query_params('UPDATE torrents SET seeders = seeders - 1 WHERE torrent_id = :torrent_id', array('torrent_id' => $torrent_row['torrent_id']));	
	}else{
		$db->query_params('UPDATE torrents SET leechers = leechers - 1 WHERE torrent_id = :torrent_id AND leechers > = 0', array('torrent_id' => $torrent_row['torrent_id'])); // bug fix: leechers > = 0
	}
	*/
}

// Completed - work
if ($data['event'] === 'completed') {
	$db->query_params('DELETE FROM peers WHERE peer_id = :peer_id', array('peer_id' => $peer_row['peer_id']));	
	$db->query_params('UPDATE torrents SET times_completed = times_completed + :completed WHERE torrent_id = :torrent_id', array('completed' => $db->encode_bool($data['left'] === 0), 'torrent_id' => $torrent_row['torrent_id'])); // Added Sep 9, 2020
	/*
	if ($is_seeder){
		$db->query_params('UPDATE torrents SET seeders = seeders + 1, times_completed = :completed WHERE torrent_id = :torrent_id', array('completed' => $db->encode_bool($data['left'] === 0), 'torrent_id' => $torrent_row['torrent_id']));	
	}else{
		$db->query_params('UPDATE torrents SET leechers = leechers + 1 WHERE torrent_id = :torrent_id AND leechers > = 0', array('torrent_id' => $torrent_row['torrent_id'])); // bug fix: leechers > = 0
	}
	*/
}

$res = $db->query_params('SELECT count(nullif(completed,false)) AS complete, count(nullif(completed,true)) AS incomplete FROM peers WHERE torrent_id = :torrent_id', array('torrent_id' => $torrent_row['torrent_id'])) or fail('db error');
$comp_res = $res->fetch() or fail('db error');

$output = array(
    'interval' => 30 * 60,
    'complete' => intval($comp_res['complete']),
    'incomplete' => intval($comp_res['incomplete']),
    'peers' => array(),
);

$res = $db->query_params('SELECT chosen_peer_id, ip, port FROM peers WHERE torrent_id = :torrent_id AND peer_id != :peer_id ORDER BY ' . $db->random() . ' LIMIT :limit', array('torrent_id' => $torrent_row['torrent_id'], 'peer_id' => $peer_row['peer_id'], 'limit' => $data['numwant'])) or fail('db error');
while ($row = $res->fetch()) {
    $peer = array(
        'ip' => $row['ip'],
        'port' => intval($row['port']),
    );
    if (!array_key_exists('no_peer_id', $data)) {
        $peer['peer_id'] = hex2bin($row['chosen_peer_id']);
    }
    $output['peers'] []= $peer;
}
if (array_key_exists('compact', $data)) {
    $peer_data = '';
    foreach ($output['peers'] as $peer) {
        $bs = ip2bytes($peer['ip']);
        if (is_null($bs)) continue;
        $peer_data .= $bs;
        $peer_data .= chr($peer['port'] >> 8);
        $peer_data .= chr($peer['port'] & 0xff);
    }

    if (empty($output['peers']) || !empty($peer_data)) {
        $output['peers'] = $peer_data;
    }
}

echo bencode($output);

