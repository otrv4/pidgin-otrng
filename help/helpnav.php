<?php $lang = isset($_REQUEST['lang']) ? htmlspecialchars($_REQUEST['lang']) : "en";?>

<div class="helpnav">
<ul>
<li><a href="authenticate.php?lang=<?php echo $lang;?>">Authentication</a></li>
<li><a href="fingerprint.php?lang=<?php echo $lang;?>">Fingerprints</a></li>
<li><a href="levels.php?lang=<?php echo $lang;?>">Privacy Levels</a></li>
<li><a href="sessions.php?lang=<?php echo $lang;?>">Multiple Sessions</a></li>
</ul>
</div>
