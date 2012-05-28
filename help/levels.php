<?php

if ($_REQUEST['lang'] == 'fr') {
    include('levels_fr.php');
} else { ?>
<html><head>
<title>Off-the-Record Messaging: Privacy Levels</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Off-the-Record Messaging</h1>
<h2>Privacy Levels</h2>
<p>A conversation can have one of four <b>privacy levels</b>:</p>
<dl>
<dt><img src="notprivate-button.png" alt="Not private" /></dt>
<dd>Alice and Bob are communicating with no cryptographic protection;
they are not using OTR at all.  Mallory, who is watching the network,
can read everything they are saying to each other.
</dd><br /><img src="notprivate-ab.png" />
<p></p>

<dt><img src="private-button.png" alt="Private" /></dt>
<dd>Alice and Bob are using OTR, and they have 
<a href="authenticate.php?lang=en">authenticated</a> each other.  They
are assured that they are actually talking to each other, and not to
an imposter.  They are also confident that no one watching the network
can read their messages.
</dd><br /><img src="private-ab.png" />
<p></p>
<dt><img src="unverified-button.png" alt="Unverified" />
<dd>Alice and Bob are using OTR, but they have not 
<a href="authenticate.php?lang=en">authenticated</a> each other, which
means they do not know for certain who they are talking to.  It is
<em>possible</em> that Mallory is impersonating one of them, or
intercepting their conversation and reading everything they say to each
other.
</dd><br /><img src="unverified-ab.png" />
<dt><img src="finished-button.png" alt="Finished" /></dt>
<dd>Alice <em>was</em> talking to Bob using OTR, but Bob has decided to
stop using it.  In this level, Alice is prevented from accidentally
sending a private message without protection, by preventing her from sending
any further messages to Bob at all.  She must explicitly either end her side
of the private conversation, or else start a new one.
</dd>
</dl>
</body></html>
<?php } ?>
