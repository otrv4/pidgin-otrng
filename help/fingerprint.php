<html><head>
<title>Off-the-Record Messaging: Fingerprints</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Off-the-Record Messaging</h1>
<h2>Fingerprints</h2>
<p>You've probably received email from people pretending to be banks, credit
agencies, even wealthy Nigerian expatriates.  People lie about who they
are all the time on the Internet.  To make sure that nobody can lie about
who they are when they use OTR, you can use <b>authentication</b>.  Starting
in version 3.1, OTR comes with a
<a href="authenticate.php?lang=en">simple way</a> to authenticate your
buddies.
</p>
<p>However, another common way to authenicate someone is through the use
of <b>fingerprints</b>.  Roughly speaking, a fingerprint is a long string
of 40 letters and numbers that let you identify an OTR user.  A typical
fingerprint looks something like this:
</p>
<p align="center">2674D6A0 0B1421B1 BFC42AEC C56F3719 672437D8</p>
<p>If you would prefer to use fingerprints to authenticate your buddies, and
you are using OTR version 3.1, select <b>"Authenticate Connection"</b> from
the OTR button, and then select <b>"Advanced"</b> from the regular
authentication window.  If you are using an older version of OTR, simply
select <b>"Verify Fingerprint"</b> from the OTR button.  You should see a
screen that looks like this:
</p>
<br /><img src="fingerprint-dialog.png" />
<p>Now you can see what your fingerprint is, as well as the fingerprint of
the person you are talking to.  But you still don't know if the fingerprint
really belongs to your friend or to an imposter.  To find out, you need a way
to check the fingerprint.  A simple way to do this is to phone your friend
and ask them to read you their fingerprint off of their screen, so that you
can check it against what you see.  If the values are the same, then you know
that you are not talking to an imposter.
</p>
<p>Regardless of whether you use fingerprints or the regular authentication
method, you do not have to follow the above steps during every conversation.
In many cases, you only need to authenticate each buddy once.  A detailed
description of when to authenticate may be found
<a href="authenticate.php?lang=en">here.</a>
</p> 
</body></html>

