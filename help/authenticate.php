<?php

if ($_REQUEST['lang'] == 'fr') {
    include('authenticate_fr.php');
} else { ?>
<html><head>
<title>Off-the-Record Messaging: Authentication</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Off-the-Record Messaging</h1>
<h2>Authentication</h2>
<p>You've probably received email from people pretending to be banks, credit
agencies, even wealthy Nigerian expatriates.  People lie about who they
are all the time on the Internet.  <b>Authentication</b> is a way to make
sure that nobody can lie to you about who they are when they use OTR.
</p>
<h3>When to authenticate</h3>
<p>You should authenticate a buddy the very first time that you talk to
them using OTR.  If you don't, then you can't really be sure that
someone else isn't impersonating them or trying to listen in on your
conversation.  However, once you've authenticated your buddy, you
don't have to do it again.  OTR will automatically do the authentication
for all of your future conversations with that buddy.
</p>
<p>The only exceptions occur when your buddy switches between multiple
computers or multiple IM accounts.  In this case, you will need to
authenticate once for each computer and account.  Once you've done this,
your buddy can freely use any of the computers you've authenticated them
on, and OTR will recognize them automatically.  If your buddy uses
a new computer or account that OTR does not recognize, a message will pop up
in your conversation window telling you about it:
</p>
<br /><img src="conv-unauthenticated.png" />
<h3>How to authenticate</h3>
<p>OTR provides three ways to authenticate your buddy:</p>
<ol><li>Question and answer</li>
<li>Shared secret</li>
<li>Manual fingerprint verification</li></ol>

<p>To start the authentication process, you need to first be
communicating with your buddy in the "Unverified" or "Private"
states.  [Note that the "Private" state indicates that you have
already successfully authenticated your buddy, and it is not
necessary to do it again.]  Choose "Authenticate buddy" from the OTR
menu.</p>
<br /><img src="conv-menuauthenticate.png" />
<p>The Authenticate Buddy dialog will pop up.  Use the combo box
to select which of the three authentication methods you would like
to use.</p>

<h4>Question and answer</h4>
<img src="auth-qa.png" />
<p>To authenticate using a question, pick a question whose answer is
known only to you and your buddy.  Enter this question and this
answer, then wait for your buddy to enter the answer too.  If the
answers don't match, then either your buddy made a mistake typing in the
answer, or you may be talking to an imposter.</p>

<p>If your buddy answers correctly, then you have successfully
authenticated him or her, and the OTR status of this conversation
will change to "Private".</p>

<p>Your buddy will probably also want to ask you a question as well in
order for him or her to authenticate you back.</p>

<p>Note that this method first appeared in pidgin-otr 3.2.0; if your
buddy is using an older version, this will not work.</p>

<h4>Shared secret</h4>
<img src="auth-ss.png" />
<p>To authenticate someone with the shared secret method, you and your
buddy should decide on a secret word or phrase in advance.  This can
be done however you like, but you shouldn't type the phrase directly
into your conversation.</p>

<p>Enter the shared secret into the field provided in the Authenticate
Buddy dialog box.  Once you enter the secret and hit OK, your buddy
will be asked to do exactly the same thing.  If you both enter the
same text, then OTR will accept that you are really talking to your
buddy.  Otherwise, OTR reports that authentication has failed.  This
either means that your buddy made a mistake typing in the text, or
it may mean that someone is intercepting your communication.</p>

<p>Note that this method first appeared in pidgin-otr 3.1.0; if your
buddy is using an older version, this will not work.</p>

<h4>Manual fingerprint verification</h4>
<img src="auth-mf.png" />
<p>If your buddy is using a version of pidgin-otr before 3.1.0, or a
different OTR client that does not support the other authentication
methods, you will need to use manual fingerprint verification.</p>

<p>You will need some other authenticated communication channel (such
as speaking to your buddy on the telephone, or sending gpg-signed
messages).  You should tell each other your own fingerprints.  If
the fingerprint your buddy tells you matches the one listed as his
or her "purported fingerprint", pull down the selection that says "I
have not" (verified that this is in fact the correct fingerprint),
and change it to "I have".</p>

<p>Once you do this, the OTR status will change to "Private".  Note
that you only need to do this once per buddy (or once per
fingerprint, if your buddy has more than one fingerprint).
pidgin-otr will remember which fingerprints you have marked as
verified.</p>

<h3>What the results mean</h3>
<p>When you have entered your secret and hit OK, a progress bar pops up.  This
bar should fill up to 100% and then display one of the following messages:
</p>
<br /><img src="progress-success.png" />
<p>This means that authentication has been a complete success.
The OTR button will automatically change to "Private", showing that
conversations with this buddy are safe.
</p>
<br /><img src="progress-failed.png" />
<p>This means that although there were no errors, your buddy did not enter
the same text as you.  You should try again, making sure that you are clear
about what to type (for example, "the restaurant name <em>in lower case</em>").
If you repeatedly get this result, you should not trust that your buddy is who you think he or she is.
</p>
<br /><img src="progress-error.png" />
<p>This means that something has gone wrong and the process could not complete
normally.  This will happen if your buddy hits "cancel" or fails to receive
one of your messages.  In this case, you should simply try again.  If you try
several times and keep getting an error, you should not trust that your buddy is who you think he or she is.
</p>
<br /><img src="progress-success-maywant.png" />
<p>This means that you answered your buddy's authentication question successfully, so you have authenticated yourself to your buddy.  However, your buddy has not yet authenticated to you.  You may want to ask your buddy an authentication question by selecting "Authenticate buddy" from the OTR menu yourself.
</p>
</body></html>

<?php } ?>
