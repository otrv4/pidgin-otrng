<html><head>
<title>Off-the-Record Messaging: Multiple Sessions</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Off-the-Record Messaging</h1>
<?php include('helpnav.php'); ?>
<h2>Multiple Sessions</h2>
<p>With versions of OTR earlier than 4.0.0, if you tried to start a private
conversation with a buddy who is logged into the same account at multiple
locations, both you and your buddy would receive OTR errors. Worse, in some
cases this would result in continuous attempts to establish a private
conversation. OTR version 4.0.0 has introduced a way of detecting and
handling buddies who are logged into the same account at multiple locations.</p>

<p>In this document we describe this situation as a buddy who has multiple
sessions. Note that in more technical documentation we use the terminology
of multiple instances to refer to the same thing.</p>

<p>Note that both you and your buddy must be running OTR 4.0.0 or
later for you to establish multiple private conversations.</p>

<h3>Establishing a Private Conversation with Multiple Sessions</h3>
<p>You can establish private conversations with multiple sessions of a
particular buddy in two scenarios. Alice 1 and Bob 1 can be in a private
conversation, and then Bob 2 can come online and also establish a private
conversation with Alice 1 (or similarly Alice can refresh the conversation
after Bob 2 comes online). The other way is when Bob 1 and Bob 2 are already
logged in. When Alice 1 initiates a private conversation with Bob, separate
private conversations can be established with both Bob 1 and Bob 2.</p>

<p>On some instant messaging networks, Alices messages will only be relayed to
the most recent of Bob's sessions. Because of this, if Bob 1 and Bob 2 are
already logged in and Alice 1 initiates a private conversation, the session
might only be established with one of Bob's sessions.
</p>

<p>When you have established a private conversations with multple sessions
you will get a notice like the following:</p>

<br /><img src="session-notification.png" />

<h3>Choosing Between Sessions</h3>

<p>When you have established a private conversations with multple sessions a
different OTR menu will appear for that buddy.</p>

<br /><img src="session-menu.png" /><br/>

<p>The OTR menu for a buddy with multiple sessions has an icon that corresponds
to the <a href="buttonhelp.php">privacy level</a> of the selected session.
Outgoing messages will always go to the selected session. You can select a
session explicitly by choosing "Select" in the session's sub-menu, or you can
select the most secure or most recent session.</p>

<p>Choosing the most recent session will select the session that has most
recently sent you a message. By default, OTR selects the most secure session.
This choses the session that has the best <a href="buttonhelp.php">privacy
level</a>. In the event of a tie, it will select the most recent session, among
those that are tied. Regardless of how the session is chosen, as shown above the
selected session in the OTR menu is presented in a way that is emphasized.</p>

<p>As noted above, some instant messaging networks may not send all messages to
all sessions when someone is logged into the same account at multiple locations.
When you select a session that is not the one that has sent you a message most
recently, OTR will warn you, as shown below. OTR cannot guarantee, even if
you select the most recent session, that your message will be delivered to that
session by the instant messaging network.</p>

<br /><img src="session-not_most_recent.png" /><br/>

<p>If you have selected a particular session for your buddy, and the instant
messaging network has delivered your network to a different session, your
buddy will get a message like the one shown below. If you receive this message
and you are logged in with multiple sessions, you may want to tell your buddy
to select a different session for you.</p>

<br /><img src="session-for_another.png" /><br/>


</body></html>


