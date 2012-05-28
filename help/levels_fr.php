<?php header('Content-Type: text/html; charset=UTF-8');?>
<html><head>
<title>Messagerie Off-the-Record&nbsp;: Niveaux de confidentialité</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Messagerie Off-the-Record</h1>
<h2>Niveaux de confidentialité</h2>
<p>Une conversation peut avoir quatre <b>niveaux de confidentialité</b> différents&nbsp;:</p>
<dl>
<dt><img src="notprivate-button.png" alt="Non-privé" /></dt>
<dd>Alice et Bob communiquent sans protection cryptographique&nbsp;; ils
n'utilisent pas du tout OTR. Mallory, qui surveille le réseau, peut
lire tout ce qu'ils se racontent.
</dd><br /><img src="notprivate-ab.png" />
<p></p>

<dt><img src="private-button.png" alt="Privé" /></dt>
<dd>Alice and Bob utilisent OTR, et ils se sont 
<a href="authenticate.php?lang=fr">authentifiés</a>. Ils sont sûrs de
se parler l'un à l'autre, et pas à un imposteur. Ils ont aussi la
certitude qu'il ne suffit pas de surveiller le réseau pour pouvoir
lire leurs échanges.
</dd><br /><img src="private-ab.png" />
<p></p>
<dt><img src="unverified-button.png" alt="Non-vérifié" />
<dd>Alice and Bob utilisent OTR, mais ils ne se sont pas 
<a href="authenticate.php?lang=fr">authentifiés</a>, ce qui signifie
qu'ils ne sont pas certains de l'identité de leur interlocuteur. Il
est <em>possible</em> que Mallory se fasse passer pour l'un d'eux, ou
qu'il intercepte leurs échanges et lise à leur insu tout ce qu'ils se
disent.
</dd><br /><img src="unverified-ab.png" />
<dt><img src="finished-button.png" alt="Fini" /></dt>
<dd>Alice <em>parlait</em> à Bob en utilisant OTR, mais Bob a décidé
d'arrêter de l'utiliser (il est passé en "Non-privé"). Ce niveau de
confidentialité assure à Alice qu'elle n'enverra pas accidentellement
un message privé sans protection : ses messages ne seront plus
transmis du tout, à moins qu'elle ne choisisse, elle aussi, d'arrêter
la discussion privée ou d'en commencer une nouvelle.
</dd>
</dl>
</body></html>

