<?php header('Content-Type: text/html; charset=UTF-8');?>
<html><head>
<title>Messagerie Off-the-Record&nbsp;: Authentification</title>
<link rel="stylesheet" type="text/css" href="main.css" />
</head>
<body><h1>Messagerie Off-the-Record</h1>
<h2>Authentification</h2>
<p>Vous avez probablement déjà reçu des emails de gens prétendant être
une banque, une agence de crédit, ou un expatrié nigérien. Sur
internet, les gens mentent tout le temps au sujet de leur
identité. L'<b>authentification</b> est une manière de s'assurer que
votre interlocuteur est bien celui qu'il prétend être lorsqu'il
utilise OTR.
</p>
<h3>Quand s'authentifier&nbsp;?</h3>
<p>Vous devriez authentifier chaque contact la première fois que vous
lui parlez en utilisant OTR. Si vous ne le faites pas, il y a deux
risques&nbsp;: un imposteur peut se faire passer pour la personne à
qui vous pensez parler, ou bien quelqu'un peut écouter votre
conversation. Lorsque vous aurez authentifié votre interlocuteur, vous
n'aurez pas à le refaire : OTR assurera automatiquement
l'authentification lors de toutes vos conversations suivantes avec ce
contact.
</p>
<p>Les seules exceptions se produisent lorsque votre contact change
d'ordinateur ou de compte de messagerie instantanée. Dans ce cas, vous
devrez l'authentifier une nouvelle fois pour chaque ordinateur et
chaque compte. Lorsque vous l'aurez fait, votre contact pourra passer
d'un ordinateur à l'autre et OTR le reconnaîtra automatiquement. Si
votre contact utilise un nouvel ordinateur ou un compte qu'OTR ne
connaît pas encore, un message surgira dans votre fenêtre de dialogue
vous disant&nbsp;:
</p>
<br /><img src="conv-unauthenticated.png" />
<h3>Comment authentifier&nbsp;?</h3>
<p>OTR fournit trois moyens d'authentifier vos contacts&nbsp;:</p>
<ol><li>Question-réponse</li>
<li>Secret partagé</li>
<li>Vérification manuelle de l'empreinte</li></ol>

<p>Pour commencer l'authentification, vous devez lancer un dialogue
"Non-privé" ou "Privé".  [Notez que le statut "Privé" indique que vous
avez déjà authentifié votre contact, et qu'il est superflu de le
refaire.] Choisissez "Authentifier contact" dans le menu OTR.</p>
<br /><img src="conv-menuauthenticate.png" />
<p>Une fenêtre "Authentifier contact" surgira alors. Utilisez le menu
déroulant pour choisir lequel des trois moyens d'authentification vous
utiliserez.</p>

<h4>Question-réponse</h4>
<img src="auth-qa.png" />
<p>Pour authentifier votre interlocuteur en utilisant une question,
choisissez une question dont seuls lui et vous connaissez la
réponse. Écrivez cette question et sa réponse, puis attendez que votre
contact donne la réponse adéquate. Si vos réponses ne sont pas
identiques, alors soit c'est une question d'orthographe, soit vous
parlez à un imposteur.</p>

<p>Si votre contact répond correctement, alors vous l'avez authentifié
avec succès, et le statut OTR de la conversation deviendra
"Privé".</p>

<p>Votre contact voudra probablement, lui aussi, vous poser une
question afin de vous authentifier à son tour.</p>

<p>Notez que cette méthode est apparue dans pidgin-otr 3.2.0&nbsp;; si
votre contact utilise une version plus ancienne, cela ne fonctionnera
pas.

<h4>Secret partagé</h4>
<img src="auth-ss.png" />
<p>Pour authentifier quelqu'un avec la méthode du secret partagé, vous
et votre contact devez décider à l'avance d'un mot ou d'une phrase de
passe. Cela peut se faire de la façon qui vous convient, mais vous ne
devriez pas écrire cette phrase dans votre fenêtre de dialogue.</p>

<p>Écrivez le secret dans la boîte prévue à cet effet de la fenêtre
"Authentifier contact". Lorsque vous validerez, il sera demandé à
votre contact d'écrire le secret à son tour. Si vous écrivez tous deux
le même texte, alors OTR considèrera que vous parlez bien à votre
contact. Autrement, OTR vous dira que l'authentification a
échoué. Cela signifiera que l'un de vous a fait une faute
d'orthographe, ou que quelqu'un intercepte votre communication.</p>

<p>Notez que cette méthode est apparue dans pidgin-otr 3.1.0&nbsp;; si
votre contact utilise une version plus ancienne, cela ne fonctionnera
pas.

<h4>Vérification manuelle d'empreinte</h4>
<img src="auth-mf.png" />
<p>Si votre contact utilise une version de pidgin-otr antérieure à la
3.1.0, ou un client OTR qui ne propose pas les autres méthodes
d'authentification, vous devrez utiliser la vérification manuelle
d'empreinte.</p>

<p>Vous devrez disposer d'un autre moyen de communication authentifié
(comme parler à votre contact au téléphone, ou échanger des emails
signés avec GnuPG). Vous devrez alors dicter (ou envoyer) vos empreintes
respectives.  Si l'empreinte que vous dicte / envoie votre contact est
identique à celle affichée comme "empreinte prétendue pour votre
contact", sélectionnez "Je n'ai pas" (vérifié que c'est en effet la
bonne empreinte pour mon contact) et changez-le pour "J'ai", puis
cliquez "Authentifier".</p>

<p>Lorsque c'est fait, le statut OTR de la conversation deviendra
"Privé". Notez qu'il vous suffit de le faire une fois pour chaque
contact (ou une fois pour chaque empreinte, si votre contact a
plusieurs empreintes). pidgin-otr se rappellera quelles empreintes
vous avez marquées comme vérifiées.</p>

<h3>Que signifie le résultat&nbsp;?</h3>
<p>Lorsque vous écrivez votre secret et cliquez sur
"Authentification", une barre de progression surgit. Une fois qu'elle
est remplie à 100%, elle affichera l'un des messages suivants&nbsp;:
</p>
<br /><img src="progress-success.png" />
<p>Cela signifie que l'authentification a réussi.  Le bouton OTR
devient automatiquement "Privé", signe que vos conversations avec ce
contact sont bien confidentielles.
</p>
<br /><img src="progress-failed.png" />
<p>Cela signifie que, bien qu'il n'y ait pas eu d'erreur technique,
votre contact n'a pas écrit le même texte que vous. Vous devez
réessayer, en vous assurant que vous êtes bien d'accord sur le secret
à écrire (par exemple "le nom du restaurant <em>en
minuscules</em>"). Si vous recevez encore le même résultat, il n'y a
aucune certitude que votre interlocuteur soit bien celui qu'il prétend
être.
</p>
<br /><img src="progress-error.png" />
<p>Cela signifie que quelque chose n'a pas fonctionné et que le
processus ne s'est pas déroulé normalement. Cela se produira si votre
contact clique sur "Annuler" ou s'il ne reçoit pas l'un de vos
messages. Dans ce cas, il vous suffit de réessayer. Après plusieurs
tentatives, si cette erreur apparaît encore, il est possible que votre
interlocuteur ne soit pas celui qu'il prétend être.
</p>
<br /><img src="progress-success-maywant.png" />
<p>Cela signifie que vous avez correctement répondu à la question de
votre contact, et que vous êtes donc authentifié auprès de lui.  Il
faut encore qu'il s'authentifie auprès de vous. Pour cela, vous pouvez
poser une question d'authentification en sélectionnant
"Authentification Contact" dans le menu OTR.
</p>
</body></html>

