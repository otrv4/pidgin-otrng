	       Off-the-Record Messaging plugin for pidgin
			  v4.0.0, 4 Sep 2012

This is a pidgin plugin which implements Off-the-Record (OTR) Messaging.
It is known to work (at least) under the Linux and Windows versions of
pidgin (2.x).

OTR allows you to have private conversations over IM by providing:
 - Encryption
   - No one else can read your instant messages.
 - Authentication
   - You are assured the correspondent is who you think it is.
 - Deniability
   - The messages you send do _not_ have digital signatures that are
     checkable by a third party.  Anyone can forge messages after a
     conversation to make them look like they came from you.  However,
     _during_ a conversation, your correspondent is assured the messages
     he sees are authentic and unmodified.
 - Perfect forward secrecy
   - If you lose control of your private keys, no previous conversation
     is compromised.

For more information on Off-the-Record Messaging, see
http://otr.cypherpunks.ca/

USAGE

Run pidgin, and open the Plugins panel.  (If you had a copy of pidgin
running before you installed pidgin-otr, you will need to restart it.)
Find the Off-the-Record Messaging plugin, and enable it by selecting the
checkbox next to it.  That should be all you need to do.

CONFIGURATION

Click "Configure Plugin" to bring up the OTR UI.  The UI has two
"pages": "Config" and "Known fingerprints".

The "Config" page allows you generate private keys, and to set OTR
settings and options.

    Private keys are used to authenticate you to your buddies.  OTR will
    automatically generate private keys when needed, but you can also
    generate them manually if you wish by using the "Generate" button
    here.  Choose one of your accounts from the menu, click "Generate"
    and wait until it's finished.  You'll see a sequence of letters and
    number appear above the "Generate" button.  This is the
    "fingerprint" for that account; it is unique to that account.  If
    you have multiple IM accounts, you can generate private keys for
    each one separately.

    The OTR settings determine when private messaging is enabled.  The
    checkboxes on this page control the default settings; you can edit
    the per-buddy settings by right-clicking on your buddy in the buddy
    list, and choosing "OTR Settings" from the menu.

    The settings are:
    [X] Enable private messaging
      [X] Automatically initiate private messaging
        [ ] Require private messaging
    [ ] Don't log OTR conversations

    If the "enable private messaging" box is unchecked, private messages
    will be disabled completely (and the other two boxes will be greyed
    out, as they're irrelevant).

    If the first box is checked, but "automatically initiate private
    messaging" is unchecked, private messaging will be enabled, but only
    if either you or your buddy explicitly requests to start a private
    conversation (and the third box will be greyed out, as it's
    irrelevant).

    If the first two boxes are checked, but "require private messaging"
    is unchecked, OTR will attempt to detect whether your buddy can
    understand OTR private messages, and if so, automatically start a
    private conversation.

    If the first three boxes are checked, messages will not be sent to your
    buddy unless you are in a private conversation.

    If the fourth box is checked, OTR-protected conversations will not
    be logged, even if logging of instant messages is turned on in
    pidgin.

    The OTR UI Options control the appearance of OTR in your conversation
    window.  At present, the only option is:
    [X] Show OTR button in toolbar

    This option controls whether an extra button will appear in your
    toolbar.  This button will allow you to quickly see the OTR status
    of your conversation, to manually start or stop an OTR conversation,
    or to authenticate your buddy.  All of these abilities are already
    available in the OTR menu, but some people prefer a butter closer to
    where they type their messages.

The "Known fingerprints" page allows you to see the fingerprints of any
buddies you have previously communicated with privately.

    The "Status" will indicate the current OTR status of any
    conversation using each fingerprint.  The possibilities are
    "Private", which means you're having a private conversation,
    "Unverified", which means you have not yet verified your buddy's
    fingerprint, "Not private", which means you're just chatting in IM
    the usual (non-OTR) way, and "Finished", which means your buddy has
    selected "End private conversation"; at this point, you will be
    unable to send messages to him at all, until you either also choose
    "End private conversation" (in which case further messages will be
    sent unencrypted), or else choose "Refresh private conversation" (in
    which case further messages will be sent privately).

    The table also indicates whether or not you have verified this
    fingerprint by authenticating your buddy.

    By selecting one of your buddies from the list, you'll be able to do
    one or more of the following things by clicking the buttons below
    the list:
     - "Start private conversation": if the status is "Not private" or
       "Finished", this will attempt to start a private conversation.
     - "End private conversation": if the status is "Unverified",
       "Private", or "Finished", you can force an end to your private
       conversation by clicking this button.  There's not usually a good
       reason to do this, though.
     - "Verify fingerprint": this will open a window where you can
       verify the value of your buddies' fingerprint.  If you do not
       wish to work with fingerprints directly, you should instead
       authenticate used the OTR button from within a conversation.
     - "Forget fingerprint": this will remove your buddy's fingerprint
       from the list.  You'll have to re-authenticate him the next time
       you start a private conversation with him.  Note that you can't
       forget a fingerprint that's currently in use in a private
       conversation.

You can close the configuration panel (but make sure not to disable the
OTR plugin).

IM as normal with your buddies.  If you want to start a private
conversation with one of them, bring up the OTR menu (either from the
menubar or by clicking the OTR button, if you have enabled it).  From
the OTR menu, select "Start private conversation".

If your buddy does not have the OTR plugin, a private conversation will
(of course) not be started.  [But he or she will get some information
about OTR instead.]

If your buddy does have the OTR plugin (and it's enabled), a private
conversation will be initiated.

If both you and your buddy have OTR software, and your OTR settings set
to automatically initiate private messaging, your clients may recognize
each other and automatically start a private conversation.

The first time you have a private conversation with one of your buddies,
a message will appear in your conversation telling you to authenticate
them.  You may authenticate by selecting "Authenticate Buddy" on the
OTR menu.  This is described later on.

At this point, the label on the OTR button in the conversation window
will change to "OTR: Unverified".  This means that, although you are
sending encrypted messages, you have not yet authenticated your buddy,
and so it is not certain that the person who can decrypt these messages
is actually your buddy (it may be an attacker).  This situation will
remain until either you or your buddy choose "Authenticate Buddy" from
the OTR button menu (described next).

The OTR menu contains the following choices:

Start / Refresh private conversation

    Choosing this menu option will attempt to start (or refresh, if
    you're already in one) a private conversation with this buddy.

End private conversation

    If you wish to end the private conversation, and go back to
    communicating without privacy protection, you can select this
    option.  Note that if you have "Automatically initiate private
    messaging" set, it is likely that a new private conversation will
    automatically begin immediately.

Authenticate Buddy

    For more information on authentication, see
    http://otr-help.cypherpunks.ca/3.2.0/authenticate.php

    OTR provides three ways to authenticate your buddy:

    1) Question and answer
    2) Shared secret
    3) Manual fingerprint verification

    To start the authentication process, you need to first be
    communicating with your buddy in the "Unverified" or "Private"
    states.  [Although the "Private" state indicates that you have
    already successfully authenticated your buddy, and it is not
    necessary to do it again.]  Choose "Authenticate buddy" from the OTR
    menu.  The Authenticate Buddy dialog will pop up.  Use the combo box
    to select which of the three authentication methods you would like
    to use.

    Once you have authenticated your buddy, your OTR status will change
    to "Private".  OTR will also remember that you successfully
    authenticated, and during future private conversations with the same
    buddy, you will no longer get the warning message when you start
    chatting.  This will continue until your buddy switches to a
    computer or an IM account he or she hasn't used before, at which
    point OTR will not recognize him or her and you will be asked to
    authenticate again.

    Question and answer
    -------------------

    To authenticate using a question, pick a question whose answer is
    known only to you and your buddy.  Enter this question and this
    answer, then wait for your buddy to enter the answer too.  If the
    answers don't match, then you may be talking to an imposter.

    If your buddy answers correctly, then you have successfully
    authenticated him or her, and the OTR status of this conversation
    will change to "Private".

    Your buddy will probably also want to ask you a question as well in
    order for him or her to authenticate you back.

    Note that this method first appeared in pidgin-otr 3.2.0; if your
    buddy is using an older version, this will not work.

    Shared secret
    -------------

    To authenticate someone with the shared secret method, you and your
    buddy should decide on a secret word or phrase in advance.  This can
    be done however you like, but you shouldn't type the phrase directly
    into your conversation.

    Enter the shared secret into the field provided in the Authenticate
    Buddy dialog box.  Once you enter the secret and hit OK, your buddy
    will be asked to do exactly the same thing.  If you both enter the
    same text, then OTR will accept that you are really talking to your
    buddy.  Otherwise, OTR reports that authentication has failed.  This
    either means that your buddy made a mistake typing in the text, or
    it may mean that someone is intercepting your communication.

    Note that this method first appeared in pidgin-otr 3.1.0; if your
    buddy is using an older version, this will not work.

    Manual fingerprint verification
    -------------------------------

    If your buddy is using a version of pidgin-otr before 3.1.0, or a
    different OTR client that does not support the other authentication
    methods, you will need to use manual fingerprint verification.

    You will need some other authenticated communication channel (such
    as speaking to your buddy on the telephone, or sending gpg-signed
    messages).  You should tell each other your own fingerprints.  If
    the fingerprint your buddy tells you matches the one listed as his
    or her "purported fingerprint", pull down the selection that says "I
    have not" (verified that this is in fact the correct fingerprint),
    and change it to "I have".

    Once you do this, the OTR status will change to "Private".  Note
    that you only need to do this once per buddy (or once per
    fingerprint, if your buddy has more than one fingerprint).
    pidgin-otr will remember which fingerprints you have marked as
    verified.

What's this?

    This will open a web browser to get online help.



NOTES

Please send your bug reports, comments, suggestions, patches, etc. to us
at the contact address below.

This plugin only attempts to protect instant messages, not multi-party
chats, file transfers, etc.

MAILING LISTS

There are three mailing lists pertaining to Off-the-Record Messaging:

otr-announce:
    http://lists.cypherpunks.ca/mailman/listinfo/otr-announce/
    *** All users of OTR software should join this. ***  It is used to
    announce new versions of OTR software, and other important information.

otr-users:
    http://lists.cypherpunks.ca/mailman/listinfo/otr-users/
    Discussion of usage issues related to OTR Messaging software.

otr-dev:
    http://lists.cypherpunks.ca/mailman/listinfo/otr-dev/
    Discussion of OTR Messaging software development.

LICENSE

The Off-the-Record Messaging plugin for pidgin is covered by the following
(GPL) license:

    Off-the-Record Messaging plugin for pidgin
    Copyright (C) 2004-2012  Ian Goldberg, Rob Smits,
                             Chris Alexander, Willy Lew,
                             Lisa Du, Nikita Borisov
                             <otr@cypherpunks.ca>


    This program is free software; you can redistribute it and/or modify
    it under the terms of version 2 of the GNU General Public License as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    There is a copy of the GNU General Public License in the COPYING file
    packaged with this plugin; if you cannot find it, write to the Free
    Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301 USA

CONTACT

To report problems, comments, suggestions, patches, etc., you can email
the authors:

Ian Goldberg, Rob Smits, Chris Alexander, Willy Lew, Lisa Du, Nikita Borisov
<otr@cypherpunks.ca>

For more information on Off-the-Record Messaging, visit
http://otr.cypherpunks.ca/
