/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2005  Nikita Borisov and Ian Goldberg
 *                           <otr@cypherpunks.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* system headers */
#include <stdio.h>
#include <stdlib.h>
#include <gtk/gtk.h>

/* gcrypt headers */
#include <gcrypt.h>

/* purple headers */
#include "version.h"
#include "pidginstock.h"
#include "plugin.h"
#include "notify.h"
#include "gtkconv.h"
#include "gtkutils.h"
#include "gtkimhtml.h"
#include "util.h"

/* libotr headers */
#include <libotr/dh.h>
#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

/* purple-otr headers */
#include "otr-plugin.h"
#include "dialogs.h"
#include "ui.h"

/* The OTR icons */

static const char * not_private_xpm[] = {
"20 20 100 2",
"  	c None",
". 	c #555555",
"+ 	c #5A5A5A",
"@ 	c #404040",
"# 	c #515151",
"$ 	c #919191",
"% 	c #9C9C9C",
"& 	c #949494",
"* 	c #848484",
"= 	c #646464",
"- 	c #161616",
"; 	c #959595",
"> 	c #B7B7B7",
", 	c #C2C2C2",
"' 	c #AFAFAF",
") 	c #8F8F8F",
"! 	c #7B7B7B",
"~ 	c #4F4F4F",
"{ 	c #5C5C5C",
"] 	c #A8A8A8",
"^ 	c #CECECE",
"/ 	c #D4D4D4",
"( 	c #B9B9B9",
"_ 	c #7A7A7A",
": 	c #686868",
"< 	c #101010",
"[ 	c #636363",
"} 	c #A3A3A3",
"| 	c #C4C4C4",
"1 	c #888888",
"2 	c #757575",
"3 	c #6B6B6B",
"4 	c #141414",
"5 	c #9E9E9E",
"6 	c #9D9D9D",
"7 	c #8C8C8C",
"8 	c #6D6D6D",
"9 	c #0C0C0C",
"0 	c #777777",
"a 	c #808080",
"b 	c #7E7E7E",
"c 	c #767676",
"d 	c #6C6C6C",
"e 	c #373737",
"f 	c #000000",
"g 	c #313131",
"h 	c #696969",
"i 	c #606060",
"j 	c #3D3D3D",
"k 	c #707070",
"l 	c #676767",
"m 	c #626262",
"n 	c #0E0E0E",
"o 	c #020202",
"p 	c #DADADA",
"q 	c #B2B2B2",
"r 	c #969696",
"s 	c #898989",
"t 	c #5E5E5E",
"u 	c #5B5B5B",
"v 	c #727272",
"w 	c #303030",
"x 	c #CFCFCF",
"y 	c #A2A2A2",
"z 	c #828282",
"A 	c #7C7C7C",
"B 	c #797979",
"C 	c #CBCBCB",
"D 	c #9F9F9F",
"E 	c #747474",
"F 	c #6E6E6E",
"G 	c #9A9A9A",
"H 	c #868686",
"I 	c #272727",
"J 	c #BFBFBF",
"K 	c #909090",
"L 	c #818181",
"M 	c #7D7D7D",
"N 	c #151515",
"O 	c #878787",
"P 	c #717171",
"Q 	c #1A1A1A",
"R 	c #8B8B8B",
"S 	c #656565",
"T 	c #292929",
"U 	c #4D4D4D",
"V 	c #1D1D1D",
"W 	c #616161",
"X 	c #3A3A3A",
"Y 	c #525252",
"Z 	c #464646",
"` 	c #080808",
" .	c #565656",
"..	c #2E2E2E",
"+.	c #262626",
"@.	c #2F2F2F",
"#.	c #535353",
"$.	c #4B4B4B",
"%.	c #111111",
"&.	c #2C2C2C",
"      . + @                             ",
"  # $ % & * = -             . + @       ",
"  ; > , ' ) ! ~         # $ % & * = -   ",
"{ ] ^ / ( $ _ : <       ; > , ' ) ! ~   ",
"[ } , | ] 1 2 3 4     { ] ^ / ( $ _ : < ",
"# ) 5 6 7 _ 8 { 9     [ } , | ] 1 2 3 4 ",
"  0 a b c d = e f     # ) 5 6 7 _ 8 { 9 ",
"  g h d h i j . + @     0 a b c d = e f ",
"  & k l m # $ % & * = - g h d h i j n o ",
"  p q r s ; > , ' ) ! ~ & k l m t u v w ",
"  x y 1 { ] ^ / ( $ _ : < q r s z A B m ",
"  C D 1 [ } , | ] 1 2 3 4 y 1 b _ E F u ",
"  | G H # ) 5 6 7 _ 8 { 9 D 1 b _ 2 8 I ",
"  J K L _ 0 a b c d = e f G H M B E 3 N ",
"  } O _ 2 g h d h i j n o K L _ c P : Q ",
"  R M v 3 & k l m t u v w O _ 2 P d S T ",
"  3 c h U p q r s z A B m V v 3 : l W X ",
"  Y P Z ` x y 1 b _ E F u  ...U +.@.#.$.",
"    i <   C D 1 b _ 2 8 I %.@.&.    n Z ",
"          | G H M B E 3 N i <           "};

static const char * unverified_xpm[] = {
"20 20 103 2",
"  	c None",
". 	c #555555",
"+ 	c #5A5A5A",
"@ 	c #404040",
"# 	c #000000",
"$ 	c #515151",
"% 	c #919191",
"& 	c #9C9C9C",
"* 	c #949494",
"= 	c #848484",
"- 	c #646464",
"; 	c #161616",
"> 	c #FFFF00",
", 	c #959595",
"' 	c #B7B7B7",
") 	c #C2C2C2",
"! 	c #AFAFAF",
"~ 	c #8F8F8F",
"{ 	c #7B7B7B",
"] 	c #4F4F4F",
"^ 	c #5C5C5C",
"/ 	c #A8A8A8",
"( 	c #CECECE",
"_ 	c #D4D4D4",
": 	c #B9B9B9",
"< 	c #7A7A7A",
"[ 	c #686868",
"} 	c #101010",
"| 	c #636363",
"1 	c #A3A3A3",
"2 	c #C4C4C4",
"3 	c #888888",
"4 	c #757575",
"5 	c #6B6B6B",
"6 	c #141414",
"7 	c #9E9E9E",
"8 	c #9D9D9D",
"9 	c #8C8C8C",
"0 	c #6D6D6D",
"a 	c #0C0C0C",
"b 	c #777777",
"c 	c #808080",
"d 	c #7E7E7E",
"e 	c #767676",
"f 	c #6C6C6C",
"g 	c #373737",
"h 	c #313131",
"i 	c #696969",
"j 	c #606060",
"k 	c #3D3D3D",
"l 	c #0E0E0E",
"m 	c #020202",
"n 	c #707070",
"o 	c #676767",
"p 	c #626262",
"q 	c #5E5E5E",
"r 	c #5B5B5B",
"s 	c #727272",
"t 	c #303030",
"u 	c #DADADA",
"v 	c #B2B2B2",
"w 	c #969696",
"x 	c #898989",
"y 	c #828282",
"z 	c #7C7C7C",
"A 	c #797979",
"B 	c #1D1D1D",
"C 	c #CFCFCF",
"D 	c #A2A2A2",
"E 	c #747474",
"F 	c #6E6E6E",
"G 	c #565656",
"H 	c #2E2E2E",
"I 	c #CBCBCB",
"J 	c #9F9F9F",
"K 	c #272727",
"L 	c #111111",
"M 	c #2F2F2F",
"N 	c #2C2C2C",
"O 	c #9A9A9A",
"P 	c #868686",
"Q 	c #7D7D7D",
"R 	c #151515",
"S 	c #BFBFBF",
"T 	c #909090",
"U 	c #818181",
"V 	c #717171",
"W 	c #1A1A1A",
"X 	c #878787",
"Y 	c #656565",
"Z 	c #292929",
"` 	c #8B8B8B",
" .	c #616161",
"..	c #3A3A3A",
"+.	c #4D4D4D",
"@.	c #262626",
"#.	c #535353",
"$.	c #4B4B4B",
"%.	c #525252",
"&.	c #464646",
"*.	c #080808",
"=.	c #121212",
"-.	c #242424",
"      . + @               # # # # #     ",
"  $ % & * = - ;         # > > > > > #   ",
"  , ' ) ! ~ { ]       # > > > # > > > # ",
"^ / ( _ : % < [ }     # > > #   # > > # ",
"| 1 ) 2 / 3 4 5 6     # > > #   # > > # ",
"$ ~ 7 8 9 < 0 ^ a     # > > #   # > > # ",
"  b c d e f - g #       # #     # > > # ",
"  h i f i j k l m             # > > > # ",
"  * n o p q r s t             # > > #   ",
"  u v w x y z A p B         # > > #     ",
"  C D 3 d < E F r G H       # > #       ",
"  I J 3 d < 4 0 K L M N     # > #       ",
"  2 O P Q A E 5 R             #         ",
"  S T U < e V [ W           # # #       ",
"  1 X < 4 V f Y Z         # > > > #     ",
"  ` Q s 5 [ o  ...        # > > > #     ",
"  5 e i +.@.M #.$.m       # > > > #     ",
"  %.V &.*.    l &.=.        # # #       ",
"    j }           -.                    ",
"                                        "};

static const char * private_xpm[] = {
"20 20 148 2",
"  	c None",
". 	c #978214",
"+ 	c #A58A10",
"@ 	c #77620A",
"# 	c #85781D",
"$ 	c #EBD437",
"% 	c #F4DE44",
"& 	c #F3D936",
"* 	c #EFC819",
"= 	c #C19207",
"- 	c #2C1E01",
"; 	c #EAD641",
"> 	c #F6E978",
", 	c #F7EB8D",
"' 	c #F5E569",
") 	c #F2D42C",
"! 	c #EBB50C",
"~ 	c #9C6302",
"{ 	c #99891F",
"] 	c #F5E45C",
"^ 	c #F8EFA4",
"/ 	c #F8F0B0",
"( 	c #F6E97D",
"_ 	c #F1D531",
": 	c #E9B20C",
"< 	c #CE7C02",
"[ 	c #201000",
"} 	c #AB961B",
"| 	c #F4E252",
"1 	c #F6EB8F",
"2 	c #F6EC93",
"3 	c #F4E25C",
"4 	c #EECB22",
"5 	c #E4A407",
"6 	c #D67401",
"7 	c #291400",
"8 	c #8F7A13",
"9 	c #F0D32E",
"0 	c #F2DC4B",
"a 	c #F2DB49",
"b 	c #EECE2B",
"c 	c #E6B10F",
"d 	c #D88503",
"e 	c #B95800",
"f 	c #190A00",
"g 	c #D9AE15",
"h 	c #E7BC1A",
"i 	c #E6B817",
"j 	c #E0A60D",
"k 	c #D58404",
"l 	c #C76301",
"m 	c #6E2E00",
"n 	c #010000",
"o 	c #58440B",
"p 	c #C68E0C",
"q 	c #D28A07",
"r 	c #CE7904",
"s 	c #BE5F02",
"t 	c #793601",
"u 	c #1A0F02",
"v 	c #040300",
"w 	c #A9A480",
"x 	c #8A8156",
"y 	c #9C8032",
"z 	c #A27A23",
"A 	c #9D7E1F",
"B 	c #9C801A",
"C 	c #C39D21",
"D 	c #5B3B05",
"E 	c #F5EEC0",
"F 	c #F0E074",
"G 	c #EAD243",
"H 	c #E7C72C",
"I 	c #E5BE20",
"J 	c #E1B218",
"K 	c #DDA615",
"L 	c #C27003",
"M 	c #3B1C00",
"N 	c #F5ECA9",
"O 	c #F1DE53",
"P 	c #ECCD25",
"Q 	c #E9C013",
"R 	c #E8B50C",
"S 	c #E2A307",
"T 	c #D98B03",
"U 	c #B66501",
"V 	c #AC5201",
"W 	c #5D2B00",
"X 	c #F6ECA1",
"Y 	c #F3DF4B",
"Z 	c #F0CF21",
"` 	c #EDC30F",
" .	c #EBB709",
"..	c #E5A405",
"+.	c #D88603",
"@.	c #4E2600",
"#.	c #231000",
"$.	c #5F2900",
"%.	c #582300",
"&.	c #F6EA93",
"*.	c #F4DD40",
"=.	c #F1CF1B",
"-.	c #EEC10C",
";.	c #EBB307",
">.	c #E49D04",
",.	c #D47A02",
"'.	c #2B1500",
").	c #F6E889",
"!.	c #F2D72F",
"~.	c #EFC614",
"{.	c #ECB508",
"].	c #E8A604",
"^.	c #E09002",
"/.	c #CF6E01",
"(.	c #351800",
"_.	c #EEDB59",
":.	c #F0CB1E",
"<.	c #EAB40B",
"[.	c #E5A205",
"}.	c #D87B01",
"|.	c #C96101",
"1.	c #532100",
"2.	c #DCC33B",
"3.	c #EAB811",
"4.	c #E09804",
"5.	c #D57D02",
"6.	c #CD6601",
"7.	c #C35600",
"8.	c #742D00",
"9.	c #BD9D19",
"0.	c #E3A109",
"a.	c #D17402",
"b.	c #9A4801",
"c.	c #4C2400",
"d.	c #5E2900",
"e.	c #A64300",
"f.	c #963500",
"g.	c #050200",
"h.	c #957610",
"i.	c #DC9107",
"j.	c #8B4101",
"k.	c #100600",
"l.	c #1C0A00",
"m.	c #8D3000",
"n.	c #240B00",
"o.	c #BB7B06",
"p.	c #210E00",
"q.	c #491800",
"            . + @                       ",
"        # $ % & * = -                   ",
"        ; > , ' ) ! ~                   ",
"      { ] ^ / ( _ : < [                 ",
"      } | 1 2 3 4 5 6 7                 ",
"      8 9 0 a b c d e f                 ",
"        g h i j k l m n                 ",
"        o p q r s t u v                 ",
"        w x y z A B C D                 ",
"        E F G H I J K L M               ",
"        N O P Q R S T U V W             ",
"        X Y Z `  ...+.@.#.$.%.          ",
"        &.*.=.-.;.>.,.'.                ",
"        ).!.~.{.].^./.(.                ",
"        _.:.<.[.^.}.|.1.                ",
"        2.3.4.5./.6.7.8.                ",
"        9.0.a.b.c.d.e.f.g.              ",
"        h.i.j.k.    l.m.n.              ",
"          o.p.          q.              ",
"                                        "};

static const char * finished_xpm[] = {
"20 20 101 2",
"  	c None",
". 	c #555555",
"+ 	c #FF0000",
"@ 	c #F31111",
"# 	c #C94949",
"$ 	c #C14242",
"% 	c #B13232",
"& 	c #8A0A0A",
"* 	c #FE0000",
"= 	c #DC5656",
"- 	c #C2BFBF",
"; 	c #AFAFAF",
"> 	c #8F8F8F",
", 	c #7B7B7B",
"' 	c #4F4F4F",
") 	c #C66D6D",
"! 	c #CECECE",
"~ 	c #D4D4D4",
"{ 	c #B9B9B9",
"] 	c #919191",
"^ 	c #7A7A7A",
"/ 	c #686868",
"( 	c #101010",
"_ 	c #9E3D3D",
": 	c #A3A3A3",
"< 	c #C2C2C2",
"[ 	c #C4C4C4",
"} 	c #A8A8A8",
"| 	c #888888",
"1 	c #757575",
"2 	c #6B6B6B",
"3 	c #141414",
"4 	c #515151",
"5 	c #9E9E9E",
"6 	c #9D9D9D",
"7 	c #8C8C8C",
"8 	c #6D6D6D",
"9 	c #5C5C5C",
"0 	c #0C0C0C",
"a 	c #777777",
"b 	c #808080",
"c 	c #7E7E7E",
"d 	c #767676",
"e 	c #6C6C6C",
"f 	c #646464",
"g 	c #373737",
"h 	c #000000",
"i 	c #313131",
"j 	c #696969",
"k 	c #606060",
"l 	c #3D3D3D",
"m 	c #0E0E0E",
"n 	c #949494",
"o 	c #707070",
"p 	c #676767",
"q 	c #626262",
"r 	c #5E5E5E",
"s 	c #5B5B5B",
"t 	c #DADADA",
"u 	c #B2B2B2",
"v 	c #969696",
"w 	c #898989",
"x 	c #828282",
"y 	c #1D1D1D",
"z 	c #CFCFCF",
"A 	c #A2A2A2",
"B 	c #6E6E6E",
"C 	c #565656",
"D 	c #2E2E2E",
"E 	c #CBCBCB",
"F 	c #9F9F9F",
"G 	c #272727",
"H 	c #111111",
"I 	c #2F2F2F",
"J 	c #2C2C2C",
"K 	c #9A9A9A",
"L 	c #797979",
"M 	c #747474",
"N 	c #151515",
"O 	c #BFBFBF",
"P 	c #717171",
"Q 	c #1A1A1A",
"R 	c #656565",
"S 	c #292929",
"T 	c #7D7D7D",
"U 	c #727272",
"V 	c #616161",
"W 	c #3A3A3A",
"X 	c #9B4848",
"Y 	c #4D4D4D",
"Z 	c #262626",
"` 	c #535353",
" .	c #4B4B4B",
"..	c #020202",
"+.	c #C13030",
"@.	c #4F4242",
"#.	c #080808",
"$.	c #464646",
"%.	c #121212",
"&.	c #FC0000",
"*.	c #DE0505",
"            . + + + + +                 ",
"        + + @ # $ % & + + + +           ",
"      + * = - ; > , '       + +         ",
"    + * ) ! ~ { ] ^ / (       + +       ",
"    + _ : < [ } | 1 2 3     + + +       ",
"  + + 4 > 5 6 7 ^ 8 9 0   + +   + +     ",
"  +     a b c d e f g h + +       +     ",
"+ +     i j e j k l m + +         + +   ",
"+ +     n o p q r s + +           + +   ",
"+       t u v w x + + q y           +   ",
"+       z A | c + + B s C D       + +   ",
"+ +     E F | + + 1 8 G H I J     + +   ",
"+ +     [ K + + L M 2 N           + +   ",
"  +     O + + ^ d P / Q           +     ",
"  + +   + + ^ 1 P e R S         + +     ",
"    + + + T U 2 / p V W         +       ",
"    + + X d j Y Z I `  ...    + +       ",
"      + + +.@.#.    m $.%.  + +         ",
"        + + &.+       + *.+ +           ",
"              + + + + +                 "};

static GtkWidget *otr_icon(GtkWidget *image, TrustLevel level)
{
    GdkPixbuf *pixbuf = NULL;
    const char **data = NULL;

    switch(level) {
	case TRUST_NOT_PRIVATE:
	    data = not_private_xpm;
	    break;
	case TRUST_UNVERIFIED:
	    data = unverified_xpm;
	    break;
	case TRUST_PRIVATE:
	    data = private_xpm;
	    break;
	case TRUST_FINISHED:
	    data = finished_xpm;
	    break;
    }

    pixbuf = gdk_pixbuf_new_from_xpm_data(data);
    if (image) {
	gtk_image_set_from_pixbuf(GTK_IMAGE(image), pixbuf);
    } else {
	image = gtk_image_new_from_pixbuf(pixbuf);
    }
    gdk_pixbuf_unref(pixbuf);

    return image;
}

static void message_response_cb(GtkDialog *dialog, gint id, GtkWidget *widget)
{
    gtk_widget_destroy(GTK_WIDGET(widget));
}

static GtkWidget *create_dialog(PurpleNotifyMsgType type, const char *title,
	const char *primary, const char *secondary, int sensitive,
	GtkWidget **labelp, void (*add_custom)(GtkWidget *vbox, void *data),
	void *add_custom_data)
{
    GtkWidget *dialog;
    GtkWidget *hbox;
    GtkWidget *vbox;
    GtkWidget *label;
    GtkWidget *img = NULL;
    char *label_text;
    const char *icon_name = NULL;

    switch (type) {
	case PURPLE_NOTIFY_MSG_ERROR:
	    icon_name = PIDGIN_STOCK_DIALOG_ERROR;
	    break;

	case PURPLE_NOTIFY_MSG_WARNING:
	    icon_name = PIDGIN_STOCK_DIALOG_WARNING;
	    break;

	case PURPLE_NOTIFY_MSG_INFO:
	    icon_name = PIDGIN_STOCK_DIALOG_INFO;
	    break;

	default:
	    icon_name = NULL;
	    break;
    }

    if (icon_name != NULL) {
	img = gtk_image_new_from_stock(icon_name, GTK_ICON_SIZE_DIALOG);
	gtk_misc_set_alignment(GTK_MISC(img), 0, 0);
    }

    dialog = gtk_dialog_new_with_buttons(title ? title : PIDGIN_ALERT_TITLE,
					 NULL, 0, GTK_STOCK_OK,
					 GTK_RESPONSE_ACCEPT, NULL);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT,
	    sensitive);

    gtk_window_set_accept_focus(GTK_WINDOW(dialog), FALSE);
    gtk_window_set_role(GTK_WINDOW(dialog), "notify_dialog");

    g_signal_connect(G_OBJECT(dialog), "response",
				     G_CALLBACK(message_response_cb), dialog);

    gtk_container_set_border_width(GTK_CONTAINER(dialog), 6);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);
    gtk_dialog_set_has_separator(GTK_DIALOG(dialog), FALSE);
    gtk_box_set_spacing(GTK_BOX(GTK_DIALOG(dialog)->vbox), 12);
    gtk_container_set_border_width(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), 6);

    hbox = gtk_hbox_new(FALSE, 12);
    vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), hbox);

    if (img != NULL) {
	gtk_box_pack_start(GTK_BOX(hbox), img, FALSE, FALSE, 0);
    }

    label_text = g_strdup_printf(
		       "<span weight=\"bold\" size=\"larger\">%s</span>%s%s",
		       (primary ? primary : ""),
		       (primary ? "\n\n" : ""),
		       (secondary ? secondary : ""));

    label = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(label), label_text);
    gtk_label_set_selectable(GTK_LABEL(label), 1);
    g_free(label_text);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    if (add_custom) {
	add_custom(vbox, add_custom_data);
    }
    gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

    gtk_widget_show_all(dialog);

    if (labelp) *labelp = label;
    return dialog;
}

/* This is just like purple_notify_message, except: (a) it doesn't grab
 * keyboard focus, (b) the button is "OK" instead of "Close", and (c)
 * the labels aren't limited to 2K. */
static void otrg_gtk_dialog_notify_message(PurpleNotifyMsgType type,
	const char *accountname, const char *protocol, const char *username,
	const char *title, const char *primary, const char *secondary)
{
    create_dialog(type, title, primary, secondary, 1, NULL, NULL, NULL);
}

struct s_OtrgDialogWait {
    GtkWidget *dialog;
    GtkWidget *label;
};

/* Put up a Please Wait dialog, with the "OK" button desensitized.
 * Return a handle that must eventually be passed to
 * otrg_dialog_private_key_wait_done. */
static OtrgDialogWaitHandle otrg_gtk_dialog_private_key_wait_start(
	const char *account, const char *protocol)
{
    PurplePlugin *p;
    const char *title = "Generating private key";
    const char *primary = "Please wait";
    char *secondary;
    const char *protocol_print;
    GtkWidget *label;
    GtkWidget *dialog;
    OtrgDialogWaitHandle handle;

    p = purple_find_prpl(protocol);
    protocol_print = (p ? p->info->name : "Unknown");
	
    /* Create the Please Wait... dialog */
    secondary = g_strdup_printf("Generating private key for %s (%s)...",
	    account, protocol_print);
	
    dialog = create_dialog(PURPLE_NOTIFY_MSG_INFO, title, primary, secondary,
	    0, &label, NULL, NULL);
    handle = malloc(sizeof(struct s_OtrgDialogWait));
    handle->dialog = dialog;
    handle->label = label;

    /* Make sure the dialog is actually displayed before doing any
     * compute-intensive stuff. */
    while (gtk_events_pending ()) {
	gtk_main_iteration ();
    }
	
    g_free(secondary);

    return handle;
}

static int otrg_gtk_dialog_display_otr_message(const char *accountname,
	const char *protocol, const char *username, const char *msg)
{
    /* See if there's a conversation window we can put this in. */
    PurpleAccount *account;
    PurpleConversation *conv;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return -1;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username, account);
    if (!conv) return -1;

    purple_conversation_write(conv, NULL, msg, PURPLE_MESSAGE_SYSTEM, time(NULL));

    return 0;
}

/* End a Please Wait dialog. */
static void otrg_gtk_dialog_private_key_wait_done(OtrgDialogWaitHandle handle)
{
    const char *oldmarkup;
    char *newmarkup;

    oldmarkup = gtk_label_get_label(GTK_LABEL(handle->label));
    newmarkup = g_strdup_printf("%s Done.", oldmarkup);

    gtk_label_set_markup(GTK_LABEL(handle->label), newmarkup);
    gtk_widget_show(handle->label);
    gtk_dialog_set_response_sensitive(GTK_DIALOG(handle->dialog),
	    GTK_RESPONSE_ACCEPT, 1);

    g_free(newmarkup);
    free(handle);
}

/* Adds a "What's this?" expander to a vbox, containing { some "whatsthis"
 * markup (displayed in a GtkLabel) and a "More..." expander, containing
 * { some "more" markup (displayed in a GtkIMHTML) } }. */
static void add_whatsthis_more(GtkWidget *vbox, const char *whatsthismarkup,
	const char *moremarkup)
{
    GtkWidget *expander;
    GtkWidget *ebox;
    GtkWidget *whatsthis;
    GtkWidget *more;
    GtkWidget *frame;
    GtkWidget *scrl;
    GtkWidget *imh;
    GdkFont *font;

    expander = gtk_expander_new_with_mnemonic("_What's this?");
    gtk_box_pack_start(GTK_BOX(vbox), expander, FALSE, FALSE, 0);
    frame = gtk_frame_new(NULL);
    gtk_container_add(GTK_CONTAINER(expander), frame);
    ebox = gtk_vbox_new(FALSE, 10);
    gtk_container_add(GTK_CONTAINER(frame), ebox);
    whatsthis = gtk_label_new(NULL);
    gtk_label_set_line_wrap(GTK_LABEL(whatsthis), TRUE);
    gtk_label_set_markup(GTK_LABEL(whatsthis), whatsthismarkup);

    gtk_box_pack_start(GTK_BOX(ebox), whatsthis, FALSE, FALSE, 0);
    more = gtk_expander_new_with_mnemonic("_More...");
    gtk_box_pack_start(GTK_BOX(ebox), more, FALSE, FALSE, 0);
    scrl = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(more), scrl);

    imh = gtk_imhtml_new(NULL, NULL);
    pidgin_setup_imhtml(imh);
    gtk_imhtml_append_text(GTK_IMHTML(imh), moremarkup, GTK_IMHTML_NO_SCROLL);

    gtk_container_add(GTK_CONTAINER(scrl), imh);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrl),
	    GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

    /* This is a deprecated API, but mucking with PangoFontDescriptions
     * is (a) complicated, and (b) not fully supported by older versions
     * of libpango, which some people may have. */
    font = gtk_style_get_font(imh->style);
    gtk_widget_set_size_request(scrl, -1, 6 * (font->ascent + font->descent));
}

static void add_unk_fingerprint_expander(GtkWidget *vbox, void *data)
{
    add_whatsthis_more(vbox,
	    "A <b>fingerprint</b> is a unique identifier that you should "
	    "use to authenticate your buddy.  Right-click on the OTR button "
	    "in your buddy's conversation window, and choose \"Verify "
	    "fingerprint\".",

	    "If your buddy has more than one IM account, or uses more than "
	    "one computer, he may have multiple fingerprints.\n\n"
	    "However, the only way an imposter could duplicate one of your "
	    "buddy's fingerprints is by stealing information from his "
	    "computer.\n\n"
	    "<a href=\"" FINGERPRINT_HELPURL "\">"
	    "Click here for more information about fingerprints.</a>");
}

/* Show a dialog informing the user that a correspondent (who) has sent
 * us a Key Exchange Message (kem) that contains an unknown fingerprint.
 * Ask the user whether to accept the fingerprint or not.  If yes, call
 * response_cb(ops, opdata, response_data, resp) with resp = 1.  If no,
 * set resp = 0.  If the user destroys the dialog without answering, set
 * resp = -1. */
static void otrg_gtk_dialog_unknown_fingerprint(OtrlUserState us,
	const char *accountname, const char *protocol, const char *who,
	unsigned char fingerprint[20])
{
    char hash[45];
    char *primary, *secondary;
    PurplePlugin *p = purple_find_prpl(protocol);
    
    otrl_privkey_hash_to_human(hash, fingerprint);
    primary = g_strdup_printf("%s (%s) has received an unknown fingerprint "
	    "from %s:", accountname, 
	    (p && p->info->name) ? p->info->name : "Unknown", who);
    secondary = g_strdup_printf("%s\n", hash);

    create_dialog(PURPLE_NOTIFY_MSG_WARNING, "Unknown fingerprint",
	    primary, secondary, 1, NULL, add_unk_fingerprint_expander, NULL);

    g_free(primary);
    g_free(secondary);
}

static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data);

static void dialog_update_label_conv(PurpleConversation *conv, TrustLevel level)
{
    GtkWidget *label;
    GtkWidget *icon;
    GtkWidget *icontext;
    GtkWidget *button;
    GtkWidget *menuquery;
    GtkWidget *menuend;
    GtkWidget *menuquerylabel;
    GtkWidget *menuview;
    GtkWidget *menuverf;
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    label = purple_conversation_get_data(conv, "otr-label");
    icon = purple_conversation_get_data(conv, "otr-icon");
    icontext = purple_conversation_get_data(conv, "otr-icontext");
    button = purple_conversation_get_data(conv, "otr-button");
    menuquery = purple_conversation_get_data(conv, "otr-menuquery");
    menuquerylabel = gtk_bin_get_child(GTK_BIN(menuquery));
    menuend = purple_conversation_get_data(conv, "otr-menuend");
    menuview = purple_conversation_get_data(conv, "otr-menuview");
    menuverf = purple_conversation_get_data(conv, "otr-menuverf");

    /* Set the button's icon, label and tooltip. */
    otr_icon(icon, level);
    gtk_label_set_text(GTK_LABEL(label),
	    level == TRUST_FINISHED ? "Finished" :
	    level == TRUST_PRIVATE ? "Private" :
	    level == TRUST_UNVERIFIED ? "Unverified" :
	    "Not private");
    gtk_tooltips_set_tip(gtkconv->tooltips, button,
	    level == TRUST_NOT_PRIVATE ? "Start a private conversation" :
		    "Refresh the private conversation", NULL);

    /* Set the menu item label for the OTR Query item. */
    gtk_label_set_markup_with_mnemonic(GTK_LABEL(menuquerylabel),
	    level == TRUST_NOT_PRIVATE ? "Start _private conversation" :
		    "Refresh _private conversation");

    /* Sensitize the menu items as appropriate. */
    gtk_widget_set_sensitive(GTK_WIDGET(menuend), level != TRUST_NOT_PRIVATE);
    gtk_widget_set_sensitive(GTK_WIDGET(menuview), level != TRUST_NOT_PRIVATE);
    gtk_widget_set_sensitive(GTK_WIDGET(menuverf), level != TRUST_NOT_PRIVATE);

    /* Use any non-NULL value for "private", NULL for "not private" */
    purple_conversation_set_data(conv, "otr-private",
	    level == TRUST_NOT_PRIVATE ? NULL : conv);

    /* Set the appropriate visibility */
    gtk_widget_show_all(button);
}

static void dialog_update_label(ConnContext *context)
{
    PurpleAccount *account;
    PurpleConversation *conv;
    TrustLevel level = otrg_plugin_context_to_trust(context);

    account = purple_accounts_find(context->accountname, context->protocol);
    if (!account) return;
    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, context->username, account);
    if (!conv) return;
    dialog_update_label_conv(conv, level);
}

/* Add the help text for the "view session id" dialog. */
static void add_sessid_expander(GtkWidget *vbox, void *data)
{
    add_whatsthis_more(vbox,
	    "You can use this <b>secure session id</b> to double-check "
	    "the privacy of <i>this one conversation</i>.",

	    "To verify the session id, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your bold "
	    "half of the above session id to the other "
	    "(your buddy will have the same session id as you, but with the "
	    "other half bold).\n\nIf everything matches up, then <i>the "
	    "current conversation</i> between your computer and your buddy's "
	    "computer is private.\n\n"
	    "<b>Note:</b> You will probably never have to do this.  You "
	    "should normally use the \"Verify fingerprint\" functionality "
	    "instead.\n\n"
	    "<a href=\"" SESSIONID_HELPURL "\">"
	    "Click here for more information about the secure "
	    "session id.</a>");
}

static GtkWidget* otrg_gtk_dialog_view_sessionid(ConnContext *context)
{
    GtkWidget *dialog;
    unsigned char *sessionid;
    char sess1[21], sess2[21];
    char *primary = g_strdup_printf("Private connection with %s "
	    "established.", context->username);
    char *secondary;
    int i;
    OtrlSessionIdHalf whichhalf = context->sessionid_half;
    size_t idhalflen = (context->sessionid_len) / 2;

    /* Make a human-readable version of the sessionid (in two parts) */
    sessionid = context->sessionid;
    for(i=0;i<idhalflen;++i) sprintf(sess1+(2*i), "%02x", sessionid[i]);
    for(i=0;i<idhalflen;++i) sprintf(sess2+(2*i), "%02x",
	    sessionid[i+idhalflen]);
    
    secondary = g_strdup_printf("Secure session id:\n"
	    "<span %s>%s</span> <span %s>%s</span>\n",
	    whichhalf == OTRL_SESSIONID_FIRST_HALF_BOLD ?
		    "weight=\"bold\"" : "", sess1,
	    whichhalf == OTRL_SESSIONID_SECOND_HALF_BOLD ?
		    "weight=\"bold\"" : "", sess2);

    dialog = create_dialog(PURPLE_NOTIFY_MSG_INFO, "Private connection "
	    "established", primary, secondary, 1, NULL,
	    add_sessid_expander, NULL);

    g_free(primary);
    g_free(secondary);

    return dialog;
}

struct vrfy_fingerprint_data {
    Fingerprint *fprint;   /* You can use this pointer right away, but
			      you can't rely on it sticking around for a
			      while.  Use the copied pieces below
			      instead. */
    char *accountname, *username, *protocol;
    unsigned char fingerprint[20];
};

static void vrfy_fingerprint_data_free(struct vrfy_fingerprint_data *vfd)
{
    free(vfd->accountname);
    free(vfd->username);
    free(vfd->protocol);
    free(vfd);
}

static struct vrfy_fingerprint_data* vrfy_fingerprint_data_new(
	Fingerprint *fprint)
{
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context = fprint->context;

    vfd = malloc(sizeof(*vfd));
    vfd->fprint = fprint;
    vfd->accountname = strdup(context->accountname);
    vfd->username = strdup(context->username);
    vfd->protocol = strdup(context->protocol);
    memmove(vfd->fingerprint, fprint->fingerprint, 20);

    return vfd;
}

static void vrfy_fingerprint_destroyed(GtkWidget *w,
	struct vrfy_fingerprint_data *vfd)
{
    vrfy_fingerprint_data_free(vfd);
}

static void vrfy_fingerprint_changed(GtkComboBox *combo, void *data)
{
    struct vrfy_fingerprint_data *vfd = data;
    ConnContext *context = otrl_context_find(otrg_plugin_userstate,
	    vfd->username, vfd->accountname, vfd->protocol, 0, NULL,
	    NULL, NULL);
    Fingerprint *fprint;
    int oldtrust, trust;

    if (context == NULL) return;

    fprint = otrl_context_find_fingerprint(context, vfd->fingerprint,
	    0, NULL);

    if (fprint == NULL) return;

    oldtrust = (fprint->trust && fprint->trust[0]);
    trust = gtk_combo_box_get_active(combo) == 1 ? 1 : 0;

    /* See if anything's changed */
    if (trust != oldtrust) {
	otrl_context_set_trust(fprint, trust ? "verified" : "");
	/* Write the new info to disk, redraw the ui, and redraw the
	 * OTR buttons. */
	otrg_plugin_write_fingerprints();
	otrg_ui_update_keylist();
	otrg_dialog_resensitize_all();
    }
}

/* Add the verify widget and the help text for the verify fingerprint box. */
static void add_vrfy_fingerprint(GtkWidget *vbox, void *data)
{
    GtkWidget *hbox;
    GtkWidget *combo, *label;
    struct vrfy_fingerprint_data *vfd = data;
    char *labelt;
    int verified = 0;

    if (vfd->fprint->trust && vfd->fprint->trust[0]) {
	verified = 1;
    }

    hbox = gtk_hbox_new(FALSE, 0);
    combo = gtk_combo_box_new_text();
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), "I have not");
    gtk_combo_box_append_text(GTK_COMBO_BOX(combo), "I have");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), verified);
    label = gtk_label_new(" verified that this is in fact the correct");
    gtk_box_pack_start(GTK_BOX(hbox), combo, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    g_signal_connect(G_OBJECT(combo), "changed",
	    G_CALLBACK(vrfy_fingerprint_changed), vfd);

    hbox = gtk_hbox_new(FALSE, 0);
    labelt = g_strdup_printf("fingerprint for %s.",
	    vfd->username);
    label = gtk_label_new(labelt);
    g_free(labelt);
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    
    /* Leave a blank line */
    gtk_box_pack_start(GTK_BOX(vbox), gtk_label_new(NULL), FALSE, FALSE, 0);

    add_whatsthis_more(vbox,
	    "A <b>fingerprint</b> is a unique identifier that you should "
	    "use to authenticate your buddy.",

	    "To verify the fingerprint, contact your buddy via some "
	    "<i>other</i> authenticated channel, such as the telephone "
	    "or GPG-signed email.  Each of you should tell your fingerprint "
	    "to the other.\n\n"
	    "If everything matches up, you should indicate in the above "
	    "dialog that you <b>have</b> verified the fingerprint.\n\n"
	    "If your buddy has more than one IM account, or uses more than "
	    "one computer, he may have multiple fingerprints.\n\n"
	    "However, the only way an imposter could duplicate one of your "
	    "buddy's fingerprints is by stealing information from his "
	    "computer.\n\n"
	    "<a href=\"" FINGERPRINT_HELPURL "\">"
	    "Click here for more information about fingerprints.</a>");
}

static void otrg_gtk_dialog_verify_fingerprint(Fingerprint *fprint)
{
    GtkWidget *dialog;
    char our_hash[45], their_hash[45];
    char *primary;
    char *secondary;
    struct vrfy_fingerprint_data *vfd;
    ConnContext *context;
    PurplePlugin *p;
    char *proto_name;

    if (fprint == NULL) return;
    if (fprint->fingerprint == NULL) return;
    context = fprint->context;
    if (context == NULL) return;

    primary = g_strdup_printf("Verify fingerprint for %s",
	    context->username);
    vfd = vrfy_fingerprint_data_new(fprint);

    otrl_privkey_fingerprint(otrg_plugin_userstate, our_hash,
	    context->accountname, context->protocol);

    otrl_privkey_hash_to_human(their_hash, fprint->fingerprint);

    p = purple_find_prpl(context->protocol);
    proto_name = (p && p->info->name) ? p->info->name : "Unknown";
    secondary = g_strdup_printf("Fingerprint for you, %s (%s):\n%s\n\n"
	    "Purported fingerprint for %s:\n%s\n", context->accountname,
	    proto_name, our_hash, context->username, their_hash);

    dialog = create_dialog(PURPLE_NOTIFY_MSG_INFO, "Verify fingerprint",
	    primary, secondary, 1, NULL, add_vrfy_fingerprint, vfd);
    g_signal_connect(G_OBJECT(dialog), "destroy",
	    G_CALLBACK(vrfy_fingerprint_destroyed), vfd);

    g_free(primary);
    g_free(secondary);
}

/* Call this when a context transitions to ENCRYPTED. */
static void otrg_gtk_dialog_connected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    buf = g_strdup_printf("%s conversation with %s started.%s",
		level == TRUST_PRIVATE ? "Private" :
		level == TRUST_UNVERIFIED ? "<a href=\"" UNVERIFIED_HELPURL
			"\">Unverified</a>" :
		    /* This last case should never happen, since we know
		     * we're in ENCRYPTED. */
		    "Not private",
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? "  Warning: using old "
		    "protocol version 1." : "");

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
}

/* Call this when a context transitions to PLAINTEXT. */
static void otrg_gtk_dialog_disconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;

    conv = otrg_plugin_context_to_conv(context, 1);

    buf = g_strdup_printf("Private conversation with %s lost.",
	    purple_conversation_get_name(conv));
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
}

/* Call this if the remote user terminates his end of an ENCRYPTED
 * connection, and lets us know. */
static void otrg_gtk_dialog_finished(const char *accountname,
	const char *protocol, const char *username)
{
    /* See if there's a conversation window we can put this in. */
    PurpleAccount *account;
    PurpleConversation *conv;
    char *buf;

    account = purple_accounts_find(accountname, protocol);
    if (!account) return;

    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, username, account);
    if (!conv) return;

    buf = g_strdup_printf("%s has ended his private conversation with you; "
	    "you should do the same.", purple_conversation_get_name(conv));
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label_conv(conv, TRUST_FINISHED);
}

/* Call this when we receive a Key Exchange message that doesn't cause
 * our state to change (because it was just the keys we knew already). */
static void otrg_gtk_dialog_stillconnected(ConnContext *context)
{
    PurpleConversation *conv;
    char *buf;
    TrustLevel level;

    conv = otrg_plugin_context_to_conv(context, 1);
    level = otrg_plugin_context_to_trust(context);

    buf = g_strdup_printf("Successfully refreshed the %s conversation "
		"with %s.%s",
		level == TRUST_PRIVATE ? "private" :
		level == TRUST_UNVERIFIED ? "<a href=\"" UNVERIFIED_HELPURL
			"\">unverified</a>" :
		    /* This last case should never happen, since we know
		     * we're in ENCRYPTED. */
		    "not private",
		purple_conversation_get_name(conv),
		context->protocol_version == 1 ? "  Warning: using old "
		    "protocol version 1." : "");

    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);

    dialog_update_label(context);
}

/* This is called when the OTR button in the button box is clicked, or
 * when the appropriate context menu item is selected. */
static void otrg_gtk_dialog_clicked_connect(GtkWidget *widget, gpointer data)
{
    const char *format;
    char *buf;
    PurpleConversation *conv = data;

    if (purple_conversation_get_data(conv, "otr-private")) {
	format = "Attempting to refresh the private conversation with %s...";
    } else {
	format = "Attempting to start a private conversation with %s...";
    }
    buf = g_strdup_printf(format, purple_conversation_get_name(conv));
    purple_conversation_write(conv, NULL, buf, PURPLE_MESSAGE_SYSTEM, time(NULL));
    g_free(buf);
	
    otrg_plugin_send_default_query_conv(conv);
}

static void view_sessionid(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_gtk_dialog_view_sessionid(context);
}

static void verify_fingerprint(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    if (context == NULL || context->msgstate != OTRL_MSGSTATE_ENCRYPTED)
	return;

    otrg_gtk_dialog_verify_fingerprint(context->active_fingerprint);
}

static void menu_whatsthis(GtkWidget *widget, gpointer data)
{
    purple_notify_uri(otrg_plugin_handle, BUTTON_HELPURL);
}

static void menu_end_private_conversation(GtkWidget *widget, gpointer data)
{
    PurpleConversation *conv = data;
    ConnContext *context = otrg_plugin_conv_to_context(conv);

    otrg_ui_disconnect_connection(context);
}

static void dialog_resensitize(PurpleConversation *conv);

/* If the OTR button is right-clicked, show the context menu. */
static gboolean button_pressed(GtkWidget *w, GdkEventButton *event,
	gpointer data)
{
    PurpleConversation *conv = data;

    if ((event->button == 3) && (event->type == GDK_BUTTON_PRESS)) {
	GtkWidget *menu = purple_conversation_get_data(conv, "otr-menu");
	if (menu) {
	    gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
		    3, event->time);
	    return TRUE;
	}
    }
    return FALSE;
}

/* If the OTR button gets destroyed on us, clean up the data we stored
 * pointing to it. */
static void button_destroyed(GtkWidget *w, PurpleConversation *conv)
{
    GtkWidget *menu = purple_conversation_get_data(conv, "otr-menu");
    if (menu) gtk_object_destroy(GTK_OBJECT(menu));
    g_hash_table_remove(conv->data, "otr-label");
    g_hash_table_remove(conv->data, "otr-button");
    g_hash_table_remove(conv->data, "otr-icon");
    g_hash_table_remove(conv->data, "otr-icontext");
    g_hash_table_remove(conv->data, "otr-private");
    g_hash_table_remove(conv->data, "otr-menu");
    g_hash_table_remove(conv->data, "otr-menuquery");
    g_hash_table_remove(conv->data, "otr-menuend");
    g_hash_table_remove(conv->data, "otr-menuview");
    g_hash_table_remove(conv->data, "otr-menuverf");
}

/* Set up the per-conversation information display */
static void otrg_gtk_dialog_new_conv(PurpleConversation *conv)
{
    PidginConversation *gtkconv = PIDGIN_CONVERSATION(conv);
    ConnContext *context;
    GtkWidget *bbox;
    GtkWidget *button;
    GtkWidget *label;
    GtkWidget *bwbox;
    GtkWidget *bvbox;
    GtkWidget *iconbox;
    GtkWidget *icon;
    GtkWidget *icontext;
    GtkWidget *menu;
    GtkWidget *menuquery;
    GtkWidget *menuend;
    GtkWidget *menusep;
    GtkWidget *menuview;
    GtkWidget *menuverf;
    GtkWidget *whatsthis;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;
    bbox = gtkconv->lower_hbox;

    context = otrg_plugin_conv_to_context(conv);

    /* See if we're already set up */
    button = purple_conversation_get_data(conv, "otr-button");
    if (button) {
	/* Check if we've been removed from the bbox; purple does this
	 * when the user changes her prefs for the style of buttons to
	 * display. */
	GList *children = gtk_container_get_children(GTK_CONTAINER(bbox));
	if (!g_list_find(children, button)) {
	    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);
	}
	g_list_free(children);
	dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
	return;
    }

    /* Make the button */
    button = gtk_button_new();
    gtk_button_set_relief(GTK_BUTTON(button), GTK_RELIEF_NONE);
    gtk_box_pack_start(GTK_BOX(bbox), button, FALSE, FALSE, 0);

    bwbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(button), bwbox);
    bvbox = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bwbox), bvbox, TRUE, FALSE, 0);
    iconbox = gtk_hbox_new(FALSE, 3);
    gtk_box_pack_start(GTK_BOX(bvbox), iconbox, FALSE, FALSE, 0);
    label = gtk_label_new(NULL);
    gtk_box_pack_start(GTK_BOX(bvbox), label, FALSE, FALSE, 0);
    icontext = gtk_label_new("OTR:");
    gtk_box_pack_start(GTK_BOX(iconbox), icontext, FALSE, FALSE, 0);
    icon = otr_icon(NULL, TRUST_NOT_PRIVATE);
    gtk_box_pack_start(GTK_BOX(iconbox), icon, TRUE, FALSE, 0);

    gtk_widget_show_all(button);

    /* Make the context menu */
    menu = gtk_menu_new();
    gtk_menu_set_title(GTK_MENU(menu), "OTR Messaging");

    menuquery = gtk_menu_item_new_with_mnemonic("");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuquery);
    gtk_widget_show(menuquery);

    menuend = gtk_menu_item_new_with_mnemonic("_End private conversation");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuend);
    gtk_widget_show(menuend);

    menusep = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_widget_show(menusep);

    menuverf = gtk_menu_item_new_with_mnemonic("_Verify fingerprint");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuverf);
    gtk_widget_show(menuverf);

    menuview = gtk_menu_item_new_with_mnemonic("View _secure session id");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuview);
    gtk_widget_show(menuview);

    menusep = gtk_separator_menu_item_new();
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), menusep);
    gtk_widget_show(menusep);

    whatsthis = gtk_menu_item_new_with_mnemonic("_What's this?");
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), whatsthis);
    gtk_widget_show(whatsthis);

    purple_conversation_set_data(conv, "otr-label", label);
    purple_conversation_set_data(conv, "otr-button", button);
    purple_conversation_set_data(conv, "otr-icon", icon);
    purple_conversation_set_data(conv, "otr-icontext", icontext);
    purple_conversation_set_data(conv, "otr-menu", menu);
    purple_conversation_set_data(conv, "otr-menuquery", menuquery);
    purple_conversation_set_data(conv, "otr-menuend", menuend);
    purple_conversation_set_data(conv, "otr-menuview", menuview);
    purple_conversation_set_data(conv, "otr-menuverf", menuverf);
    gtk_signal_connect(GTK_OBJECT(menuquery), "activate",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    gtk_signal_connect(GTK_OBJECT(menuend), "activate",
	    GTK_SIGNAL_FUNC(menu_end_private_conversation), conv);
    gtk_signal_connect(GTK_OBJECT(menuverf), "activate",
	    GTK_SIGNAL_FUNC(verify_fingerprint), conv);
    gtk_signal_connect(GTK_OBJECT(menuview), "activate",
	    GTK_SIGNAL_FUNC(view_sessionid), conv);
    gtk_signal_connect(GTK_OBJECT(whatsthis), "activate",
	    GTK_SIGNAL_FUNC(menu_whatsthis), conv);
    gtk_signal_connect(GTK_OBJECT(button), "clicked",
	    GTK_SIGNAL_FUNC(otrg_gtk_dialog_clicked_connect), conv);
    g_signal_connect(G_OBJECT(button), "destroy",
	    G_CALLBACK(button_destroyed), conv);
    g_signal_connect(G_OBJECT(button), "button-press-event",
	    G_CALLBACK(button_pressed), conv);

    dialog_update_label_conv(conv, otrg_plugin_context_to_trust(context));
    dialog_resensitize(conv);
}

/* Remove the per-conversation information display */
static void otrg_gtk_dialog_remove_conv(PurpleConversation *conv)
{
    GtkWidget *button;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    button = purple_conversation_get_data(conv, "otr-button");
    if (button) gtk_object_destroy(GTK_OBJECT(button));
}

/* Set the OTR button to "sensitive" or "insensitive" as appropriate. */
static void dialog_resensitize(PurpleConversation *conv)
{
    PurpleAccount *account;
    PurpleConnection *connection;
    GtkWidget *button;
    const char *name;
    OtrlPolicy policy;

    /* Do nothing if this isn't an IM conversation */
    if (purple_conversation_get_type(conv) != PURPLE_CONV_TYPE_IM) return;

    account = purple_conversation_get_account(conv);
    name = purple_conversation_get_name(conv);
    policy = otrg_ui_find_policy(account, name);

    if (policy == OTRL_POLICY_NEVER) {
	otrg_gtk_dialog_remove_conv(conv);
    } else {
	otrg_gtk_dialog_new_conv(conv);
    }
    button = purple_conversation_get_data(conv, "otr-button");
    if (!button) return;
    if (account) {
	connection = purple_account_get_connection(account);
	if (connection) {
	    /* Set the button to "sensitive" */
	    gtk_widget_set_sensitive(button, 1);
	    return;
	}
    }
    /* Set the button to "insensitive" */
    gtk_widget_set_sensitive(button, 0);
}

/* Set all OTR buttons to "sensitive" or "insensitive" as appropriate.
 * Call this when accounts are logged in or out. */
static void otrg_gtk_dialog_resensitize_all(void)
{
    purple_conversation_foreach(dialog_resensitize);
}

static const OtrgDialogUiOps gtk_dialog_ui_ops = {
    otrg_gtk_dialog_notify_message,
    otrg_gtk_dialog_display_otr_message,
    otrg_gtk_dialog_private_key_wait_start,
    otrg_gtk_dialog_private_key_wait_done,
    otrg_gtk_dialog_unknown_fingerprint,
    otrg_gtk_dialog_verify_fingerprint,
    otrg_gtk_dialog_connected,
    otrg_gtk_dialog_disconnected,
    otrg_gtk_dialog_stillconnected,
    otrg_gtk_dialog_finished,
    otrg_gtk_dialog_resensitize_all,
    otrg_gtk_dialog_new_conv,
    otrg_gtk_dialog_remove_conv
};

/* Get the GTK dialog UI ops */
const OtrgDialogUiOps *otrg_gtk_dialog_get_ui_ops(void)
{
    return &gtk_dialog_ui_ops;
}
