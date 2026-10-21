package php

import "regexp"

// A second broadening pass: more PHP applications/CMSes and a few additional
// high-signal PHP-presence headers and error patterns.
func init() {
	cookieSigs = append(cookieSigs, extraCookieSigs2...)
	headerSigs = append(headerSigs, extraHeaderSigs2...)
	bodySigs = append(bodySigs, extraBodySigs2...)
}

var extraCookieSigs2 = []cookieSig{
	{"serendipity[", matchPrefix, "Serendipity", 50, "Serendipity blog cookie"},
	{"elgg", matchPrefix, "Elgg", 45, "Elgg social-network cookie"},
	{"limesurvey", matchPrefix, "LimeSurvey", 50, "LimeSurvey session cookie"},
	{"bolt_session", matchPrefix, "Bolt", 50, "Bolt CMS session cookie"},
	{"spip_session", matchPrefix, "SPIP", 50, "SPIP session cookie"},
	{"xoops_", matchPrefix, "XOOPS", 45, "XOOPS session cookie"},
	{"exp_", matchPrefix, "ExpressionEngine", 45, "ExpressionEngine cookie"},
	{"BOXSESSID", matchExact, "FOSSBilling", 45, "FOSSBilling/BoxBilling session cookie"},
	{"zenid", matchExact, "Zen Cart", 50, "Zen Cart session cookie"},
	{"XCART_SESSION", matchPrefix, "X-Cart", 50, "X-Cart session cookie"},
	{"cpsession", matchPrefix, "cPanel", 40, "cPanel session cookie"},
	{"espo-", matchPrefix, "EspoCRM", 45, "EspoCRM cookie"},
	{"mautic_", matchPrefix, "Mautic", 45, "Mautic session cookie"},
	{"chamilo", matchPrefix, "Chamilo", 45, "Chamilo LMS cookie"},
	{"il_", matchPrefix, "ILIAS", 30, "possible ILIAS LMS cookie"},
}

var extraHeaderSigs2 = []headerSig{
	{"X-Php-Version", "", "", true, "PHP", 65, "explicit X-Php-Version header"},
	{"X-Php-Originating-Script", "", "", true, "PHP", 65, "PHP mail() X-Php-Originating-Script header leak"},
	{"X-Powered-By", "sylius", "Sylius", true, "", 50, "Sylius e-commerce (Symfony)"},
	{"X-Powered-By", "thelia", "Thelia", true, "", 50, "Thelia e-commerce (Symfony)"},
	{"X-Powered-By", "expressionengine", "ExpressionEngine", true, "", 50, "ExpressionEngine CMS"},
	{"X-Powered-By", "limesurvey", "LimeSurvey", true, "", 50, "LimeSurvey"},
	{"X-Powered-By", "xoops", "XOOPS", true, "", 45, "XOOPS CMS"},
	{"X-Powered-By", "mautic", "Mautic", true, "", 50, "Mautic marketing automation"},
	{"X-Powered-By", "espocrm", "EspoCRM", true, "", 50, "EspoCRM"},
	{"X-Powered-By", "ibexa", "eZ Publish / Ibexa", true, "", 50, "Ibexa DXP (eZ Platform)"},
	{"X-Powered-By", "ez publish", "eZ Publish / Ibexa", true, "", 50, "eZ Publish"},
	{"X-Powered-By", "winter", "Winter CMS", true, "", 45, "Winter CMS (Laravel)"},
	{"X-Powered-By", "pyrocms", "PyroCMS", true, "", 45, "PyroCMS (Laravel)"},
	{"X-Powered-By", "dokuwiki", "DokuWiki", true, "", 50, "DokuWiki"},
	{"X-Generator", "mautic", "Mautic", true, "", 50, "Mautic generator header"},
	{"X-Generator", "bolt", "Bolt", true, "", 45, "Bolt CMS generator header"},
	{"Server", "cpsrvd", "cPanel", false, "", 20, "cPanel (cpsrvd) web server"},
	{"X-Powered-By", "plesklin", "Plesk", false, "", 20, "Plesk control panel"},
}

var extraBodySigs2 = []bodySig{
	{"body.phplist", regexp.MustCompile(`(?i)Powered by phpList|/lists/admin/`), "phpList", true, 50, "phpList markers"},
	{"body.limesurvey", regexp.MustCompile(`(?i)LimeSurvey|/scripts/survey|limesurvey`), "LimeSurvey", true, 45, "LimeSurvey markers"},
	{"body.spip", regexp.MustCompile(`(?i)Composed with SPIP|spip\.php|/local/cache-`), "SPIP", true, 45, "SPIP markers"},
	{"body.xoops", regexp.MustCompile(`(?i)Powered by XOOPS|/modules/system/`), "XOOPS", true, 45, "XOOPS markers"},
	{"body.expressionengine", regexp.MustCompile(`(?i)ExpressionEngine|/themes/ee/|Powered by EE`), "ExpressionEngine", true, 45, "ExpressionEngine markers"},
	{"body.bolt", regexp.MustCompile(`(?i)Powered by Bolt|/bolt/view/`), "Bolt", true, 45, "Bolt CMS markers"},
	{"body.textpattern", regexp.MustCompile(`(?i)Textpattern CMS|<!-- Textpattern`), "Textpattern", true, 45, "Textpattern markers"},
	{"body.serendipity", regexp.MustCompile(`(?i)Serendipity|/plugins/serendipity_`), "Serendipity", true, 45, "Serendipity markers"},
	{"body.b2evolution", regexp.MustCompile(`(?i)b2evolution`), "b2evolution", true, 50, "b2evolution markers"},
	{"body.getsimple", regexp.MustCompile(`(?i)GetSimple|Powered by GetSimple`), "GetSimple CMS", true, 50, "GetSimple CMS markers"},
	{"body.mautic", regexp.MustCompile(`(?i)Mautic|/mtc\.js|mauticForm`), "Mautic", true, 45, "Mautic markers"},
	{"body.espocrm", regexp.MustCompile(`(?i)EspoCRM`), "EspoCRM", true, 50, "EspoCRM markers"},
	{"body.chamilo", regexp.MustCompile(`(?i)Chamilo`), "Chamilo", true, 50, "Chamilo LMS markers"},
	{"body.ilias", regexp.MustCompile(`(?i)ILIAS|/Services/Init/`), "ILIAS", true, 45, "ILIAS LMS markers"},
	{"body.sylius", regexp.MustCompile(`(?i)Sylius|sylius-`), "Sylius", true, 45, "Sylius markers"},
	{"body.zencart", regexp.MustCompile(`(?i)Zen Cart|zenid=`), "Zen Cart", true, 45, "Zen Cart markers"},
	{"body.cubecart", regexp.MustCompile(`(?i)CubeCart`), "CubeCart", true, 50, "CubeCart markers"},
	{"body.xcart", regexp.MustCompile(`(?i)X-Cart|xcart/`), "X-Cart", true, 45, "X-Cart markers"},
	{"body.winter", regexp.MustCompile(`(?i)Winter CMS|/modules/winter/`), "Winter CMS", true, 45, "Winter CMS markers"},
	{"body.kirby", regexp.MustCompile(`(?i)/media/plugins/|Kirby\b`), "Kirby", true, 40, "Kirby CMS markers"},
	{"body.craft", regexp.MustCompile(`(?i)Craft CMS|/cpresources/`), "Craft CMS", true, 45, "Craft CMS markers"},
	{"body.cpanel", regexp.MustCompile(`(?i)cPanel, L\.L\.C\.|cpanel-logo|Login - cPanel`), "cPanel", true, 40, "cPanel login/branding"},
	{"body.plesk", regexp.MustCompile(`(?i)Plesk Obsidian|plesk-login|Parallels Plesk`), "Plesk", true, 40, "Plesk control panel"},
	{"body.php-eval-error", regexp.MustCompile(`(?i)eval\(\)'d code`), "", true, 45, "PHP eval()'d code error"},
	{"body.php-fatal-online", regexp.MustCompile(`(?i)Fatal error:[^<\n]{0,120}on line \d+`), "", true, 45, "PHP fatal error with line number"},
}
