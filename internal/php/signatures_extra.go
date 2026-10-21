package php

import "regexp"

// This file broadens detection coverage: more application/framework/addon
// cookies and headers, many more PHP error-message and runtime-quirk body
// signatures, additional loader tokens and phpinfo modules. They are appended
// to the primary catalogues in signatures.go at package init so the detection
// loops pick them up unchanged.
func init() {
	cookieSigs = append(cookieSigs, extraCookieSigs...)
	headerSigs = append(headerSigs, extraHeaderSigs...)
	bodySigs = append(bodySigs, extraBodySigs...)
	loaderBodyTokens = append(loaderBodyTokens, extraLoaderTokens...)
	phpInfoModules = append(phpInfoModules, extraModules...)
}

var extraCookieSigs = []cookieSig{
	{"OCSESSID", matchExact, "OpenCart", 55, "OpenCart session cookie"},
	{"Drupal.visitor.", matchPrefix, "Drupal", 45, "Drupal visitor cookie"},
	{"SSESS", matchPrefix, "Drupal", 35, "Drupal (HTTPS) session cookie"},
	{"SESS", matchPrefix, "Drupal", 25, "Drupal session cookie"},
	{"CraftSessionId", matchExact, "Craft CMS", 55, "Craft CMS session cookie"},
	{"october_session", matchExact, "October CMS", 55, "October CMS session cookie"},
	{"grav-site-", matchPrefix, "Grav", 50, "Grav flat-file CMS cookie"},
	{"flarum_session", matchExact, "Flarum", 55, "Flarum forum session cookie"},
	{"dle_", matchPrefix, "DataLife Engine", 45, "DataLife Engine cookie"},
	{"phpbb3_", matchPrefix, "phpBB", 55, "phpBB3 session cookie"},
	{"WHMCS", matchPrefix, "WHMCS", 50, "WHMCS billing cookie"},
	{"MATOMO_SESSID", matchExact, "Matomo", 55, "Matomo analytics session cookie"},
	{"PIWIK_SESSID", matchExact, "Matomo", 55, "Piwik/Matomo session cookie"},
	{"zbx_session", matchExact, "Zabbix", 55, "Zabbix frontend session cookie"},
	{"zbx_sessionid", matchExact, "Zabbix", 55, "Zabbix session cookie"},
	{"ips4_", matchPrefix, "IPS Community Suite", 50, "Invision Community cookie"},
	{"SMFCookie", matchPrefix, "SMF", 55, "Simple Machines Forum cookie"},
	{"DokuWiki", matchPrefix, "DokuWiki", 50, "DokuWiki session cookie"},
	{"CONCRETE5", matchPrefix, "ConcreteCMS", 50, "Concrete CMS cookie"},
	{"EGROUPWARE_SESSID", matchExact, "EGroupware", 45, "EGroupware session cookie"},
	{"ezsessionid", matchExact, "eZ Publish / Ibexa", 50, "eZ Publish / Ibexa session cookie"},
	{"modx", matchPrefix, "MODX", 45, "MODX session cookie"},
	{"shop_", matchPrefix, "Shopware", 25, "possible Shopware storefront cookie"},
	{"glpi_", matchPrefix, "GLPI", 50, "GLPI IT asset manager cookie"},
	{"OJSSID", matchExact, "Open Journal Systems", 50, "OJS session cookie"},
	{"nette-", matchPrefix, "Nette", 45, "Nette Framework cookie"},
	{"drupalSettings", matchPrefix, "Drupal", 30, "Drupal settings cookie"},
	{"magento", matchPrefix, "Magento", 35, "Magento cookie"},
}

var extraHeaderSigs = []headerSig{
	{"X-Powered-By", "laravel", "Laravel", true, "", 55, "Laravel advertised in X-Powered-By"},
	{"X-Powered-By", "symfony", "Symfony", true, "", 55, "Symfony advertised in X-Powered-By"},
	{"X-Powered-By", "slim", "Slim", true, "", 45, "Slim micro-framework"},
	{"X-Powered-By", "cakephp", "CakePHP", true, "", 50, "CakePHP advertised"},
	{"X-Powered-By", "codeigniter", "CodeIgniter", true, "", 50, "CodeIgniter advertised"},
	{"X-Powered-By", "yii", "Yii", true, "", 50, "Yii framework advertised"},
	{"X-Powered-By", "phalcon", "Phalcon", true, "", 50, "Phalcon (C-extension PHP framework)"},
	{"X-Powered-By", "statamic", "Statamic", true, "", 55, "Statamic (Laravel) CMS"},
	{"X-Powered-By", "october", "October CMS", true, "", 55, "October CMS (Laravel)"},
	{"X-Powered-By", "contao", "Contao", true, "", 55, "Contao CMS"},
	{"X-Powered-By", "pimcore", "Pimcore", true, "", 55, "Pimcore CMS/PIM"},
	{"X-Powered-By", "whmcs", "WHMCS", true, "", 55, "WHMCS billing platform"},
	{"X-Powered-By", "matomo", "Matomo", true, "", 55, "Matomo analytics (PHP)"},
	{"X-Powered-By", "silverstripe", "SilverStripe", true, "", 55, "SilverStripe CMS"},
	{"X-Powered-By", "grav", "Grav", true, "", 55, "Grav flat-file CMS"},
	{"X-Powered-By", "kirby", "Kirby", true, "", 55, "Kirby CMS"},
	{"X-Powered-By", "processwire", "ProcessWire", true, "", 55, "ProcessWire CMS"},
	{"X-Powered-By", "dolibarr", "Dolibarr", true, "", 55, "Dolibarr ERP/CRM"},
	{"X-Powered-By", "modx", "MODX", true, "", 50, "MODX CMS"},
	{"X-Powered-By", "fat-free", "Fat-Free", true, "", 45, "Fat-Free Framework"},
	{"X-Powered-By", "concrete", "ConcreteCMS", true, "", 50, "Concrete CMS"},
	{"X-Generator", "silverstripe", "SilverStripe", true, "", 55, "SilverStripe generator header"},
	{"X-Generator", "typo3", "TYPO3", true, "", 55, "TYPO3 generator header"},
	{"X-Backdrop-Cache", "", "Backdrop", true, "", 50, "Backdrop CMS cache header"},
	{"X-Redirect-By", "yoast", "WordPress", true, "", 45, "Yoast SEO redirect (WordPress)"},
	{"X-Powered-By", "wpengine", "WordPress", true, "", 45, "WP Engine (managed WordPress)"},
	{"Host-Header", "wordpress", "WordPress", true, "", 30, "WordPress host header marker"},
	{"X-Nextcloud-", "", "Nextcloud", true, "", 50, "Nextcloud response header"},
	{"X-Matomo-Request-Id", "", "Matomo", true, "", 50, "Matomo request-id header"},
	{"X-Drupal-Cache-Contexts", "", "Drupal", true, "", 45, "Drupal cache-contexts header"},
	{"X-Php-Ref", "", "", true, "", 25, "custom X-Php-Ref header"},
	{"Liip-Cache-Control", "", "Symfony", true, "", 35, "Liip cache (Symfony)"},
	{"X-Powered-By", "bagisto", "Bagisto", true, "", 50, "Bagisto (Laravel) e-commerce"},
	{"X-Sourcefiles", "", "", true, "", 20, "debug X-Sourcefiles header"},
}

var extraBodySigs = []bodySig{
	{"body.php-headers-sent", regexp.MustCompile(`(?i)Cannot modify header information - headers already sent`), "", true, 55, "PHP 'headers already sent' warning"},
	{"body.php-session-start", regexp.MustCompile(`(?i)session_start\(\):`), "", true, 50, "PHP session_start() diagnostic"},
	{"body.php-open-basedir", regexp.MustCompile(`(?i)open_basedir restriction in effect`), "", true, 55, "PHP open_basedir restriction message"},
	{"body.php-disabled-fn", regexp.MustCompile(`(?i)has been disabled for security reasons`), "", true, 55, "PHP disable_functions message"},
	{"body.php-safe-mode", regexp.MustCompile(`(?i)SAFE MODE Restriction in effect`), "", true, 55, "PHP (legacy) safe_mode message"},
	{"body.php-max-input", regexp.MustCompile(`(?i)Input variables exceeded \d+`), "", true, 55, "PHP max_input_vars exceeded"},
	{"body.php-post-size", regexp.MustCompile(`(?i)POST Content-Length of \d+ bytes exceeds`), "", true, 55, "PHP post_max_size exceeded"},
	{"body.php-upload", regexp.MustCompile(`(?i)The uploaded file exceeds the upload_max_filesize`), "", true, 55, "PHP upload_max_filesize message"},
	{"body.php-typeerror", regexp.MustCompile(`(?i)Uncaught TypeError:[^<\n]*?\.php`), "", true, 50, "PHP 7+ Uncaught TypeError"},
	{"body.php-argcount", regexp.MustCompile(`(?i)ArgumentCountError`), "", true, 45, "PHP ArgumentCountError"},
	{"body.php-divzero", regexp.MustCompile(`(?i)DivisionByZeroError`), "", true, 45, "PHP DivisionByZeroError"},
	{"body.php-valueerror", regexp.MustCompile(`(?i)Uncaught ValueError:[^<\n]*?\.php`), "", true, 45, "PHP 8 Uncaught ValueError"},
	{"body.php-doc-link", regexp.MustCompile(`(?i)https?://(www\.)?php\.net/(manual|function)\.`), "", true, 40, "error page links to php.net manual"},
	{"body.php-xdebug", regexp.MustCompile(`(?i)Xdebug has detected|xdebug-error|class="xdebug-error`), "xdebug", true, 50, "Xdebug-formatted error output"},
	{"body.php-return-type", regexp.MustCompile(`(?i)Return value must be of type|must be of type \w+, \w+ (returned|given)`), "", true, 40, "PHP type-declaration error"},
	{"body.php-deprecated-dyn", regexp.MustCompile(`(?i)Creation of dynamic property .* is deprecated`), "", true, 50, "PHP 8.2 dynamic-property deprecation"},
	{"body.php-null-deprecated", regexp.MustCompile(`(?i)Passing null to parameter #\d+ \(\$\w+\) of type`), "", true, 50, "PHP 8.1 null-to-non-nullable deprecation"},
	{"body.ci-error", regexp.MustCompile(`(?i)A PHP Error was encountered|CodeIgniter\\|system/(core|database)/`), "CodeIgniter", true, 50, "CodeIgniter error/runtime markers"},
	{"body.cake-error", regexp.MustCompile(`(?i)Cake\\(Core|Error|Routing)|CakePHP.*?\bError\b`), "CakePHP", true, 45, "CakePHP error markers"},
	{"body.yii-error", regexp.MustCompile(`(?i)yii\\(base|web|db)\\|Yii Framework`), "Yii", true, 45, "Yii framework markers"},
	{"body.slim-error", regexp.MustCompile(`(?i)Slim Application Error`), "Slim", true, 50, "Slim framework error page"},
	{"body.laminas", regexp.MustCompile(`(?i)Zend\\(Mvc|Diactoros|Db)|Laminas\\`), "Laminas/Zend", true, 45, "Laminas/Zend Framework markers"},
	{"body.phalcon", regexp.MustCompile(`(?i)Phalcon\\(Mvc|Exception)`), "Phalcon", true, 50, "Phalcon framework markers"},
	{"body.october", regexp.MustCompile(`(?i)/modules/system/assets/|October\\Rain`), "October CMS", true, 50, "October CMS markers"},
	{"body.grav", regexp.MustCompile(`(?i)/user/(themes|plugins)/|Grav was unable`), "Grav", true, 45, "Grav flat-file CMS markers"},
	{"body.statamic", regexp.MustCompile(`(?i)Statamic\b|/vendor/statamic/`), "Statamic", true, 50, "Statamic CMS markers"},
	{"body.whmcs", regexp.MustCompile(`(?i)WHMCS|/templates/orderforms/`), "WHMCS", true, 45, "WHMCS billing markers"},
	{"body.matomo", regexp.MustCompile(`(?i)piwik|matomo\.(js|php)|var _paq`), "Matomo", true, 40, "Matomo/Piwik analytics markers"},
	{"body.cacti", regexp.MustCompile(`(?i)Cacti|cacti_version`), "Cacti", true, 45, "Cacti monitoring markers"},
	{"body.zabbix", regexp.MustCompile(`(?i)Zabbix SIA|zabbix\.php`), "Zabbix", true, 50, "Zabbix frontend markers"},
	{"body.glpi", regexp.MustCompile(`(?i)GLPI\b|/plugins/.*?/front/`), "GLPI", true, 45, "GLPI markers"},
	{"body.osticket", regexp.MustCompile(`(?i)osTicket|powered by osTicket`), "osTicket", true, 50, "osTicket helpdesk markers"},
	{"body.suitecrm", regexp.MustCompile(`(?i)SugarCRM|SuiteCRM|/sugar_version`), "SuiteCRM/SugarCRM", true, 50, "Sugar/SuiteCRM markers"},
	{"body.dolibarr", regexp.MustCompile(`(?i)Dolibarr|/htdocs/theme/`), "Dolibarr", true, 50, "Dolibarr ERP markers"},
	{"body.silverstripe", regexp.MustCompile(`(?i)SilverStripe|/resources/vendor/silverstripe/`), "SilverStripe", true, 50, "SilverStripe markers"},
	{"body.contao", regexp.MustCompile(`(?i)/bundles/contao|Contao Open Source CMS`), "Contao", true, 50, "Contao CMS markers"},
	{"body.concrete", regexp.MustCompile(`(?i)/concrete/(js|css|themes)/|ConcreteCMS`), "ConcreteCMS", true, 50, "Concrete CMS markers"},
	{"body.modx", regexp.MustCompile(`(?i)MODX|/assets/components/`), "MODX", true, 45, "MODX CMS markers"},
	{"body.phpmyadmin", regexp.MustCompile(`(?i)phpMyAdmin|pma_|/themes/pmahomme/`), "phpMyAdmin", true, 45, "phpMyAdmin markers"},
	{"body.roundcube", regexp.MustCompile(`(?i)Roundcube Webmail|/program/js/app\.js`), "Roundcube", true, 45, "Roundcube webmail markers"},
	{"body.nextcloud", regexp.MustCompile(`(?i)data-requesttoken|/core/js/dist/|Nextcloud`), "Nextcloud/ownCloud", true, 40, "Nextcloud/ownCloud markers"},
	{"body.opencart", regexp.MustCompile(`(?i)catalog/view/theme/|route=product/`), "OpenCart", true, 45, "OpenCart storefront markers"},
	{"body.xmlrpc", regexp.MustCompile(`(?i)XML-RPC server accepts POST requests only`), "WordPress", true, 55, "WordPress XML-RPC endpoint response"},
}

var extraLoaderTokens = []struct {
	token  string
	module string
	detail string
}{
	{"Snuffleupagus", "snuffleupagus", "Snuffleupagus hardening module"},
	{"blackfire", "blackfire", "Blackfire profiler agent"},
	{"Tideways", "tideways", "Tideways profiler agent"},
	{"phpdbg", "phpdbg", "phpdbg interactive debugger"},
	{"ionCube Loader", "ionCube Loader", "ionCube Loader present"},
	{"OPcache", "Zend OPcache", "OPcache referenced"},
	{"FrankenPHP", "FrankenPHP", "FrankenPHP (PHP app server)"},
	{"RoadRunner", "RoadRunner", "RoadRunner (PHP app server)"},
}

var extraModules = []string{
	// App servers / runtimes.
	"frankenphp", "roadrunner", "openswoole",
	// Further extensions seen in phpinfo.
	"gmagick", "imagick", "ImageMagick", "mongodb", "couchbase", "cassandra",
	"rdkafka", "amqp", "zmq", "ev", "uv", "parallel", "fiber", "sodium",
	"opentelemetry", "excimer", "decimal", "ds", "simdjson", "yac", "apcu_bc",
	"vld", "trader", "stats", "geoip", "geospatial", "svm", "gRPC",
	"relay", "uuid", "igbinary", "lz4", "zstd", "brotli", "xlswriter",
	"phpredis", "swoole", "swow", "memprof", "meminfo", "componere",
}
