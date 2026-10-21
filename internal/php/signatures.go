package php

import "regexp"

var (
	// The optional trailing group keeps a distro/backport suffix (e.g. Debian's
	// "7.4.33-1+deb11u3") verbatim, so later stages can reason about backports.
	reVersion        = regexp.MustCompile(`(?i)php/(\d+\.\d+(?:\.\d+)?(?:[-+~][A-Za-z0-9.\-+~]*)?)`)
	reHHVM           = regexp.MustCompile(`(?i)hhvm/(\d+\.\d+(?:\.\d+)?)`)
	rePHPInfoVersion = regexp.MustCompile(`(?i)PHP Version (\d+\.\d+\.\d+[A-Za-z0-9.\-+~]*)`)
	reGenerator      = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reZendEngineLine = regexp.MustCompile(`(?i)Zend Engine v[\d.]+(?:,\s*(?:with|Copyright)[^<\n]*)?`)
	// Loader/engine add-on line fragments that phpinfo prints.
	reWithLoaders = regexp.MustCompile(`(?i)with (the ionCube PHP Loader|Zend OPcache|Xdebug|Zend Guard Loader|Suhosin[- ]Patch|eAccelerator)[^,<\n]*`)

	// reApacheSig matches the Apache server-signature footer on default error
	// pages, which often leaks the PHP version: "... PHP/7.4.3 Server at ...".
	reApacheSig = regexp.MustCompile(`(?i)PHP/(\d+\.\d+\.\d+)[^<]*Server at`)
	// reServerSigPHP matches a bare "PHP/x.y.z" inside an <address> signature.
	reServerSig = regexp.MustCompile(`(?i)<address>[^<]*PHP/(\d+\.\d+\.\d+)`)
	// rePHPSourceLeak matches raw PHP source leaking into a response (a server
	// not executing PHP), a definitive PHP indicator.
	rePHPSourceLeak = regexp.MustCompile(`<\?php[\s\n]|<\?=`)
	// rePoweredBy matches "Powered by <PHP app>" footers across common apps.
	rePoweredBy = regexp.MustCompile(`(?i)Powered by\s+(WordPress|Joomla|Drupal|phpBB|MyBB|SMF|Simple Machines|vBulletin|XenForo|PrestaShop|OpenCart|Magento|MediaWiki|Discuz|DedeCMS|Typecho|Textpattern|Concrete5|ConcreteCMS|phpwind|Moodle|Laravel|Symfony|CodeIgniter|CakePHP|Yii|TYPO3)`)
)

type matchKind int

const (
	matchExact matchKind = iota
	matchPrefix
)

// cookieSig maps a cookie name to the technology it implies.
type cookieSig struct {
	name      string
	kind      matchKind
	framework string // "" means it only implies PHP generally
	weight    int
	detail    string
}

var cookieSigs = []cookieSig{
	{"PHPSESSID", matchExact, "", 70, "default PHP session cookie"},
	{"PHPSESSION", matchExact, "", 60, "PHP session cookie"},
	{"laravel_session", matchExact, "Laravel", 65, "Laravel session cookie"},
	{"laravel_token", matchExact, "Laravel", 55, "Laravel token cookie"},
	{"remember_web_", matchPrefix, "Laravel", 45, "Laravel remember-me cookie"},
	{"symfony", matchExact, "Symfony", 55, "Symfony session cookie"},
	{"sf_redirect", matchExact, "Symfony", 45, "Symfony redirect cookie"},
	{"ci_session", matchExact, "CodeIgniter", 60, "CodeIgniter session cookie"},
	{"CAKEPHP", matchExact, "CakePHP", 60, "CakePHP session cookie"},
	{"yii", matchPrefix, "Yii", 45, "Yii framework cookie"},
	{"_identity", matchPrefix, "Yii", 35, "Yii identity cookie"},
	{"wordpress_", matchPrefix, "WordPress", 55, "WordPress auth cookie"},
	{"wp-settings-", matchPrefix, "WordPress", 55, "WordPress settings cookie"},
	{"wordpress_logged_in_", matchPrefix, "WordPress", 60, "WordPress logged-in cookie"},
	{"MoodleSession", matchExact, "Moodle", 60, "Moodle session cookie"},
	{"fuel_csrf_token", matchExact, "FuelPHP", 55, "FuelPHP CSRF cookie"},
	{"frontend", matchExact, "Magento", 35, "Magento frontend cookie"},
	{"XDEBUG_SESSION", matchExact, "", 40, "Xdebug session cookie (debugger enabled)"},
	{"adminer_", matchPrefix, "Adminer", 40, "Adminer database tool cookie"},
	{"phpMyAdmin", matchExact, "phpMyAdmin", 55, "phpMyAdmin session cookie"},
	{"pmaUser-", matchPrefix, "phpMyAdmin", 55, "phpMyAdmin user cookie"},
	{"fe_typo_user", matchExact, "TYPO3", 60, "TYPO3 frontend session cookie"},
	{"be_typo_user", matchExact, "TYPO3", 60, "TYPO3 backend session cookie"},
	{"roundcube_sessid", matchExact, "Roundcube", 60, "Roundcube webmail session cookie"},
	{"roundcube_sessauth", matchExact, "Roundcube", 55, "Roundcube webmail auth cookie"},
	{"SQMSESSID", matchExact, "SquirrelMail", 60, "SquirrelMail session cookie"},
	{"horde_secret", matchExact, "Horde", 55, "Horde groupware cookie"},
	{"osCsid", matchExact, "osCommerce", 55, "osCommerce session cookie"},
	{"oc_sessionPassphrase", matchExact, "Nextcloud/ownCloud", 55, "Nextcloud/ownCloud cookie"},
	{"ocs", matchPrefix, "", 20, "possible ownCloud/Nextcloud cookie"},
	{"PrestaShop-", matchPrefix, "PrestaShop", 55, "PrestaShop cookie"},
	{"woocommerce_", matchPrefix, "WooCommerce", 50, "WooCommerce (WordPress) cookie"},
	{"wp_woocommerce_session_", matchPrefix, "WooCommerce", 55, "WooCommerce session cookie"},
	{"wordpress_test_cookie", matchExact, "WordPress", 55, "WordPress test cookie"},
	{"comment_author_", matchPrefix, "WordPress", 45, "WordPress comment author cookie"},
	{"_simplesaml", matchPrefix, "SimpleSAMLphp", 55, "SimpleSAMLphp session cookie"},
	{"MANTIS_", matchPrefix, "MantisBT", 50, "MantisBT cookie"},
	{"bbsessionhash", matchExact, "vBulletin", 55, "vBulletin session cookie"},
	{"mybb", matchPrefix, "MyBB", 45, "MyBB forum cookie"},
	{"PHPSESSIONID", matchExact, "", 60, "PHP session cookie variant"},
}

// headerSig matches a header value, optionally by substring.
type headerSig struct {
	header     string
	contains   string // case-insensitive substring; "" means "present at all"
	framework  string
	phpImplied bool
	variant    string
	weight     int
	detail     string
}

var headerSigs = []headerSig{
	{"X-Powered-By", "php", "", true, "PHP", 80, "X-Powered-By advertises PHP"},
	{"X-Powered-By", "hhvm", "", true, "HHVM", 80, "X-Powered-By advertises HHVM (PHP-compatible runtime)"},
	{"X-Powered-By", "zendserver", "", true, "Zend Server", 70, "Zend Server runtime"},
	{"X-Powered-By", "w3 total cache", "WordPress", true, "", 55, "W3 Total Cache (WordPress plugin)"},
	{"X-Powered-By", "shopware", "Shopware", true, "", 60, "Shopware e-commerce (PHP)"},
	{"X-Powered-By", "nette", "Nette", true, "", 55, "Nette Framework (PHP)"},
	{"X-Generator", "drupal", "Drupal", true, "", 60, "Drupal generator header"},
	{"X-Drupal-Cache", "", "Drupal", true, "", 55, "Drupal page cache header"},
	{"X-Drupal-Dynamic-Cache", "", "Drupal", true, "", 55, "Drupal dynamic cache header"},
	{"X-Redirect-By", "wordpress", "WordPress", true, "", 55, "WordPress redirect header"},
	{"X-Pingback", "xmlrpc.php", "WordPress", true, "", 50, "WordPress XML-RPC pingback endpoint"},
	{"X-Powered-CMS", "", "", false, "", 25, "CMS advertised via X-Powered-CMS"},
	{"Link", "api.w.org", "WordPress", true, "", 45, "WordPress REST API link relation"},
	{"X-Debug-Token", "", "Symfony", true, "", 45, "Symfony web profiler debug token"},
	{"X-Debug-Token-Link", "", "Symfony", true, "", 45, "Symfony web profiler link"},
	{"X-Powered-By", "ioncube", "", true, "", 40, "ionCube PHP Loader advertised"},
	{"Set-Cookie", "phpsessid", "", true, "PHP", 70, "PHP session cookie in Set-Cookie"},
	{"X-LiteSpeed-Cache", "", "WordPress", true, "", 35, "LiteSpeed Cache (commonly WordPress)"},
	{"X-LiteSpeed-Tag", "", "", true, "", 25, "LiteSpeed Cache tag header"},
	{"X-Content-Powered-By", "k2", "Joomla", true, "", 50, "K2 (Joomla extension)"},
	{"X-Content-Powered-By", "joomla", "Joomla", true, "", 55, "Joomla content header"},
	{"X-Clockwork-Id", "", "Clockwork", true, "", 50, "Clockwork PHP dev profiler"},
	{"X-Clockwork-Version", "", "Clockwork", true, "", 50, "Clockwork PHP dev profiler"},
	{"X-Powered-By", "wp super cache", "WordPress", true, "", 50, "WP Super Cache (WordPress plugin)"},
	{"X-Powered-By", "wp rocket", "WordPress", true, "", 50, "WP Rocket (WordPress plugin)"},
	{"X-Powered-By", "typo3", "TYPO3", true, "", 55, "TYPO3 CMS"},
	{"X-Powered-By", "craft cms", "Craft CMS", true, "", 55, "Craft CMS (PHP/Yii)"},
	{"X-Powered-By", "bitrix", "Bitrix", true, "", 55, "1C-Bitrix (PHP)"},
	{"X-Drupal-Route-Normalizer", "", "Drupal", true, "", 50, "Drupal route normalizer header"},
	{"X-Drupal-Cache-Tags", "", "Drupal", true, "", 45, "Drupal cache-tags header"},
	{"X-Shopware-Cache-Id", "", "Shopware", true, "", 50, "Shopware cache header"},
	{"X-Flow-Powered", "", "Neos/Flow", true, "", 50, "Neos/Flow (PHP)"},
	{"X-Redirect-By", "polylang", "WordPress", true, "", 45, "Polylang (WordPress plugin)"},
	{"X-Powered-By", "mod_php", "", true, "PHP", 70, "mod_php advertised"},
	{"X-Turbo-Charged-By", "litespeed", "", false, "", 20, "LiteSpeed web server"},
}

// bodySig matches distinctive content in a response body.
type bodySig struct {
	id         string
	re         *regexp.Regexp
	framework  string
	phpImplied bool
	weight     int
	detail     string
}

var bodySigs = []bodySig{
	{"body.php-fatal", regexp.MustCompile(`(?i)<b>Fatal error</b>:.*?in <b>.*?\.php</b>`), "", true, 65, "PHP fatal error with .php source path"},
	{"body.php-warning", regexp.MustCompile(`(?i)<b>Warning</b>:.*?in <b>.*?\.php</b>`), "", true, 55, "PHP warning with .php source path"},
	{"body.php-notice", regexp.MustCompile(`(?i)<b>(Notice|Deprecated)</b>:.*?in <b>.*?\.php</b>`), "", true, 50, "PHP notice/deprecation with .php source path"},
	{"body.php-parse", regexp.MustCompile(`(?i)Parse error:.*?in .*?\.php on line \d+`), "", true, 55, "PHP parse error"},
	{"body.php-uncaught", regexp.MustCompile(`(?i)(Uncaught (Error|Exception)|Stack trace:).*?\.php`), "", true, 50, "PHP uncaught exception / stack trace"},
	{"body.php-undefined-fn", regexp.MustCompile(`(?i)Call to undefined (function|method) .*?\(\)`), "", true, 45, "PHP undefined function/method error"},
	{"body.php-call-stack", regexp.MustCompile(`(?i)PHP (Warning|Notice|Fatal error|Deprecated):`), "", true, 50, "PHP log-style diagnostic line"},
	{"body.php-strict", regexp.MustCompile(`(?i)<b>(Strict Standards|Recoverable fatal error)</b>:`), "", true, 50, "PHP strict/recoverable error"},
	{"body.php-memory", regexp.MustCompile(`(?i)Allowed memory size of \d+ bytes exhausted`), "", true, 60, "PHP memory-exhaustion error"},
	{"body.php-maxtime", regexp.MustCompile(`(?i)Maximum execution time of \d+ second`), "", true, 60, "PHP max-execution-time error"},
	{"body.php-include", regexp.MustCompile(`(?i)(include|require)(_once)?\(\): Failed opening`), "", true, 55, "PHP include/require failure"},
	{"body.php-membercall", regexp.MustCompile(`(?i)Call to a member function \w+\(\) on (null|bool|false|array)`), "", true, 55, "PHP member-call error"},
	{"body.php-undefined", regexp.MustCompile(`(?i)(Undefined (variable|index|array key|offset|property)|Trying to access array offset)`), "", true, 45, "PHP undefined access notice"},
	{"body.php-stacktrace", regexp.MustCompile(`(?i)Stack trace:\s*#0`), "", true, 55, "PHP exception stack trace"},
	{"body.php-trace-end", regexp.MustCompile(`#\d+ \{main\}`), "", true, 55, "PHP stack-trace terminator"},
	{"body.php-pdoexception", regexp.MustCompile(`(?i)(PDOException|mysqli_sql_exception|SQLSTATE\[)`), "", true, 45, "PHP database exception"},
	{"body.php-source-leak", rePHPSourceLeak, "", true, 65, "Raw PHP source leaked (server not executing PHP)"},
	{"body.apache-sig", reApacheSig, "", true, 50, "Apache server signature advertises PHP"},
	{"body.whoops", regexp.MustCompile(`(?i)Whoops\\(Run|Handler)|class="Whoops`), "Whoops", true, 55, "Whoops PHP error handler"},
	{"body.debugbar", regexp.MustCompile(`(?i)phpdebugbar`), "Laravel Debugbar", true, 50, "Laravel/PHP Debugbar"},
	{"body.newrelic", regexp.MustCompile(`(?i)NREUM|window\.newrelic`), "New Relic (PHP agent)", true, 25, "New Relic browser agent (PHP agent likely)"},
	{"body.laravel-ignition", regexp.MustCompile(`(?i)ignition|flare-client|Illuminate\\Foundation`), "Laravel", true, 45, "Laravel Ignition error page"},
	{"body.symfony-profiler", regexp.MustCompile(`(?i)sf-toolbar|/_profiler/|Symfony\\Component\\(HttpKernel|ErrorHandler)`), "Symfony", true, 45, "Symfony profiler/runtime markers"},
	{"body.bitrix", regexp.MustCompile(`(?i)/bitrix/(js|templates|cache)/`), "Bitrix", true, 50, "1C-Bitrix paths"},
	{"body.dle", regexp.MustCompile(`(?i)/engine/(classes|modules|data)/|dle_root`), "DataLife Engine", true, 45, "DataLife Engine paths"},
	{"body.moodle", regexp.MustCompile(`(?i)/theme/(image|yui)\.php|M\.cfg\s*=`), "Moodle", true, 45, "Moodle runtime markers"},
	{"body.powered-by", rePoweredBy, "", true, 50, "\"Powered by\" footer for a PHP application"},
	{"body.wp-content", regexp.MustCompile(`(?i)/wp-(content|includes)/`), "WordPress", true, 50, "WordPress asset paths"},
	{"body.wp-json", regexp.MustCompile(`(?i)/wp-json/`), "WordPress", true, 45, "WordPress REST route"},
	{"body.drupal", regexp.MustCompile(`(?i)/sites/(default|all)/(files|modules|themes)/`), "Drupal", true, 50, "Drupal site paths"},
	{"body.joomla", regexp.MustCompile(`(?i)/media/(jui|system)/js/|option=com_`), "Joomla", true, 50, "Joomla media/component paths"},
	{"body.magento", regexp.MustCompile(`(?i)/(skin/frontend|static/version\d+)/|Magento_`), "Magento", true, 50, "Magento asset paths"},
	{"body.laravel", regexp.MustCompile(`(?i)Illuminate\\|laravel_session|window\.Laravel`), "Laravel", true, 45, "Laravel runtime markers"},
	{"body.symfony", regexp.MustCompile(`(?i)Symfony\\Component|sf-toolbar`), "Symfony", true, 45, "Symfony runtime markers"},
	{"body.phpbb", regexp.MustCompile(`(?i)Powered by phpBB`), "phpBB", true, 55, "phpBB forum"},
	{"body.mediawiki", regexp.MustCompile(`(?i)<meta name="generator" content="MediaWiki`), "MediaWiki", true, 50, "MediaWiki generator"},
	{"body.prestashop", regexp.MustCompile(`(?i)PrestaShop|/themes/.*?/assets/`), "PrestaShop", true, 40, "PrestaShop markers"},
	{"body.typo3", regexp.MustCompile(`(?i)/typo3(conf|temp)/|TYPO3 CMS`), "TYPO3", true, 50, "TYPO3 CMS paths"},
}

// loaderBodyTokens are distinctive enough to detect in any body, not just
// phpinfo output.
var loaderBodyTokens = []struct {
	token  string
	module string
	detail string
}{
	{"ionCube", "ionCube Loader", "ionCube encoder/loader present"},
	{"the ionCube PHP Loader needs to be installed", "ionCube Loader", "ionCube-encoded code without the loader"},
	{"Zend Guard", "Zend Guard Loader", "Zend Guard protected code"},
	{"Zend Optimizer", "Zend Optimizer", "Zend Optimizer referenced"},
	{"SourceGuardian", "SourceGuardian", "SourceGuardian-protected code"},
	{"This file is protected by", "SourceGuardian", "SourceGuardian loader message"},
	{"Xdebug", "xdebug", "Xdebug diagnostic output"},
	{"Suhosin", "Suhosin", "Suhosin hardening referenced"},
}

// phpInfoModules is the extension/module catalogue scanned inside phpinfo
// output, where these short names are unambiguous.
var phpInfoModules = []string{
	"bcmath", "bz2", "calendar", "ctype", "curl", "dom", "exif", "fileinfo",
	"filter", "ftp", "gd", "gettext", "gmp", "hash", "iconv", "igbinary",
	"imap", "intl", "json", "ldap", "mbstring", "mysqli", "mysqlnd",
	"openssl", "pcntl", "pcre", "pdo_mysql", "pdo_pgsql", "pdo_sqlite",
	"pgsql", "Phar", "posix", "readline", "redis", "Reflection", "session",
	"shmop", "SimpleXML", "soap", "sockets", "sodium", "SPL", "sqlite3",
	"tokenizer", "xml", "xmlreader", "xmlrpc", "xmlwriter", "xsl", "zip",
	"zlib", "Zend OPcache", "opcache", "xdebug", "ionCube Loader", "Suhosin",
	"imagick", "memcached", "memcache", "apcu", "mongodb", "amqp", "swoole",
	"ssh2", "yaml", "maxminddb", "protobuf", "grpc",
	// Databases & drivers.
	"pdo_sqlsrv", "sqlsrv", "oci8", "pdo_oci", "interbase", "pdo_firebird",
	"db2", "odbc", "pdo_odbc", "cubrid",
	// Crypto / hashing / mail.
	"mcrypt", "mhash", "gnupg", "libsodium", "argon2",
	// Caching / APM / profilers (strong "addon" give-aways).
	"apc", "eaccelerator", "wincache", "newrelic", "blackfire", "tideways",
	"tideways_xhprof", "xhprof", "pcov", "ddtrace", "datadog", "opentelemetry",
	"spx", "xhgui",
	// Async / concurrency / FFI.
	"pcntl", "ev", "event", "libevent", "parallel", "uv", "inotify", "ffi",
	"sync", "pthreads",
	// Imaging / text / misc.
	"gmagick", "vips", "tidy", "enchant", "pspell", "wddx", "recode",
	"gearman", "rdkafka", "zookeeper", "stomp", "oauth", "yac", "igbinary",
	"msgpack", "lzf", "zstd", "brotli", "snuffleupagus", "ioncube_loader",
	"Zend Guard Loader", "SourceGuardian",
}

// phpExtensions returns the subset of module names considered "extensions"
// for reporting; here modules and extensions are reported from the same scan,
// but kept as separate output fields for clarity and future divergence.
