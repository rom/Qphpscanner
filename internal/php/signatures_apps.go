package php

import "regexp"

// Deeper detection for two of the most common PHP stacks: Drupal and Magento.
func init() {
	headerSigs = append(headerSigs, appHeaderSigs...)
	cookieSigs = append(cookieSigs, appCookieSigs...)
	bodySigs = append(bodySigs, appBodySigs...)
}

var appHeaderSigs = []headerSig{
	{"X-Magento-Cache-Debug", "", "Magento", true, "", 60, "Magento full-page-cache debug header"},
	{"X-Magento-Tags", "", "Magento", true, "", 55, "Magento cache-tags header"},
	{"X-Magento-Cache-Control", "", "Magento", true, "", 45, "Magento cache-control header"},
	{"X-Drupal-Cache-Max-Age", "", "Drupal", true, "", 45, "Drupal cache max-age header"},
	{"X-Generator", "drupal", "Drupal", true, "", 60, "Drupal generator header"},
}

var appCookieSigs = []cookieSig{
	{"X-Magento-Vary", matchExact, "Magento", 55, "Magento full-page-cache vary cookie"},
	{"mage-messages", matchExact, "Magento", 45, "Magento messages cookie"},
	{"section_data_ids", matchExact, "Magento", 45, "Magento customer-section cookie"},
	{"private_content_version", matchExact, "Magento", 45, "Magento private-content cookie"},
}

var appBodySigs = []bodySig{
	{"body.magento2", regexp.MustCompile(`(?i)x-magento-init|data-mage-init|/pub/static/|/static/version\d+/|mage/cookies|Magento_\w+/`), "Magento", true, 55, "Magento 2 runtime/asset markers"},
	{"body.magento-fpc", regexp.MustCompile(`(?i)/customer/section/load/|mage-cache-storage|Magento_Ui/`), "Magento", true, 45, "Magento customer-section / cache markers"},
	{"body.drupal2", regexp.MustCompile(`(?i)Drupal\.settings|drupalSettings|data-drupal-|/core/misc/drupal\.js|/core/(modules|themes)/`), "Drupal", true, 50, "Drupal runtime / core-path markers"},
	{"body.drupal-aggregate", regexp.MustCompile(`(?i)/sites/default/files/(css|js)/|/sites/[^/"']+/files/`), "Drupal", true, 45, "Drupal aggregated-asset paths"},
}
