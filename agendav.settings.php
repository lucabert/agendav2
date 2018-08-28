<?php
// Database settings
$app['db.options'] = [
        'dbname' => '<agendav db>',
        'user' => '<agendav user>',
        'password' => '<agendav password>',
        'host' => 'localhost',
        'driver' => 'pdo_mysql'
];

// CSRF secret
$app['csrf.secret'] = '<secret (random 12)>';

// Log path
$app['log.path'] = __DIR__.'/../../log/';

// Logging level
$app['log.level'] = 'WARNING';

// Authentication method required by CalDAV server (basic or digest)
$app['caldav.authmethod'] = 'basic';

// Whether to show public CalDAV urls
$app['caldav.publicurls'] = true;

// Default time format. Options: '12' / '24'
$app['defaults.time_format'] = '24';

/*
 * Default date format. Options:
 *
 * - ymd: YYYY-mm-dd
 * - dmy: dd-mm-YYYY
 * - mdy: mm-dd-YYYY
 */
$app['defaults.date_format'] = 'dmy';

// Default first day of week. Options: 0 (Sunday), 1 (Monday)
$app['defaults.weekstart'] = 0;

// Default for showing the week numbers. Options: true/false
$app['defaults.show_week_nb'] = true;

// Default for showing the "now" indicator, a line on current time. Options: true/false
$app['defaults.show_now_indicator'] = true;
//
// Default number of days covered by the "list" (agenda) view. Allowed values: 7, 14 or 31
$app['defaults.list_days'] = 7;

// Default view (month, week, day or list)
$app['defaults.default_view'] = 'month';

// Adding CSS to hide logout button
$app['stylesheets'] = [
    'agendav.css',
    '../../../../../agendav2.css',
];

include_once(__DIR__.'/../../../agendav2_cal.php');
?>
