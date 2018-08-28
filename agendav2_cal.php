<?php
if(isset($_COOKIE['agendav_baseurl']))
  $app['caldav.baseurl'] = $_COOKIE['agendav_baseurl'];
if(isset($_COOKIE['agendav_timezone']))
  $app['defaults.timezone'] = $_COOKIE['agendav_timezone'];
if(isset($_COOKIE['agendav_language']))
  $app['defaults.language'] = $_COOKIE['agendav_language'];

$app['site.title'] = '';
?>
