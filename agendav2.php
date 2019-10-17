<?php
class agendav2 extends rcube_plugin
{
  public $task = '.*';
  public $rc;
  public $ui;

  private $env_loaded = false;

  /**
   * Plugin initialization.
   */
  function init()
  {
    $this->rc = rcube::get_instance();

    if($this->rc->task == 'settings')
    {
      $this->add_hook('preferences_sections_list', array($this, 'agendav2_preferences_sections_list'));
      $this->add_hook('preferences_list', array($this, 'agendav2_preferences_list'));
      $this->add_hook('preferences_save', array($this, 'agendav2_preferences_save'));
    }

    $this->load_ui();
    $this->register_task('agendav2');
    $this->add_hook('startup', array($this, 'startup'));
    $this->register_action('index', array($this, 'action'));
    $this->add_hook('session_destroy', array($this, 'logout'));
  }

  /**
   * Returns the DB-Driver for AgenDAV
   *
   * @return string                  the driver
   */
  private function getDriver()
  {
    $rcmail = rcmail::get_instance();

    switch($rcmail->config->get('agendav_dbtype', false))
    {
      case 'mysqli':
      case 'pdo_mysql':
        $agendavDriver = 'mysql';
      break;
      case 'oci8':
        $agendavDriver = 'oci';
      break;
      case 'postgre':
        $agendavDriver = 'pgsql';
      break;
      default:
        $agendavDriver = $rcmail->config->get('agendav_dbtype', false);
      break;
    }

    return $agendavDriver;
  }

  /**
   * Startup the application, adding the Task-button
   */
  function startup()
  {
    $rcmail = rcmail::get_instance();
    if(!$rcmail->output->framed)
    {
      // add taskbar button
      $this->add_button(array(
          'command'    => 'agendav2',
          'class'      => 'button-calendar',
          'classsel'   => 'button-calendar button-selected',
          'innerclass' => 'button-inner',
          'label'      => 'agendav2.agendav2',
          'type'       => 'link',
      ), 'taskbar');

      $this->include_script('agendav2.js');
    }

    $this->include_stylesheet($this->local_skin_path() . '/agendav2.css');
  }

  /**
   * Manage the action (called from Roundcube)
   */
  function action()
  {
    $rcmail = rcmail::get_instance();

    if($rcmail->action == 'index')
    {
      $rcmail->output->set_pagetitle($this->gettext('agendav2'));
      $rcmail->output->add_handlers(array('agendav2content' => array($this, 'content')));
      $rcmail->output->send('agendav2.agendav2');
    }
  }

  /**
   * Called on logout from Roundcube.
   * Destroy the AgenDAV-session
   */
  function logout($args)
  {
    $rcmail = rcmail::get_instance();
    $dbh = new PDO($this->getDriver().':dbname='.$rcmail->config->get('agendav_dbname', false).';host='.$rcmail->config->get('agendav_dbhost', false), $rcmail->config->get('agendav_dbuser', false), $rcmail->config->get('agendav_dbpass', false));
    $stmt = $dbh->prepare("DELETE FROM sessions WHERE sess_ID=:id");
    $stmt->bindParam(':id', $_COOKIE['agendav_sess']);
    $stmt->execute();
    setcookie('agendav_sess', '', time() - 3600);
  }

  /**
   * Create a new session for AgenDAV
   *
   * @param string $url             URL of CalDAV-Server
   * @param string $username        Username for CalDAV-Server
   * @param string $passwd          Password for CalDAV-Server
   * @return string                 AgenDAV SessionID
   */
  private function createAgendavSession($url, $username, $passwd)
  {
    $rcmail = rcmail::get_instance();

    $dbh = new PDO($this->getDriver().':dbname='.$rcmail->config->get('agendav_dbname', false).';host='.$rcmail->config->get('agendav_dbhost', false), $rcmail->config->get('agendav_dbuser', false), $rcmail->config->get('agendav_dbpass', false));

    $createSession = true;
// Check if AgenDAV already runs
    if(isset($_COOKIE['agendav_sess']))
    {
// Now have to check the validity of the session...
      $stmt = $dbh->prepare("SELECT COUNT(*) AS c FROM ".$rcmail->config->get('agendav_dbprefix', false)."sessions WHERE sess_ID = :sessid AND sess_data LIKE '%username%'");
      $stmt->bindParam(':sessid', $_COOKIE['agendav_sess']);
      $stmt->execute();
      $sess = $stmt->fetch(PDO::FETCH_ASSOC);
      if($sess['c'] == 1)
      {
        $createSession = false;
        $agendavSess = $_COOKIE['agendav_sess'];
      }
    }

    if($createSession)
    {
// Only create a session if needed (not already present)
      $agendavSess = sprintf('%04x%04x%04x%04x%04x%04x%04x%04x', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
      $parts = parse_url($url);
      $calURL = str_replace('/default/', '/', $parts['path']);
      $princURL = str_replace('calendars', 'principals', $calURL);
      $title = sprintf('%s on %s', $username, $parts['host']);
      $sessData = sprintf("_sf2_attributes|a:6:{s:%d:\"_csrf/%s\";s:43:\"jjHRUo2b2h1mJKdmgssq-9nIfz89JQimUn7adX3q-Ss\";s:8:\"username\";s:%d:\"%s\";s:8:\"password\";s:%d:\"%s\";s:13:\"principal_url\";s:%d:\"%s\";s:17:\"calendar_home_set\";s:%d:\"%s\";s:11:\"displayname\";s:%d:\"%s\";}_sf2_flashes|a:0:{}_sf2_meta|a:3:{s:1:\"u\";i:1535378471;s:1:\"c\";i:1535366483;s:1:\"l\";s:1:\"0\";}",
             strlen($app['csrf.secret']) + 6, $app['csrf.secret'],
             strlen($username), $username,
             strlen($passwd), $passwd,
             strlen($princURL), $princURL,
             strlen($calURL), $calURL,
             strlen($title), $title
      );

      $stmt = $dbh->prepare('INSERT INTO '.$rcmail->config->get('agendav_dbprefix', false).'sessions (sess_id, sess_data, sess_lifetime, sess_time) VALUES (:id, :data, 21600, UNIX_TIMESTAMP())');
      $stmt->bindParam(':id', $agendavSess);
      $stmt->bindParam(':data', $sessData);
      $stmt->execute();
    }

    $dbh = null;

    return $agendavSess;
  }

  /**
   * Display the content of the calender (calling AgenDAV)
   */
  function content($attrib)
  {
    $rcmail = rcmail::get_instance();

    $url = $this->rc->config->get('agendav2_url');
    $username = $this->rc->config->get('agendav2_username');
    if (substr($url, -10) === "caldav.php") {
      $url = $url.'/'.$username; // DAViCal url
    }
    $passwd = $this->decrypt($this->rc->config->get('agendav2_passwd'));

    $agendavSessID = $this->createAgendavSession($url, $username, $passwd);
    setcookie('agendav_sess', $agendavSessID, 0);

    setcookie('agendav_baseurl', $url, 0);
    setcookie('agendav_timezone', $_SESSION['timezone'], 0);
    setcookie('agendav_language', substr($_SESSION['language'], 0, 2), 0);

    $src = $this->api->url.'agendav2/'.$rcmail->config->get('agendav_path', false).'/web/public/index.php';
    $attrib['src'] = $src;
    if(empty($attrib['id']))
      $attrib['id'] = 'rcmailagendav2content';
    $attrib['name'] = $attrib['id'];

    return $rcmail->output->frame($attrib);
  }

  /**
   * Handler for preferences_sections_list hook.
   * Adds Encryption settings section into preferences sections list.
   *
   * @param array Original parameters
   *
   * @return array Modified parameters
   */
  function agendav2_preferences_sections_list($p)
  {
    $this->add_texts('localization/');
    $p['list']['agendav2'] = array(
        'id' => 'agendav2',
        'section' => $this->gettext('calendar'),
    );

    return $p;
  }

  /**
   * Handler for preferences_list hook.
   * Adds options blocks into AgenDAV settings sections in Preferences.
   *
   * @param array Original parameters
   *
   * @return array Modified parameters
   */
  function agendav2_preferences_list($p)
  {
    $this->add_texts('localization/');
    if($p['section'] != 'agendav2')
      return $p;

    $urlV = rcube_utils::get_input_value('agendav2_url', rcube_utils::INPUT_POST);
    $usernameV = rcube_utils::get_input_value('agendav2_username', rcube_utils::INPUT_POST);
    $passwdV = rcube_utils::get_input_value('agendav2_passwd', rcube_utils::INPUT_POST);

    $url = new html_inputfield(array('name' => 'agendav2_url', 'type' => 'text', 'autocomplete' => 'off', 'value' => $urlV != '' ? $urlV : $this->rc->config->get('agendav2_url'), 'size' => 255));
    $username = new html_inputfield(array('name' => 'agendav2_username', 'type' => 'text', 'autocomplete' => 'off', 'value' => $usernameV != '' ? $usernameV : $this->rc->config->get('agendav2_username'), 'size' => 255));
    $passwd = new html_inputfield(array('name' => 'agendav2_passwd', 'type' => 'password', 'autocomplete' => 'off', 'value' => '', 'size' => 255));

    $p['blocks']['agendav2_preferences_section'] = array(
                        'options' => array(
                                array('title'=> rcube::Q($this->gettext('caldav_url')), 'content' => $url->show()),
                                array('title'=> rcube::Q($this->gettext('username')), 'content' => $username->show()),
                                array('title'=> rcube::Q($this->gettext('password')), 'content' => $passwd->show()),
                        ),
                        'name' => rcube::Q($this->gettext('dav_settings'))
    );

    return $p;
  }

  /**
   * Handler for preferences_save hook.
   * Executed on AgenDAV settings form submit.
   *
   * @param array Original parameters
   *
   * @return array Modified parameters
   */
  function agendav2_preferences_save($p)
  {
    $this->add_texts('localization/');
    if ($p['section'] == 'agendav2')
    {
      $rcmail = rcmail::get_instance();

      $url = rcube_utils::get_input_value('agendav2_url', rcube_utils::INPUT_POST);
      $username = rcube_utils::get_input_value('agendav2_username', rcube_utils::INPUT_POST);
      $passwd = rcube_utils::get_input_value('agendav2_passwd', rcube_utils::INPUT_POST);
      if($passwd == '')
        $passwd = $this->decrypt($this->rc->config->get('agendav2_passwd'));

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_USERPWD, "$username:$passwd");
      curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
      curl_setopt($ch, CURLOPT_HEADER, 0);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PROPFIND');
      $content = curl_exec($ch);
      $ret = curl_getinfo($ch);
      $curl_error = curl_error($ch);
      curl_close($ch);
      if (!$curl_error){
        try {
          $xml = new SimpleXMLElement($content);
        } catch (Exception $e) {
          $xml = NULL; // in case of incorrect user/pwd, DAViCal returns a plain text error message
        }
      }
      if($ret['http_code'] >= 200 && $ret['http_code'] < 300 && !$curl_error && $xml)
      {
        $p['prefs'] = array(
            'agendav2_url'       => $url,
            'agendav2_username'  => $username,
            'agendav2_passwd'    => $this->encrypt($passwd),
        );
      }
      else
      {
        if ($curl_error) {
          $error_message = $curl_error;
        } elseif (!$xml) {
          $error_message = $content;
          // in case of incorrect user/pwd, DAViCal returns a plain text error
        } else {
          $s = $xml->children('s', true);
          $error_message = $s->message;
        }
        $p['abort'] = true;
        $p['message'] = sprintf($this->gettext('err_propfind'), (string) $error_message);
      }
    }

    return $p;
  }

  /**
   * Plugin environment initialization.
   */
  function load_env()
  {
    if($this->env_loaded)
      return;

    $this->env_loaded = true;

    // load the AgenDAV2 plugin configuration
    $this->load_config();

    // include localization (if wasn't included before)
    $this->add_texts('localization/');
  }

  /**
   * Plugin UI initialization.
   */
  function load_ui()
  {
    $this->load_env();
    $skin_path = $this->local_skin_path();
    $this->include_stylesheet("$skin_path/agendav2.css");
  }

  /**
   * Encrypt a passwort (key: IMAP-password)
   *
   * @param string $passwd             Password as plain text
   * @return string                    Encrypted password
   */
  private function encrypt($passwd)
  {
    $rcmail = rcmail::get_instance();

    $imap_password = $rcmail->decrypt($_SESSION['password']);
    while(strlen($imap_password)<24)
      $imap_password .= $imap_password;
    $imap_password = substr($imap_password, 0, 24);
    $deskey_backup = $rcmail->config->set('agendav_des_key', $imap_password);
    $enc = $rcmail->encrypt($passwd, 'agendav_des_key');
    $deskey_backup = $rcmail->config->set('agendav_des_key', '');

    return $enc;
  }

  /**
   * Decrypt a passwort (key: IMAP-password)
   *
   * @param string $passwd             Encrypted password
   * @return string                    Passwort as plain text
   */
  private function decrypt($passwd)
  {
    $rcmail = rcmail::get_instance();

    $imap_password = $rcmail->decrypt($_SESSION['password']);
    while(strlen($imap_password)<24)
      $imap_password .= $imap_password;

    $imap_password = substr($imap_password, 0, 24);
    $deskey_backup = $rcmail->config->set('agendav_des_key', $imap_password);
    $clear = $rcmail->decrypt($passwd, 'agendav_des_key');
    $deskey_backup = $rcmail->config->set('agendav_des_key', '');

    return $clear;
  }
}
?>
