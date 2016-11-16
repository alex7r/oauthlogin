<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.OAuthLogin
 *
 * @author      JoomPlace Team
 * @copyright   Copyright (C) JoomPlace, www.joomplace.com
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Plugin class for login/register with google account.
 *
 * @since  1.0
 */
class PlgSystemOAuthLogin extends JPlugin
{
	/**
	 * Load the language file on instantiation.
	 *
	 * @var    boolean
	 * @since  3.1
	 */
	protected $autoloadLanguage = true;

	protected $oauth_client;

	protected $credentials = array();

	/**
	 * Constructor.
	 *
	 * @param   object  &$subject  The object to observe -- event dispatcher.
	 * @param   object  $config    An optional associative array of configuration settings.
	 *
	 * @since   1.6
	 */
	public function __construct(&$subject, $config)
	{
		parent::__construct($subject, $config);
		if(
			!$this->params->get('clientid',false)
			||
			!$this->params->get('clientsecret',false)
			||
			!$this->params->get('redirecturi',false)
		){
			return false;
		}
	}

	public function onAfterRoute(){
		if((JFactory::getApplication()->input->get('task',null)=='user.login' && JFactory::getApplication()->input->get('jauth',null)=='google') || JFactory::getApplication()->input->get('state',null)=='jauth'){
			jimport('joomla.oauth2.client');
			$oauth_client = new JOAuth2Client();
			$oauth_client->setOption('sendheaders',true);
			$oauth_client->setOption('client_id','token');
			$oauth_client->setOption('scope',array('email','profile'));
			$oauth_client->setOption('requestparams',array('state'=>'jauth','task'=>JFactory::getApplication()->input->get('task',null),'access_type'=>'offline'));
			$oauth_client->setOption('clientid',$this->params->get('clientid',false));
			$oauth_client->setOption('clientsecret',$this->params->get('clientsecret',false));
			$oauth_client->setOption('redirecturi',$this->params->get('redirecturi',false));
			$oauth_client->setOption('authurl','https://accounts.google.com/o/oauth2/v2/auth');
			$oauth_client->setOption('tokenurl','https://www.googleapis.com/oauth2/v4/token');
			$oauth_client->authenticate();
			$this->oauth_client = $oauth_client;
			if($oauth_client->isAuthenticated())
			{
				if($this->params->get('implicitloginallowed',false) || ($id = JUserHelper::getUserId($this->credentials['email']) && strpos(JFactory::getUser($id)->getParam('link',''),'google.com'))){
					$options = array('action'=>'core.login.'.(JFactory::getApplication()->isSite()?'site':'admin'));
					if($this->login($options)){
						/* if not redirected on onAfterLogin just go to front page */
						JFactory::getApplication()->redirect(JRoute::_('index.php'));
					}
				}
			}
		}
	}

	protected function login($options){
		$credentials = array();
		$response = new stdClass();
		$this->onUserAuthenticate($credentials,$options,$response);
		if($response->status == JAuthentication::STATUS_SUCCESS){
			JPluginHelper::importPlugin('user');
			// OK, the credentials are authenticated and user is authorised.  Let's fire the onLogin event.
			$app = JFactory::getApplication();
			$response->password_clear = JUserHelper::genRandomPassword();
			if($this->registrationAllowed()){
				$options['autoregister'] = true;
			}
			$results = $app->triggerEvent('onUserLogin', array((array) $response, $options));

			/*
			 * If any of the user plugins did not successfully complete the login routine
			 * then the whole method fails.
			 *
			 * Any errors raised should be done in the plugin as this provides the ability
			 * to provide much more information about why the routine may have failed.
			 */
			$user = JFactory::getUser();

			if ($response->type == 'Cookie')
			{
				$user->set('cookieLogin', true);
			}

			if (in_array(false, $results, true) == false)
			{
				$options['user'] = $user;
				$options['responseType'] = $response->type;
				// The user is successfully logged in. Run the after login events
				JFactory::getApplication()->triggerEvent('onUserAfterLogin', array($options));
			}

			return true;
		}
		return false;
	}

	public function onUserAuthenticate($credentials, $options, &$response)
	{
		jimport('joomla.authentication.authentication');
		jimport('joomla.user.authentication');
		$response->type = 'JOAuth';
		$isAuthed = $this->oauth_client->isAuthenticated();
		$this->credentials = $credentials = json_decode($this->oauth_client->query('https://www.googleapis.com/oauth2/v1/userinfo?alt=json')->body,true);

		if (JFactory::getApplication()->input->get('state',null)!='jauth' || !$credentials['verified_email'])
		{
			$response->status        = JAuthentication::STATUS_FAILURE;
			return;
		}else{
			$response->username = $credentials['email'];
			$response->email    = $credentials['email'];
			$response->fullname = $credentials['name'];
			$response->params   = json_encode(array('link'=>$credentials['link']));

			$response->status        = JAuthentication::STATUS_SUCCESS;
			$response->error_message = '';
		}
	}

	protected function registrationAllowed(){
		return $this->params->get('registrationallowed',true);
	}

	public function onUserAfterLogin($options){
		/** @var JUser $user */
		$user = $options['user'];
		$user->defParam('photo',$this->credentials['picture']);
		$user->defParam('link',$this->credentials['link']);
		$user->save(true);
	}

	public function onBeforeRender(){
		if(JFactory::getApplication()->isSite()){
			$doc = JFactory::getApplication()->getDocument();
			ob_start();
			?>
			jQuery(document).ready(function($){
				$('body').on('click','.jauth_button',function(){
					var form = $(this).closest('form');
					form.find('input[name="jauth"]').val('google');
					form.submit();
				});
			});
			<?php
			$script = ob_get_contents();
			ob_end_clean();
			$doc->addScriptDeclaration($script);

			ob_start();
			?><input name="jauth" type="hidden" value=""/> <button class="btn btn-danger jauth_button"><i class="fa fa-google"> </i> Login</button><?php
			$html = ob_get_contents();
			ob_end_clean();
			$html = addcslashes($html,"'\"");
			$doc->addStyleSheet('https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css');
			$doc->addScriptDeclaration("
				jQuery(document).ready(function($){
					$('input[name=\"task\"][value=\"user.login\"]')
					.closest('form').find('input[type=\"submit\"],button[type=\"submit\"]')
					.after('".$html."');
				});
			");
		}
	}

	public function onUserLogout($user, $options = array())
	{
		return true;
	}
}
