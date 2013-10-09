<?php
/**
 * Adding external authentication for a password reset form
 */
class AuthPasswordReset extends Controller {
	private static $allowed_actions = array( 
		'lostpassword',
		'LostPasswordForm',
		'ChangePasswordForm',
		'changepassword'
	);

	/**
	 * Factory method for the lost password form
	 *
	 * @return Form Returns the lost password form
	 */
	public function LostPasswordForm() {
		$fields = new FieldList(
			new EmailField('Email', _t('Member.EMAIL', 'Email'))
		);
		$actions = new FieldList(
			new FormAction('forgotPassword', 
				_t('Security.BUTTONSEND', 'Send me the password reset link')
			)
		);
		// need to add validation for the details
		return new Form($this, 'LostPasswordForm', $fields, $actions);
	}

	/**
	 * Show the "lost password" page
	 *
	 * @return string Returns the "lost password" page as HTML code.
	 */
	public function lostpassword() {
		if(class_exists('SiteTree')) {
			$tmpPage = new Page();
			$tmpPage->Title = _t('Security.LOSTPASSWORDHEADER', 'Lost Password');
			$tmpPage->URLSegment = 'Security';
			$tmpPage->ID = -1; // Set the page ID to -1 so we dont get the top level pages as its children
			$controller = Page_Controller::create($tmpPage);
			$controller->init();
		} else {
			$controller = $this;
		}

		// if the controller calls Director::redirect(), this will break early
		if(($response = $controller->getResponse()) && $response->isFinished()) return $response;

		$customisedController = $controller->customise(array(
			'Content' => 
				'<p>' . 
				_t(
					'Security.NOTERESETPASSWORD', 
					'Enter your e-mail address and we will send you a link with which you ' . 
						'can reset your password'
				) . 
				'</p>',
			'Form' => $this->LostPasswordForm(),
		));
		
		//Controller::$currentController = $controller;
		return $customisedController->renderWith(
			array('Security_lostpassword', 'Security', $this->stat('template_main'), 'Page')
		);
	}

	/**
	 * Forgot password form handler method
	 *
	 * This method is called when the user clicks on "I've lost my password"
	 *
	 * @param array $data Submitted data
	 */
	public function forgotPassword($data) {
		$SQL_data = Convert::raw2sql($data);
		$SQL_email = $SQL_data['Email'];
		$member = DataObject::get_one('Member', "\"Email\" = '{$SQL_email}'");

		if($member) {
			$token = $member->generateAutologinTokenAndStoreHash();
			$passwordResetLink = Security::getPasswordResetLink($member, $token);

			$e = Member_ForgotPasswordEmail::create();
			$e->populateTemplate($member);
			$e->populateTemplate(array(
				'PasswordResetLink' => $this->getPasswordResetLink($member, $token)
			));
			$e->setTo($member->Email);
			$e->send();

			Controller::redirect('Security/passwordsent/' . urlencode($data['Email']));
		} elseif($data['Email']) {
			// Avoid information disclosure by displaying the same status,
			// regardless wether the email address actually exists
			$this->controller->redirect('Security/passwordsent/' . urlencode($data['Email']));
		} else {
			$this->sessionMessage(
				_t('Member.ENTEREMAIL', 'Please enter an email address to get a password reset link.'),
				'bad'
			);
			
			Controller::redirect('Security/passwordsent/' . urlencode($data['Email']));
		}
	}

	public function changepassword() {
		if(class_exists('SiteTree')) {
			$tmpPage = new Page();
			$tmpPage->Title = _t('Security.CHANGEPASSWORDHEADER', 'Change your password');
			$tmpPage->URLSegment = 'Security';
			$tmpPage->ID = -1; // Set the page ID to -1 so we dont get the top level pages as its children
			$controller = Page_Controller::create($tmpPage);
			$controller->init();
		} else {
			$controller = $this;
		}

		// if the controller calls Director::redirect(), this will break early
		if(($response = $controller->getResponse()) && $response->isFinished()) return $response;

		// Extract the member from the URL.
		$member = null;
		if (isset($_REQUEST['m'])) {
			$member = Member::get()->filter('ID', (int)$_REQUEST['m'])->First();
		}

		// Check whether we are merely changin password, or resetting.
		if(isset($_REQUEST['t']) && $member && $member->validateAutoLoginToken($_REQUEST['t'])) {
			Session::set('AutoLoginHash', $member->encryptWithUserSettings($_REQUEST['t']));
			
			$customisedController = $controller->customise(array(
				'Content' => '<p>' 
					. _t('Security.CHANGEPASSWORDBELOW', 'You can change your password below.')
						 . '</p>',
				'Form' => $this->ChangePasswordForm($_REQUEST['t'], $member)));

		} else {
			// show an error message if the auto login token is invalid and the
			// user is not logged in
				$customisedController = $controller->customise(
					array('Content' =>
						_t(
							'Security.NOTERESETLINKINVALID',
							'<p>The password reset link is invalid or expired.</p>'
							. '<p>You can request a new one <a href="{link1}">here</a> ' . '
								or change your password after'
							. ' you <a href="{link2}">logged in</a>.</p>',
							array('link1' => $this->Link('lostpassword'),
								'link2' => $this->link('login')
							)
						)
					)
				);
		}

		return $customisedController->renderWith(
			array('Security_changepassword', 'Security', $this->stat('template_main'), 'Page')
		);
	}

	public function ChangePasswordForm($token, $member = '') {
		$memberID = (isset($memebr->ID)) ? $memebr->ID : 0;
		if(isset($_REQUEST['BackURL'])) {
			$backURL = $_REQUEST['BackURL'];
		} else {
			$backURL = Session::get('BackURL');
		}
		$fields = new FieldList();
			
		$fields->push(new PasswordField("NewPassword1", _t('Member.NEWPASSWORD', "New Password")));
		$fields->push(new PasswordField("NewPassword2", _t('Member.CONFIRMNEWPASSWORD',
			"Confirm New Password")));
		$fields->push(new HiddenField('token', 'token', $token));
		$fields->push(new HiddenField('member', 'member', $memberID));
		$actions = new FieldList(
			new FormAction("doChangePassword", _t('Member.BUTTONCHANGEPASSWORD', "Change Password"))
		);
		return new Form($this, 'ChangePasswordForm', $fields, $actions);
	}

	public function doChangePassword($data) {
		if(isset($data['token']) && $token = $data['token']) {
			$member = Member::member_from_autologinhash($token, true);
			Session::set('AutoLoginHash', $token);
		}

		// The user is not logged in and no valid auto login hash is available
		if(!$member) {
			Session::clear('AutoLoginHash');
			$this->controller->redirect('loginpage');
			return;
		}
		// are we changing the password
		// validation is performed here as it is external authentication will be hard to validate if the password is valid
		if (isset($data['NewPassword1'])) {

			$password = $data['NewPassword1'];
			$confirmPassword = (isset($data['NewPassword2']) ? $data['NewPassword2'] : '';
			if (($password == $confirmPassword) && (isset($member) && is_object($member))) {
				if ($password != $confirmPassword) {
					$this->clearMessage();
					$this->sessionMessage(
						_t('Member.ERRORNEWPASSWORD', "You have entered your new password differently, try again"),
						"bad");

					// redirect back to the form, instead of using redirectBack() which could send the user elsewhere.
					$this->controller->redirect($this->controller->Link('changepassword'));
				}
				$member->setAuthenticator();
				$auth = $member->getAuthenticator();
				$auth->login();
				$ldap = $auth->ldapLinkIdentifier;

				$newPassword = "\"" . $password . "\"";
				$newPassw = '';
				$len = strlen($newPassword);
				for ($i = 0; $i < $len; $i++) $newPassw .= "{$newPassword{$i}}\000";
				$newPassword = $newPassw;
				$passwordChange["unicodePwd"] = $newPassword;
				$result = ldap_mod_replace($ldap, $member->External_DN, $passwordChange);
				if (!$result) {
					$form->sessionMessage(
						'Could not change password.',
						'bad'
					);
					//Error changing password
					//SS_Log::log(new Exception(print_r('could NOT change the password',
						 //true)), SS_Log::NOTICE);
				} else {
					$formMessage = 'Details were saved and password has been changed.';
				}
			}
		} else {
			$this->clearMessage();
			$this->sessionMessage(
				_t('Member.EMPTYNEWPASSWORD', "The new password can't be empty, please try again"),
				"bad");

			// redirect back to the form, instead of using redirectBack() which could send the user elsewhere.
			$this->controller->redirect($this->controller->Link('changepassword'));
		}
		Controller::redirect('');
	}

	public static function getPasswordResetLink($member, $autologinToken) {
		$autologinToken = urldecode($autologinToken);
		return 'AuthPasswordReset/changepassword' . "?m={$member->ID}&t=$autologinToken";
	}
}
