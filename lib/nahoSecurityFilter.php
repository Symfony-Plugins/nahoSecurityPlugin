<?php

// Dynamic inheritance
eval(sprintf(
  'class BasenahoSecurityFilter extends %s { }', 
  sfConfig::get('app_nahoSecurityPlugin_filter_base_class', 'sfBasicSecurityFilter')
));

class nahoSecurityFilter extends BasenahoSecurityFilter
{

  /**
   * Executes this filter.
   *
   * @param sfFilterChain $filterChain A sfFilterChain instance
   */
  public function execute($filterChain)
  {
    // Handle "auto_credential" feature
    if (sfConfig::get('app_nahoSecurityPlugin_auto_credential', false))
    {
      
      $formats = sfConfig::get('app_nahoSecurityPlugin_auto_credential_format', array( 
        'application' => '%application%',
        'module'      => '%application%.%module%',
        'action'      => '%application%.%module%.%action%',
      ));
      
      $credentials = array_map(array($this, 'transformAutoCredential'), $formats);
      
      $access =
        // Access to this action is explicitely granted 
        (($access_action = $this->getAccess($credentials['action'])) === true)
        // No access defined for action, but access to module is explicitely granted 
        || (is_null($access_action) && ($access_module = $this->getAccess($credentials['module'])) === true)
        // No access defined for action or module, but access to application is explicitely granted 
        || (is_null($access_action) && is_null($access_module) && $this->getAccess($credentials['application']) === true);
      ;
      
      if (!$access)
      {
        $key = $this->getContext()->getUser()->isAuthenticated() ? 'secure' : 'login';
        $this->context->getController()->forward(sfConfig::get('sf_'.$key.'_module'), sfConfig::get('sf_'.$key.'_action'));
        
        throw new sfStopException();
      }

      $this->addCredential($credentials);
    }
    
    parent::execute($filterChain);
  }
  
  /**
   * Get current user's access to given resource by its credential
   * 
   * @param $credential
   * @return boolean|null
   */
  protected function getAccess($credential)
  {
    $negate = sfConfig::get('app_nahoSecurityPlugin_auto_credential_negate', '!');
    $user = $this->getContext()->getUser();

    if ($user->hasCredential($credential))
    {
      return true;
    }

    if ($user->hasCredential($negate.$credential))
    {
      return false;
    }

    return null;
  }
  
  /**
   * Transform a credential format into a real credential
   * 
   * @param $credential
   * @return string
   */
  protected function transformAutoCredential($credential)
  {
    return strtr($credential, array(
      '%action%'      => $this->getContext()->getActionName(),
      '%module%'      => $this->getContext()->getModuleName(),
      '%application%' => sfConfig::get('sf_app'),
    ));
  }
  
  /**
   * Add required credential to current action 
   * 
   * @param $credential
   */
  protected function addCredential($credential)
  {
    $action = $this->getContext()->getController()->getActionStack()->getLastEntry()->getActionInstance();
    
    $security = $action->getSecurityConfiguration();
    
    if (!isset($security['all']['credentials']))
    {
      $security['all']['credentials'] = array();
    }
    $security['all']['credentials'][] = $credential;
    
    $action->setSecurityConfiguration($security);
  }
  
}