<?php


/**
 * Attribute filter to evaluate entitlement for access to GGUS.
 *
 */
class sspmod_entitlement_Auth_Process_GGUS extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The attribute that will hold the entitlement value.
     * @var string
     */
    private $attribute = 'eduPersonEntitlement';


    /**
     * The assigned entitlement value.
     * @var string
     */
    private $entitlement = array(
        'urn:mace:egi.eu:aai.egi.eu:helpdesk',
        'urn:mace:egi.eu:res:helpdesk#aai.egi.eu',
    );


    /**
     * List of IdP entity IDs excluded from this entitlement.
     */
    private $idpBlacklist = array(
        // Production
        // Devel
    );


    /**
     * List of IdP entity IDs qualifying for this entitlement.
     */
    private $idpWhitelist = array(
        // Production
        'https://sso.egi.eu/edugainidp/shibboleth',
        'https://idp.admin.grnet.gr/idp/shibboleth',
        // Devel
        //'https://vho.grnet.gr/idp/shibboleth',
        'https://www.egi.eu/idp/shibboleth',
    );


    /**
     * Combination of entity attributes qualifying for this entitlement.
     */
    private $minEntityAttributes = array(
        //'http://macedir.org/entity-category-support' => array(
        //    'http://refeds.org/category/research-and-scholarship',
        //),
        'urn:oasis:names:tc:SAML:attribute:assurance-certification' => array(
            'https://refeds.org/sirtfi',
        ),
    );


    /**
     * List of user entitlements qualifying for this entitlement.
     */
    private $entitlementWhitelist = array(
        // Production
        'urn:mace:egi.eu:elixir-europe.org:member@vo.elixir-europe.org',
        'urn:mace:egi.eu:group:vo.elixir-europe.org:role=member#elixir-europe.org',
        // Devel
        //'urn:mace:grnet.gr:faai:vo:vo.elixir-europe.org:role:member',
    );


    /**
     * Initialize this filter, parse configuration
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML_Error_Exception if the mandatory 'accepted' configuration option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
    }


    /**
     *
     * @param array &$state The current SP state
     */
    public function process(&$state)
    {
        assert('is_array($state)');

        if (!$this->isQualified($state)) {
            return;
        }
        if (empty($state['Attributes'][$this->attribute])) {
            $state['Attributes'][$this->attribute] = array();
        }
        $state['Attributes'][$this->attribute] = array_merge($state['Attributes'][$this->attribute], $this->entitlement);
    }


    private function isQualified($state)
    {
        assert('array_key_exists("entityid", $state["Source"])');

        // If the entitlement module is active on a bridge $state['saml:sp:IdP']
        // will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpMetadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $state['Source']['entityid'];
            $idpMetadata = $state['Source'];
        }
        SimpleSAML_Logger::debug("[entitlement:GGUS] IdP="
            . var_export($idpEntityId, true));
        if (in_array($idpEntityId, $this->idpBlacklist)) {
            return false;
        }
        if (in_array($idpEntityId, $this->idpWhitelist)) {
            return true;
        }
        if (!empty($idpMetadata['EntityAttributes']) && empty($this->getEntityAttributesDiff($this->minEntityAttributes, $idpMetadata['EntityAttributes']))) {
            return true;
        }
        if (!empty($state['Attributes'][$this->attribute]) && !empty(array_intersect($state['Attributes'][$this->attribute], $this->entitlementWhitelist))) {
            return true;
        }
        return false;
    }


    private function getEntityAttributesDiff($array1, $array2) 
    {   
        $diff = array();
        foreach ($array1 as $key => $value) {
           if (empty($array2[$key]) || !is_array($array2[$key])) {
               $diff[$key] = $value;
           } else {
               $new_diff = array_diff($value, $array2[$key]);
               if (!empty($new_diff)) {
                   $diff[$key] = $new_diff;
               }
           }
        }
        return $diff;
    }

}
