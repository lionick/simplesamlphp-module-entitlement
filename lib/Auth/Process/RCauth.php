<?php


/**
 * Attribute filter to evaluate entitlement for access to RCauth.eu CA.
 *
 */
class sspmod_entitlement_Auth_Process_RCauth extends SimpleSAML_Auth_ProcessingFilter
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
        // OBSOLETE 'urn:mace:egi.eu:aai.egi.eu:rcauth',
        'urn:mace:egi.eu:res:rcauth#aai.egi.eu',
    );


    /**
     * List of entity IDs qualifying for this entitlement.
     */
    private $entityIds = array(
        // Production
        'https://sso.egi.eu/edugainidp/shibboleth',
        //'https://idp.admin.grnet.gr/idp/shibboleth',
        // Devel
        //'https://vho.grnet.gr/idp/shibboleth',
    );


    /**
     * Combination of entity attributes qualifying for this entitlement.
     */
    private $entityAttributes = array(
        'http://macedir.org/entity-category-support' => array(
            'http://refeds.org/category/research-and-scholarship',
        ),
        'urn:oasis:names:tc:SAML:attribute:assurance-certification' => array(
            'https://refeds.org/sirtfi',
        ),
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

        if (!$this->isValidIdP($state)) {
            return;
        }
        if (empty($state['Attributes'][$this->attribute])) {
            $state['Attributes'][$this->attribute] = array();
        }
        $state['Attributes'][$this->attribute] = array_merge($state['Attributes'][$this->attribute], $this->entitlement);
    }


    private function isValidIdP($state)
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
        SimpleSAML_Logger::debug("[entitlement:RCauth] IdP="
            . var_export($idpEntityId, true));
        if (in_array($idpEntityId, $this->entityIds)) {
            return true;
        }
        if (!empty($idpMetadata['EntityAttributes']) && empty($this->getEntityAttributesDiff($this->entityAttributes, $idpMetadata['EntityAttributes']))) {
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
