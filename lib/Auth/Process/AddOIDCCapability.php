<?php

namespace SimpleSAML\Module\entitlement\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;

/**
 * Attribute filter for evaluating the resources capabilities of the
 * authenticating user. A capability defines the resource or child-resource the
 * user is allowed to access, optionally specifying certain actions the user is
 * entitled to perform. Capabilities can be used to convey – in a compact form –
 * authorisation information. Capability values are formatted as URNs following
 * the syntax specified in https://aarc-community.org/guidelines/aarc-g027
 *
 * Example config
 * 'client_id' => [
 *     'class' => 'entitlement:AddCapability',
 *     'attributeName' => "eduPersonEntitlement",
 *     'capability' => [
 *         'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org',
 *     ],
 *     'idpWhitelist' => [ // or idpBlacklist
 *         'https://idp.example1.org/entityId',
 *         'https://idp.example2.org/entityId',
 *     ],
 *     'entityAttributeWhitelist' => [
 *         'http://macedir.org/entity-category-support' => [
 *             'http://refeds.org/category/research-and-scholarship',
 *         ],
 *         'urn:oasis:names:tc:SAML:attribute:assurance-certification' => [
 *             'https://refeds.org/sirtfi',
 *         ],
 *     ],
 *     'entitlementWhitelist' => [
 *         'urn:mace:idp.example.org:group:another.vo.example.org:role=member#bar.example.org',
 *     ],
 * ],
 */
class AddCapability extends ProcessingFilter
{

    /**
     * The attribute that will hold the capability value(s).
     * @var string
     */
    private $attributeName = 'eduPersonEntitlement';


    /**
     * The assigned capability value(s).
     * @var string
     */
    private $capability = [];


    /**
     * List of IdP entity IDs excluded from this capability.
     */
    private $idpBlacklist = [];


    /**
     * List of IdP entity IDs qualifying for this capability.
     */
    private $idpWhitelist = [];


    /**
     * Combination of entity attributes qualifying for this capability.
     */
    private $entityAttributeWhitelist = [];


    /**
     * List of user entitlements qualifying for this capability.
     */
    private $entitlementWhitelist = [];

    /**
     *  Keycloak Sp
     */
    private $keycloakSp;

    /**
     *  Client Ids
     */
    private $client_ids;

    /**
     * Initialize this filter, parse configuration
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML\Error\Exception if the mandatory 'accepted' configuration option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('keycloakSp', $config)) {
            if (!is_string($config['keycloakSp'])) {
                Logger::error(
                    "[AddOIDCCapability] Configuration error: 'keycloakSp' not an string"
                );
                throw new \Exception(
                    "[AddOIDCCapability] configuration error: 'keycloakSp' not an string"
                );
            }
            $this->keycloakSp = $config['keycloakSp'];
        }
        //Initialize client_ids variable
        $this->client_ids = [];
        foreach ($config['clients'] as $client_id => $client_config) {

            if (array_key_exists('attributeName', $client_config)) {
                if (!is_string($client_config['attributeName'])) {
                    Logger::error("[AddOIDCCapability] Configuration error: 'attributeName' not a string literal");
                    throw new Exception("AddOIDCCapability configuration error: 'attributeName' not a string literal");
                }
                $this->attributeName[$client_id] = $client_config['attributeName'];
            }

            if (array_key_exists('capability', $client_config)) {
                if (!is_array($client_config['capability'])) {
                    Logger::error("[AddOIDCCapability] Configuration error: 'capability' not a string literal");
                    throw new Exception("AddOIDCCapability configuration error: 'capability' not a string literal");
                }
                $this->capability[$client_id] = $client_config['capability'];
            }

            if (array_key_exists('idpBlacklist', $client_config)) {
                if (!is_array($client_config['idpBlacklist'])) {
                    Logger::error("[AddOIDCCapability] Configuration error: 'idpBlacklist' not a string literal");
                    throw new Exception("AddOIDCCapability configuration error: 'idpBlacklist' not a string literal");
                }
                $this->idpBlacklist[$client_id] = $client_config['idpBlacklist'];
            }

            if (array_key_exists('idpWhitelist', $client_config)) {
                if (!is_array($client_config['idpWhitelist'])) {
                    Logger::error("[AddOIDCCapability] Configuration error: 'idpWhitelist' not a string literal");
                    throw new Exception("AddOIDCCapability configuration error: 'idpWhitelist' not a string literal");
                }
                $this->idpWhitelist[$client_id] = $client_config['idpWhitelist'];
            }

            if (array_key_exists('entityAttributeWhitelist', $client_config)) {
                if (!is_array($client_config['entityAttributeWhitelist'])) {
                    Logger::error(
                        "[AddOIDCCapability] Configuration error: 'entityAttributeWhitelist' not a string literal"
                    );
                    throw new Exception(
                        "AddOIDCCapability configuration error: 'entityAttributeWhitelist' not a string literal"
                    );
                }
                $this->entityAttributeWhitelist[$client_id] = $client_config['entityAttributeWhitelist'];
            }

            if (array_key_exists('entitlementWhitelist', $client_config)) {
                if (!is_array($client_config['entitlementWhitelist'])) {
                    Logger::error(
                        "[AddOIDCCapability] Configuration error: 'entitlementWhitelist' not a string literal"
                    );
                    throw new Exception("AddOIDCCapability configuration error: 'entitlementWhitelist' not a string literal");
                }
                $this->entitlementWhitelist[$client_id] = $client_config['entitlementWhitelist'];
            }
            // Add client_id to the array
            $this->client_ids[]=$client_id;
        }
        
    }


    /**
     *
     * @param array &$state The current SP state
     */
    public function process(&$state)
    {
        assert('is_array($state)');

        $client_id = null;

        if (!empty($state['saml:RelayState']) 
          && !empty($this->keycloakSp) 
          && $state['Destination']['entityid'] == 
                    $this->keycloakSp) {
          $client_id = explode('.', $state['saml:RelayState'], 3)[2];
          if(empty($client_id)) {
            throw new Error\Error(
                ['UNHANDLEDEXCEPTION', 'Could not extract client ID from saml:RelayState']
            );  
          }
        } else if(!empty($state['saml:RelayState'])) {
          $client_id = $state['saml:RelayState'];
        } else {
          throw new Error\Error(
              ['UNHANDLEDEXCEPTION', 'Request missing saml:RelayState']
          );
        }
        

        // Check if client_id exists in module configuration
        if (in_array($client_id, $this->client_ids)) {
            if (!$this->isQualified($state, $client_id)) {
                return;
            }
            if (empty($state['Attributes'][$this->attributeName[$client_id]])) {
                $state['Attributes'][$this->attributeName[$client_id]] = [];
            }
            $state['Attributes'][$this->attributeName[$client_id]] = array_merge(
                $state['Attributes'][$this->attributeName[$client_id]],
                $this->capability[$client_id]
            );
            Logger::debug("[AddOIDCCapability] Adding capability " . var_export($this->capability, true));
        }  
       
    }


    private function isQualified($state, $client_id)
    {
        assert('array_key_exists("entityid", $state["Source"])');

        // If the entitlement module is active on a bridge $state['saml:sp:IdP']
        // will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpMetadata = MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $state['Source']['entityid'];
            $idpMetadata = $state['Source'];
        }
        Logger::debug("[AddOIDCCapability] IdP="
            . var_export($idpEntityId, true));
        if (!empty($this->idpBlacklist[$client_id]) && in_array($idpEntityId, $this->idpBlacklist[$client_id])) {
            return false;
        }
        if (!empty($this->idpWhitelist[$client_id]) && in_array($idpEntityId, $this->idpWhitelist[$client_id])) {
            return true;
        }
        if (
            !empty($idpMetadata['EntityAttributes'])
            && empty($this->getEntityAttributesDiff($this->entityAttributeWhitelist[$client_id], $idpMetadata['EntityAttributes']))
        ) {
            return true;
        }
        if (
            !empty($state['Attributes'][$this->attributeName[$client_id]])
            && !empty(array_intersect($state['Attributes'][$this->attributeName[$client_id]], $this->entitlementWhitelist[$client_id]))
        ) {
            return true;
        }
        return false;
    }


    private function getEntityAttributesDiff($array1, $array2)
    {
        $diff = [];
        foreach ($array1 as $key => $value) {
            if (empty($array2[$key]) || !is_array($array2[$key])) {
                $diff[$key] = $value;
            } else {
                $newDiff = array_diff($value, $array2[$key]);
                if (!empty($newDiff)) {
                    $diff[$key] = $newDiff;
                }
            }
        }
        return $diff;
    }
}
