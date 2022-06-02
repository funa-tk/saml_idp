require 'builder'
require 'saml_idp/algorithmable'
require 'saml_idp/signable'
module SamlIdp
  class MetadataLoader
    attr_accessor :sp_metadata

    def initialize(sp_metadata)
      self.sp_metadata = if sp_metadata.is_a?(String)
                           IncomingMetadata.new(sp_metadata)
                         else
                           PersistedMetadata.new(sp_metadata)
                         end
    end

    def configure_idp
      SamlIdp.configure do |config|
        config.x509_certificate = certificate
        config.secret_key = secret_key
        config.password = password
        config.algorithm = :sha256
        config.organization_name = group.name
        config.organization_url = group.name
        config.base_saml_location = url_helper.base
        config.single_logout_service_post_location = url_helper.post_logout
        config.single_logout_service_redirect_location = url_helper.redirect_logout
        config.attribute_service_location = url_helper.attribute_endpoint
        config.single_service_post_location = url_helper.sso_post
        config.single_service_redirect_location = url_helper.sso_post
        config.name_id.formats = generate_name_id_format
        config.attributes = generate_saml_attributes
        config.service_provider.metadata_persister = metadata_persister
        config.service_provider.persisted_metadata_getter = persisted_matadata
        config.service_provider.finder = service_providers
      end
    end

    def get_configuration
      {
        entity_id: entity_id,
        assertion_consumer_services: acs_url,
        name_id_formats: name_id_formats,
        single_logout_services: single_logout_services,
        sign_assertions: want_assertion_signed,
        auth_request_signed: auth_request_signed,
        display_name: '',
        contact_person: {
          given_name: '',
          surname: '',
          company: '',
          telephone_number: '',
          email_address: ''
        },
        signing_certificate: signing_certificate,
        encryption_certificate: encryption_certificate
      }
    end

    def acs_url
      sp_metadata.assertion_consumer_services.pluck[:location]
    end
    private :acs_url

    def entity_id
      sp_metadata.entity_id
    end
    private :acs_url

    def name_id_formats
      Array.wrap(sp_metadata.name_id_formats)
    end
    private :name_id_formats

    def want_assertion_signed
      sp_metadata.sign_assertions
    end
    private :want_assertion_signed

    def auth_request_signed
      sp_metadata.sign_authn_request
    end
    private :auth_request_signed

    def signing_certificate
      sp_metadata.signing_certificate
    end
    private :signing_certificate

    def encryption_certificate
      sp_metadata.encryption_certificate
    end
    private :encryption_certificate

    def single_logout_services
      sp_metadata.single_logout_services
    end
    private :single_logout_services
  end
end
