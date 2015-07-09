require 'spec_helper'
require "logstash/filters/LDAPresolve"

describe LogStash::Filters::LDAPresolve do

  describe "check bind error" do
    let(:config) do <<-CONFIG
      filter {
        LDAPresolve {
          host    => "none.pasteur.fr"
          userdn  => "ou=utilisateurs,dc=pasteur,dc=fr"
          groupdn => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
          uidNumber     => 1234
        }
      }
    CONFIG
    end

    sample("test" => "test" ) do
      expect(subject).to include('tags')
      expect(subject["tags"]).to eq(["LDAP_ERR"])

    end
  end # bind test
   
#  describe "unknown uidNumber" do
#    let(:config) do <<-CONFIG
#      filter {
#        LDAPresolve {
#          host    => "ldap.pasteur.fr"
#          userdn  => "ou=utilisateurs,dc=pasteur,dc=fr"
#          groupdn => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
#          uidNumber     => 1234567890
#        }
#      }
#    CONFIG
#    end
#
#    sample("test" => "test" ) do
#      expect(subject).to include('user')
#      expect(subject["user"]).to eq('Unknown')
#      expect(subject).to include('group')
#      expect(subject["group"]).to eq('Unknown')
#      expect(subject).to include('tags')
#      expect(subject["tags"]).to eq(["LDAP_UNK_USER"])
#
#    end
#  end # end unknow uid
#
#  
#  describe "uidNumber with no associated group" do
#    let(:config) do <<-CONFIG
#      filter {
#        LDAPresolve {
#          host    => "ldap.pasteur.fr"
#          userdn  => "ou=utilisateurs,dc=pasteur,dc=fr"
#          groupdn => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
#          uidNumber     => 23865
#        }
#      }
#    CONFIG
#    end
#
#    sample("test" => "test") do
#      expect(subject).to include('user')
#      expect(subject["user"]).to eq('biomaj')
#      expect(subject).to include('group')
#      expect(subject["group"]).to eq('biomaj')
#      expect(subject).to include('tags')
#      expect(subject["tags"]).to eq(["LDAP_UNK_GROUP"])
#
#    end
#  end #end no group name user
#
#  describe "LDAP test" do
#    let(:config) do <<-CONFIG
#      filter {
#        LDAPresolve {
#          host    => "ldap.pasteur.fr"
#          userdn  => "ou=utilisateurs,dc=pasteur,dc=fr"
#          groupdn => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
#          use_ssl => false
#          uidNumber     => 7225
#        }
#      }
#    CONFIG
#    end
#
#    sample("test" => "test") do
#      expect(subject).to include('user')
#      expect(subject["user"]).to eq('Eric DEVEAUD')
#      expect(subject).to include('group')
#      expect(subject["group"]).to eq('CIB')
#      expect(subject).to include('login')
#      expect(subject["login"]).to eq('edeveaud')
#      expect(subject).to include('tags')
#      expect(subject["tags"]).to eq(["LDAP_OK"])
#
#    end
#  end #end LDAP test
#
#  describe "LDAPS test" do
#    let(:config) do <<-CONFIG
#      filter {
#        LDAPresolve {
#          host    => "ldap.pasteur.fr"
#          userdn  => "ou=utilisateurs,dc=pasteur,dc=fr"
#          groupdn => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
#          use_ssl => true
#          uidNumber     => 7225
#        }
#      }
#    CONFIG
#    end
#
#    sample("test" => "test") do
#      expect(subject).to include('user')
#      expect(subject["user"]).to eq('Eric DEVEAUD')
#      expect(subject).to include('group')
#      expect(subject["group"]).to eq('CIB')
#      expect(subject).to include('tags')
#      expect(subject["tags"]).to eq(["LDAP_OK"])
#
#    end
#  end # end LDAPS test

end
