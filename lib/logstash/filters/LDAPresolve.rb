# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# LDAPresolve filter will add to the event the fields 'login', 'user' and 'group' based on LDAP request 
# with provided uidNumber information. 
# and add LDAP_OK on success, otherwise  error tag s added to the event
#    LDAP_ERR: some LDAP connection or schema error
#    LDAP_UNK_USER: unknow uidNumber 
#    LDAP_UNK_GROUP: unknow group 
#
# This filter useby default LDAPS but can be configure to use plain LDAP.
# you can select the protocol you want to use via the use_ssl config setting
#
# As all filters, this filter only processes 1 event at a time, so using this plugin can 
# significantly slow down your pipeline's throughput if you have a high latency network.
# In order to reduce the slow down a cache mechanism is provided. 
# Cache holds the relevant information for a given uidNumber (full user name, group), and cache 
# entries are tagged with a timestamp of cache introduction
# Basicaly uidNumber is first searched using the cache on the cache, checked for the timestamp.
# if cache introduction time is older than persistence time then it is considered as not found and a LDAP
# request is performed and cache updated for this specific uidNumber.
#
# cache use and cache persistence time are adjustable form the config.
#
# LDAP tree naming and schema may vary. 
# You must specify the DN where to lookcup for user and group information
# User and group attributes are set to some reasonable values and are overwritable via the config
#    user attributes : 'uid', 'gidNumber', 'givenName', 'sn'
#    group attributes: 'dn'
#
# If uidNumber is not found in LDAP, for user and group are set to default values, eg: Unknown

class LogStash::Filters::LDAPresolve < LogStash::Filters::Base

  # configure this filter from your Logstash config.
  #
  # filter {
  #   LDAPresolve {
  #     uidNumber  => uidNumber to resolve
  #     host       => "my.LDAP.Server" 
  #     userdn     => "Domain Name to search for users information"
  #     groupdn    => "Domain Name to search for group information"
  #     ldap_port  => LDAP Server port (Default: 389)
  #     ldaps_port => LDAPS Server port (Default: 636)
  #     use_ssl    => boolean (Default: true)
  #     username   => "username to log on LDAP server" (Default '')
  #     password   => "password to log on the LDAP server" Default '')
  #   }
  # }
  #
  config_name "LDAPresolve"

  # uidNumber to resolve.
  config :uidNumber, :validate => :number, :required => true

  ##--- LDAP server specific configuration

  # LDAP host name
  config :host, :validate => :string, :required => true
  # LDAP//LDAPS port
  config :ldap_port, :validate => :number, :required => false, :default => 389
  config :ldaps_port, :validate => :number, :required => false, :default => 636
  # use SSL ?
  config :use_ssl, :validate => :boolean, :required => false, :default => false
  # LDAP username used to log to LDAP server
  config :username, :validate => :username, :required => false
  # LDAP password used to log to LDAP server
  config :password, :validate => :password, :required => false
  # as LDAP tree naming convention may vary, you must specify the dn to use for OU's user
  config :userdn, :validate => :string, :required => true 
  config :userattrs, :validate => :array, :required => false,  :default => ['uid', 'gidNumber', 'givenName', 'sn']
  # as LDAP tree naming convention may vary, you must specify the dn to use for OU's group
  config :groupdn, :validate => :string, :required => true 
  config :groupattrs, :validate => :array, :required => false, :default => ['dn']

  ##--- cache settings true//false and time of cache renewal in sec

  # shall we use caching true//false
  config :useCache, :validate => :boolean, :required => false, :default => true
  # cache persistence in second.
  config :cache_interval, :validate => :number, :required => false, :default => 300

  # assume we have on LDAPS (with no authent) an user John DOE with uidNumber 25377 that pertains to group nobody
  # For example with following envent structure.
  #  {
  #      "@version" => "1",
  #    "@timestamp" => "2015-06-29:00:00.000Z",
  #    "some_infos" => 'foo bar"
  #  }
  #
  # and the following init configuration 
  #
  # LDAPresolve {
  #     uidNumber => 25377
  #     host      => "ldaps.pasteur.fr"
  #     userdn    => "ou=utilisateurs,dc=pasteur,dc=fr"
  #     groupdn   => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
  # }
  # 
  # we will get this output
  #
  #  {
  #      "@version" => "1",
  #    "@timestamp" => "2015-06-29:00:00.000Z",
  #    "some_infos" => 'foo bar"
  #          "user" => "John DOE"
  #         "group" => "nobody"
  #  }
  #

  
  public
  def register
    require 'ldap'
    @cache = {}
    @DEFAULT = "Unknown"
    @SUCCESS = "LDAP_OK"
    @FAILURE = "LDAP_ERR"
    @UNKNOWN = "LDAP_UNK"
  end 

  public
  def filter(event)

    ## first check cache for provided uidNumber
    cached = false
    if @useCache
        cached = cached?(@uidNumber) 
    end

    if cached
        login, user , group = cached
    else
        @logger.info("prompt LDAP for #{@uidNumber} informations")
        if use_ssl
            conn = LDAP::SSLConn.new(host=@host, port=@ldaps_port)
        else
            conn = LDAP::Conn.new(host=@host, port=@ldap_port)
        end
        
        res = ldapsearch(conn, uidNumber)

        ##--- cache infos.
        cacheUID(@uidNumber, login, user, group)
    end 

    ##--- finaly change event to embed user and group information
    event["user"] = res['user']
    event["group"] = res['group']
    event["login"] = res['login']

    ##--- add LDAPresolve succes tag
    exitstatus = res['status']
    if event["tags"] 
        event["tags"] << exitstatus
    else
        event["tags"]=[exitstatus]
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter


  private

  def cached?(uidNumber)
    cached = @cache.fetch(uidNumber, false) 
    if cached and Time.now - cached[3] <= @cache_interval
        return cached[0], cached[1], cached[2]
    end
    return false
  end
        
  def cacheUID(uidNumber, login, user, group)
    @cache[uidNumber] = [login, user, group, Time.now]
  end 

  def ldapsearch(conn, uidNumber)
    ret = { 'login' => @DEFAULT, 'user'  => @DEFAULT, 'group' => @DEFAULT, 'status' => @SUCCESS, 'err' => "" }
    gid = 0

    begin 
        conn.bind(username, password) 
    rescue LDAP::Error => err
        @logger.error("Error: #{err.message}")
        ret['err'] = err
        ret['status']  = @FAILURE
        return ret
    end 


    # ok we bound, start search
    scope = LDAP::LDAP_SCOPE_SUBTREE 
    ##--- search LDAP for the user name
    begin
        conn.search(@userdn, scope, "(& (objectclass=posixAccount) (uidNumber=#{@uidNumber}))", @userattrs) { |entry|
            
            # convert entry object to hash for easier manipulation
            hashEntry = {}
            for k in entry.get_attributes
                hashEntry[k] = entry.vals(k).join(" ")
            end 
            # generate user full name.
            # in posix account we expect at least uid, gidNumber
            # givenName and sn may be ommited so provide default value 
            ret['user']  = "#{hashEntry.fetch("givenName", "")} #{hashEntry.fetch("sn", @DEFAULT)}".strip
            ret['login'] = "#{hashEntry.fetch("uid")}"
    
            # extract gid for further interogation
            gid = hashEntry.fetch("gidNumber", 0)
            match = 1
        }
    rescue LDAP::Error => err
        @logger.error("Error: #{err.message}")
        ret['err'] = err
        ret['status']  = @FAILURE
        return ret
    end 

    if ret['user'] == @DEFAULT
        ret['status'] = "#{@UNKNOWN}_USER"
        return ret
    end    

    ##--- search for GROUP name
    filter = "(& (objectclass=posixGroup) (gidNumber=#{gid}))" 
    begin
        conn.search(@groupdn, scope, filter, @groupattrs) { |entry|
            ret['group'] = entry.dn.split(',')[0].split('=')[1]
        }
    rescue LDAP::Error => err
        @logger.error("Error: #{err.message}")
        ret['err'] = err
        ret['status']  = @FAILURE
        return ret
    end

    if ret['group'] == @DEFAULT
        ret['status'] = "#{@UNKNOWN}_GROUP"
        ret['group'] =ret['user']
        return ret
    end
 
    return ret
  end 
end # class LogStash::Filters::LDAPresolve
