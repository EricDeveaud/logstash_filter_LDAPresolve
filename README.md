# LDAPresolve Logstash Plugin

This is a plugin for [Logstash](https://github.com/elasticsearch/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

LDAPresolve filter will add to the event the fields *login*, *user* and *group* based on LDAP request 
 with provided uidNumber information.  and add *LDAP_OK* tag on success, otherwise error tag 
* *LDAP_ERR*: some LDAP connection or schema error
* *LDAP_UNK_USER*: unknow uidNumber 
* *LDAP_UNK_GROUP*: unknow group 

 This filter useby default LDAPS but can be configure to use plain LDAP.
 you can select the protocol you want to use via the use_ssl config setting

 As all filters, this filter only processes 1 event at a time, so using this plugin can 
 significantly slow down your pipeline's throughput if you have a high latency network.
 In order to reduce the slow down a cache mechanism is provided. 
 Cache holds the relevant information for a given uidNumber (full user name, group), and cache 
 entries are tagged with a timestamp of cache introduction
 Basicaly uidNumber is first searched using the cache on the cache, checked for the timestamp.
 if cache introduction time is older than persistence time then it is considered as not found and a LDAP
 request is performed and cache updated for this specific uidNumber.

 cache use and cache persistence time are adjustable form the config.

 LDAP tree naming and schema may vary. 
 You must specify the DN where to lookcup for user and group information
 User and group attributes are set to some reasonable values and are overwritable via the config
    user attributes : 'uid', 'gidNumber', 'givenName', 'sn'
    group attributes: 'dn'

 If uidNumber is not found in LDAP, for user and group are set to default values, eg: Unknown.

## Example

assume we have on LDAPS (with no authent) an user John DOE with uidNumber 25377 that pertains to group nobody
For example with following envent structure.
``` 
 {
     "@version" => "1",
   "@timestamp" => "2015-06-29:00:00.000Z",
   "some_infos" => 'foo bar"
 }
```

and the following init configuration 
``` 
LDAPresolve {
    uidNumber => 25377
    host      => "ldaps.pasteur.fr"
    userdn    => "ou=utilisateurs,dc=pasteur,dc=fr"
    groupdn   => "ou=entites,ou=groupes,dc=pasteur,dc=fr"
}
```

we will get this output
```
 {
     "@version" => "1",
   "@timestamp" => "2015-06-29:00:00.000Z",
   "some_infos" => 'foo bar"
         "user" => "John DOE"
        "group" => "nobody"
        "login" => "jdoe"
 }
```

# Usage

## 1 Installation

You can use the built-in plugin tool from Logstash to install the filter from https://rubygems.org/gems/logstash-filter-LDAPresolve

```
$LS_HOME/bin/plugin install logstash-filter-LDAPresolve
```

Or you can build it yourself:

```
git clone https://github.com/EricDeveaud/logstash_filter_LDAPresolve
cd logstash_filter_LDAPresolve
bundle install
bundle exec rspec
gem build logstash-filter-LDAPresolve.gemspec
$LS_HOME/bin/plugin install ./logstash-filter-rest-0.1.0.gem
```

## 2 Configuration

Add the following to the #filter# section of your logstash configuration 

#### mandatory elements
```sh
LDAPresolve {
    uidNumber  => 7225
    host       => "ldap.somewhere.org"
    userdn     => "ou=users,dc=somewhere,dc=org"
    groupdn    => "ou=groups,dc=somewhere,dc=org"
}
```

uidNumber can be dynamic and include parts of the event using the %{field} syntax.
eg assume we have the uidNumber previously stored in the envent's field 'uid'
We can then use 
```sh
LDAPresolve {
    uidNumber  => "%{uid}"
    host       => "ldap.somewhere.org"
    userdn     => "ou=users,dc=somewhere,dc=org"
    groupdn    => "ou=groups,dc=somewhere,dc=org"
}

```


#### auxiliary arguments

if your LDAP server use another port than the (339) default one 
```sh
    ldap_port  => 1234
```

if your LDAPS server use another port than the (636) default one 
```sh
   ldaps_port  => 1234
```

if you use a login//passord to log to your LDAP server
```sh
   username    => "some_loggin"
   passord     => "secretPassword"
```

if your LDAP use some specific attributes you can specify them for the filtering request
```sh
   userattrs   => ['attr1', 'attr2', ..] 
   groupattrs  => ['attr1', 'attr2', ..]
```

defaut atributes used by LDAPresolve are the following:
```sh
   userattrs => ['uid', 'gidNumber', 'givenName', 'sn'] that suits the posix account definitions.
   groupattrs  => ['dn']
```

## 3 Cache or not cache

LDAPresolve uses a basic cache mechanism by default. This cache mechanism can be disabled using the following configuration options

```sh
   usecache    => false
```

Cache retention is set by default to 300 second. you can change the cache retention duration using the following configuration options

```sh
   cache_interval => number_of_seconds 
```

# Contributing
All contributions are welcome: ideas, patches, documentation, bug reports, complaints, usggestions ... 




