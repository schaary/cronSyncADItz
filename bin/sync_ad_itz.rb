
require 'thor'
require 'ruby-plsql'
require 'redis'
require 'net-ldap'
require 'awesome_print'
require 'digest/sha1'
require 'json'
require 'pry'
require 'active_support/core_ext'
require 'base64'
require 'securerandom'
require 'pry'

class SyncADItz < Thor

  SERVICE = self.name
  LDAP_CHECKSUM_SET = 'ad_itz:s_checksum_ldap_ad_itz'
  LDAP_UID_SET      = 'ad_itz:s_uid_ldap_ad_itz'
  LDAP_DN_BY_UID_HASH = 'ad_itz:h_dn_by_uid'
  UMT_CHECKSUM_SET  = 'ad_itz:s_checksum_umt'
  UMT_UID_SET       = 'ad_itz:s_uid_umt'
  UMT_ACCOUNT_BY_UID_HASH  = 'ad_itz:h_accounts_by_uid'
  UMT_ACCOUNT_BY_CHECKSUM_HASH  = 'ad_itz:h_accounts_by_checksum'

  desc 'new','add all missing accounts to the ldap'
  def new
    cleanup_redis_db
    fetch_umt
    fetch_ldap

    counter = 0
    missing_entries.each do |uid|
      counter += 1
      puts "#{counter}: #{uid}"

      write_new_entry uid
    end

    puts "Es wurden #{counter} neue Eintraege geschrieben"
  end

  desc "update","update ldap accounts"
  def update
    cleanup_redis_db
    fetch_umt
    fetch_ldap

    unless 0 == missing_entries.size
      puts "[ERROR] there are missing entries left."
      puts "[ERROR] run 'sync_ad_itz new' first"
      exit
    end

    counter = 0
    update_candidates.each do |checksum|
      counter += 1
      write_update_entry checksum
    end

    puts "Es wurden #{counter} Eintraege erneuert"
  end

private
  def connect_redis
    @redis ||= Redis.new
  end

  def connect_umt
    plsql.connection = OCI8.new(
      ENV.fetch('UMT_USER'),
      ENV.fetch('UMT_PASSWORD'),
      ENV.fetch('UMT_SID'))
  end

  def connect_ldap
    unless @ldap
      @ldap = Net::LDAP.new
      @ldap.host = ENV.fetch('AD_ITZ_HOST')
      @ldap.port = 636
      @ldap.encryption :simple_tls
      @ldap.auth ENV.fetch('AD_ITZ_USER'), ENV.fetch('AD_ITZ_PASSWORD')
    end
  end

  def cleanup_redis_db
    connect_redis
    @redis.del LDAP_CHECKSUM_SET
    @redis.del LDAP_UID_SET
    @redis.del LDAP_DN_BY_UID_HASH
    @redis.del UMT_CHECKSUM_SET
    @redis.del UMT_UID_SET
    @redis.del UMT_ACCOUNT_BY_CHECKSUM_HASH
    @redis.del UMT_ACCOUNT_BY_UID_HASH
  end

  def fetch_umt
    connect_umt
    connect_redis

    records = nil
    plsql.ad_itz_pkg.getAccounts { |cursor| records = cursor.fetch_all }

    records.each do |record|
      checksum = build_checksum record

      entry = {
        lastname:  record[0],
        firstname: record[1],
        nkz:       record[2],
        mail:      record[3],
        checksum:  checksum}

      @redis.hmset(
        UMT_ACCOUNT_BY_CHECKSUM_HASH,
        checksum,
        entry.to_json)

      @redis.hmset(
        UMT_ACCOUNT_BY_UID_HASH,
        entry[:nkz],
        entry.to_json)

      @redis.sadd UMT_CHECKSUM_SET, checksum
      @redis.sadd UMT_UID_SET, entry[:nkz]
    end
  end

  def fetch_ldap
    connect_ldap
    connect_redis

    filter = Net::LDAP::Filter.construct '(&(objectCategory=person)(objectClass=user))'
    basedn = 'dc=xd,dc=uni-halle,dc=de'
    attr = ['carLicense','sAMAccountName','dn']

    protected_user = [
      'admin',
      'Administrator',
      'krbtgt',
      'Gast',
      'UNI-HALLE.DE$',
      'TAC001'
    ]

    @ldap.search(base: basedn, filter: filter, attributes: attr) do |entry|
      unless protected_user.include? entry[:sAMAccountName][0]
        unless entry[:carLicense].empty?
          @redis.sadd LDAP_CHECKSUM_SET,entry[:carLicense][0]
        end
        @redis.sadd LDAP_UID_SET,entry[:sAMAccountName][0]
        @redis.hset LDAP_DN_BY_UID_HASH, entry[:sAMAccountName][0], entry[:dn][0]
      end
    end
  end

  def write_new_entry uid
    connect_ldap
    connect_redis
    entry = JSON.parse(
      @redis.hget UMT_ACCOUNT_BY_UID_HASH, uid).
      symbolize_keys

    dn = "cn=#{entry[:nkz]},ou=nutzer,dc=xd,dc=uni-halle,dc=de"
    attributes = {
      samaccountname:     entry[:nkz],
      sn:                 entry[:lastname],
      givenname:          entry[:firstname],
      cn:                 entry[:nkz],
      useraccountcontrol: "546",
      displayname:        "#{entry[:firstname]} #{entry[:lastname]}",
      userprincipalname:  "#{entry[:nkz]}@xd.uni-halle.de",
      carlicense:         entry[:checksum],
      mail:               "#{entry[:mail]}",
      objectClass: [
        "top",
        "person",
        "organizationalPerson",
        "user"]}

    unless @ldap.add dn: dn, attributes: attributes
      puts "Result: #{@ldap.get_operation_result.code}"
      puts "Message: #{@ldap.get_operation_result.message}"
    end

    operations = [[:add, :unicodepw, as_unicodepw(random_string)]]

    unless@ldap.modify dn: dn, operations: operations
      puts "Result: #{@ldap.get_operation_result.code}"
      puts "Message: #{@ldap.get_operation_result.message}"
    end
  end

  def write_update_entry checksum
    entry = get_account_by_checksum checksum

    dn = get_personal_dn entry[:nkz]

    operations = [
      [:replace, :givenname, entry[:firstname]],
      [:replace, :sn, entry[:lastname]],
      [:replace, :mail, entry[:mail]],
      [:replace, :cn, "#{entry[:firstname]} #{entry[:lastname]}"],
      [:replace, :carlicense, entry[:checksum]]]

    unless @ldap.modify dn: dn, operations: operations
      puts "Result: #{@ldap.get_operation_result.code}"
      puts "Message: #{@ldap.get_operation_result.message}"
    end

    puts "Eintrag geschrieben: #{entry[:nkz]}"
  end

  def get_account_by_checksum checksum
    JSON.parse(
      @redis.hget UMT_ACCOUNT_BY_CHECKSUM_HASH, checksum).
      symbolize_keys
  end

  def get_personal_dn uid
    @redis.hget LDAP_DN_BY_UID_HASH, uid
  end

  def missing_entries
    @redis.sdiff UMT_UID_SET, LDAP_UID_SET
  end

  def update_candidates
    @redis.sdiff UMT_CHECKSUM_SET, LDAP_CHECKSUM_SET
  end

  def as_unicodepw password
    result = "\"" + password + "\""
    Base64.encode64(
      result.chars.to_a.inject('') { |res, i| res += i.to_s + "\000" }).chomp
  end

  def random_string
    '!' + SecureRandom.hex(20).to_s +
    '+' + SecureRandom.hex(20).to_s.upcase +
    '#'
  end


  def build_checksum hash
    Digest::SHA1.hexdigest(
      hash.inject('') {|string,item| string + item.to_s})
  end
end

SyncADItz.start
