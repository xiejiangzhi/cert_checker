# frozen_string_literal: true

require "cert_checker/version"

require 'socket'
require 'openssl'

module CertChecker
  extend self

  class Error < StandardError; end

  DEFAULT_TIMEOUT = 5
  ONE_DAY = 3600.0 * 24

  def get_cert(host, port = 443, timeout: DEFAULT_TIMEOUT)
    tcp_client = Socket.tcp(host, port, connect_timeout: timeout)
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.hostname = host

    begin
      ssl_client.connect_nonblock
    rescue IO::WaitReadable
      retry if IO.select([ssl_client], nil, nil, timeout)
    rescue IO::WaitWritable
      retry if IO.select(nil, [ssl_client], nil, timeout)
    end

    [ssl_client.peer_cert, ssl_client.peer_cert_chain].tap do
      ssl_client.close
      tcp_client.close
    end
  rescue SocketError, SystemCallError, OpenSSL::SSL::SSLError => e
    raise CertChecker::Error.new("Failed to get cert of #{host}:#{port}. #{e.inspect}")
  end

  # @return [cert, verify_result, cert_chain, err_str]
  def verify(host, *args)
    cert, cert_chain = get_cert(host, *args)
    if cert
      err = nil
      result = cert_store.verify(cert, cert_chain) { |r, s| err = s.error_string unless r; r }
      [cert, result, cert_chain, err]
    end
  end

  # @return [status_symbol, host, issuer, expired_at, desc]
  def check(host, *args)
    cert, verify_result, _cert_chain, err_str = verify(host, *args)
    return [:failed, host, nil, nil, nil] unless cert
    status_sym = :unverifiable unless verify_result

    issuer = get_cert_issuer_name(cert)
    expired_at = cert.not_after
    valid_days = ((cert.not_after - Time.now) / ONE_DAY).floor
    valid_days = 0 if valid_days < 0
    desc = err_str || valid_days

    status_sym ||= :not_match unless verify_cert_dns(host, cert)
    status_sym ||= if expired_at <= Time.now then :expired
    elsif expired_at <= Time.now + 15 * ONE_DAY then :urgent
    elsif expired_at <= Time.now + 30 * ONE_DAY then :warning
    else :ok
    end

    [status_sym, host, issuer, expired_at, desc]
  end

  def cert_store
    @cert_store ||= OpenSSL::X509::Store.new.tap do |store|
      store.set_default_paths
    end
  end

  private

  def verify_cert_dns(host, cert)
    dns_ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
    dns = dns_ext.value.split(',').map { |d| d.split(':').last }
    !dns.all? { |d| !(Regexp.new('\A' + d.gsub('*', '.+') + '\z') =~ host) }
  end

  def get_cert_issuer_name(cert)
    issuer_names = cert.issuer.to_a
    (
      issuer_names.find { |name, data, type| name == 'O' } ||
      issuer_names.find { |name, data, type| name == 'CN' }
    )[1]
  end
end
