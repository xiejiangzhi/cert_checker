RSpec.describe CertChecker do
  let(:tcp_server) { TCPServer.new('localhost', 0) }
  let(:host) { 'localhost' }
  let!(:time) { Time.at(Time.now.to_i).utc }
  let(:port) { tcp_server.local_address.ip_port }
  let(:root_key) { OpenSSL::PKey::RSA.new 2048 }
  let(:root_ca) do
    OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2
      c.serial = 1
      c.subject = OpenSSL::X509::Name.parse "/DC=org/DC=CertChecker/CN=CertChecker"
      c.issuer = c.subject
      c.public_key = root_key.public_key
      c.not_before = time - 3600
      c.not_after = time + 3600 * 24 * 100
      c.sign root_key, OpenSSL::Digest::SHA256.new
    end
  end
  let(:key) { OpenSSL::PKey::RSA.new 2048 }
  let(:cert) do
    OpenSSL::X509::Certificate.new.tap do |c|
      c.version = 2
      c.serial = 2
      c.subject = OpenSSL::X509::Name.parse "/DC=org/O=CertChecker/CN=CertChecker cert"
      c.issuer = root_ca.subject
      c.public_key = key.public_key
      c.not_before = time - 3600
      c.not_after = time + 3600 * 24 * 60
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = c
      ef.issuer_certificate = root_ca
      c.add_extension(ef.create_extension("subjectAltName", "DNS:localhost", false))
      c.sign root_key, OpenSSL::Digest::SHA256.new
    end
  end
  let(:ssl_ctx) do
    OpenSSL::SSL::SSLContext.new.tap do |ctx|
      ctx.key = key
      ctx.cert = cert
      ctx.alpn_select_cb = lambda { |ps| ps.first }
    end
  end
  let(:ssl_server) { OpenSSL::SSL::SSLServer.new(tcp_server, ssl_ctx) }

  before :each do
    CertChecker.instance_variable_set(:@cert_store, nil)
  end

  it "has a version number" do
    expect(CertChecker::VERSION).not_to be nil
  end

  describe 'get_cert' do
    around :each do |example|
      @ssl_thread = Thread.new { ssl_server.accept }
      example.run
      @ssl_thread.kill
    end

    it "should return cert" do
      c, cc = CertChecker.get_cert(host, port)
      expect(c.to_pem).to eql(cert.to_pem)
      expect(cc.map(&:to_pem)).to eql([c.to_pem])
    end

    it "should raise CertChecker::Error if get a network error" do
      [host, port]
      tcp_server.close
      expect {
        CertChecker.get_cert(host, port)
      }.to raise_error(CertChecker::Error)
    end

    it "should return nil if network timeout" do
      # server don't accpet request
      @ssl_thread.kill

      c, cc = CertChecker.get_cert(host, port)
      expect(c).to be_nil
      expect(cc).to be_nil
    end
  end

  describe 'verify' do
    it 'should verify cert by cert_store' do
      expect(CertChecker).to receive(:get_cert).with(host, port).and_return([cert, [cert]])
      expect(CertChecker.cert_store).to receive(:verify).with(cert, [cert]).and_call_original
      expect(CertChecker.verify(host, port)).to eql([
        cert, false, [cert], nil, "unable to get local issuer certificate"
      ])
    end

    it 'should return true if cert is believable' do
      expect(CertChecker).to receive(:get_cert).with(host, port).and_return([cert, [cert]])
      CertChecker.cert_store.add_cert(root_ca)
      expect(CertChecker.verify(host, port)).to eql([cert, true, [cert], nil])
    end

    it 'should return true if cert is believable' do
      allow(CertChecker).to receive(:get_cert).with(host, port).and_return(nil)
      expect(CertChecker.verify(host, port)).to eql(nil)
    end
  end

  describe 'check' do
    it 'should return cert info' do
      allow(Time).to receive(:now).and_return(time)
      allow(CertChecker).to receive(:get_cert).with(host, port).and_return([cert, [cert]])
      CertChecker.cert_store.add_cert(root_ca)
      expect(CertChecker.check(host, port)).to eql([
        :ok, "localhost", "CertChecker", time + 3600 * 24 * 60, 60
      ])
    end

    it 'should update status when time change' do
      allow(Time).to receive(:now).and_return(time + 3600 * 24 * 30)
      allow(CertChecker).to receive(:get_cert).with(host, port).and_return([cert, [cert]])
      CertChecker.cert_store.add_cert(root_ca)
      expect(CertChecker.check(host, port)).to eql([
        :warning, "localhost", "CertChecker", time + 3600 * 24 * 60, 30
      ])

      allow(Time).to receive(:now).and_return(time + 3600 * 24 * 50)
      expect(CertChecker.check(host, port)).to eql([
        :urgent, "localhost", "CertChecker", time + 3600 * 24 * 60, 10
      ])

      allow(Time).to receive(:now).and_return(time + 3600 * 24 * 60)
      expect(CertChecker.check(host, port)).to eql([
        :expired, "localhost", "CertChecker", time + 3600 * 24 * 60, 0
      ])

      allow(Time).to receive(:now).and_return(time + 3600 * 24 * 70)
      expect(CertChecker.check(host, port)).to eql([
        :expired, "localhost", "CertChecker", time + 3600 * 24 * 60, 0
      ])
    end

    it 'should return not match if domain is not match the cert' do
      allow(Time).to receive(:now).and_return(time)
      allow(CertChecker).to receive(:get_cert).and_return([cert, [cert]])
      CertChecker.cert_store.add_cert(root_ca)
      expect(CertChecker.check('127.0.0.1', port)).to eql([
        :not_match, "127.0.0.1", "CertChecker", time + 3600 * 24 * 60, 60
      ])
    end

    it 'should return unverifiable if cannot verify' do
      allow(Time).to receive(:now).and_return(time)
      allow(CertChecker).to receive(:get_cert).and_return([cert, [cert]])
      expect(CertChecker.check(host, port)).to eql([
        :unverifiable, host, "CertChecker", time + 3600 * 24 * 60,
        "unable to get local issuer certificate", nil
      ])
    end

    it 'should return failed status if failed to get a cert' do
      allow(CertChecker).to receive(:get_cert).with(host, port).and_return(nil)
      expect(CertChecker.check(host, port)).to eql([
        :failed, "localhost", nil, nil, nil
      ])
    end
  end
end
