# CertChecker


[![Build Status](https://travis-ci.org/xiejiangzhi/cert_checker.svg?branch=master)](https://travis-ci.org/xiejiangzhi/cert_checker)
[![Gem Version](https://badge.fury.io/rb/cert_checker.svg)](https://badge.fury.io/rb/cert_checker)

A tool to check X509 cert status

## Installation

```
$ gem install cert_checker
```

## Command Line Usage


```
$ cert_checker
cert_checker [-d domain_or_ip] [-f hosts_file]
    -d host                          host name, example google.com. more host: -h h1.com -h h2.com
    -f file                          hosts file, split hosts by new line, and ignore line whice start by # and empt line
```

### Examples

```
$ cert_checker -d taobao.com -d xjz.pw
ok             taobao.com                          GlobalSign nv-sa     2019-11-13 344 days
ok             xjz.pw                              Let's Encrypt        2019-02-18 76 days

$ cat >> myhosts <<EOF
# A
xjz.pw

# B
taobao.com
jd.com
EOF

$ cert_checker -f myhosts
ok             xjz.pw                              Let's Encrypt        2019-02-18 76 days
ok             taobao.com                          GlobalSign nv-sa     2019-11-13 344 days
ok             jd.com                              GlobalSign nv-sa     2019-09-28 298 days
```

## Code Usage 

```
require 'cert_checker'

status, host, issuer, expired, desc = CertChecker.check('taobao.com')

# Other port and timeout
port = 443 # default
status, host, issuer, expired, desc = CertChecker.check('taobao.com', port, timeout: 5)
```

**Add your root cert**

```
CertChecker.cert_store.add_cert(root_ca)

# It will trust certs which signed by this root ca
status, host, issuer, expired, desc = CertChecker.check('mydomain.com', port, timeout: 3)
```

**Multiple cert store instance**

```
class MyChecker
  include CertChecker
end

MyChecker.cert_store.add_cert(root_ca)
status, host, issuer, expired, desc = MyChecker.check('mydomain.com', port, timeout: 3)
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/xiejiangzhi/cert_checker.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
