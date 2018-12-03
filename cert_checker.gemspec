
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "cert_checker/version"

Gem::Specification.new do |spec|
  spec.name          = "cert_checker"
  spec.version       = CertChecker::VERSION
  spec.authors       = ["jiangzhi.xie"]
  spec.email         = ["xiejiangzhi@gmail.com"]

  spec.summary       = %q{A tool to check host certs config}
  spec.description   = %q{A tool to check host certs config}
  spec.homepage      = "https://github.com/xiejiangzhi/cert_checker"
  spec.license       = "MIT"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.17"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "pry", ">= 0.10"
  spec.add_development_dependency "rubocop", "~> 0.60.0"
end
