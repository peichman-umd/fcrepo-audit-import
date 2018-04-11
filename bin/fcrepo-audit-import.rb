require 'java'
require 'rainbow'
require 'socket'
require 'main'

class FileNotFound < StandardError; end

# Our default values
hostname = Socket.gethostname.chomp
source_url = "https://#{hostname}/fcrepo/rest/audit"
target_url = "https://#{hostname}/fuseki/testing/data"
keystore = "/apps/fedora/ssl/backup-client.p12"
password = "changeme"
threads = 5

if STDIN.isatty
  # if STDIN is a terminal, present prompts
  # otherwise, use defaults
  puts Rainbow("*" * 100 ).red
  puts Rainbow("*" * 100 ).red
  puts Rainbow("*" * 100 ).red

  print Rainbow("Enter source URL").white.bg(:red) + "  " + Rainbow("[#{source_url}] > ").cyan
  input = gets.chomp
  source_url = input if input.length > 0

  print Rainbow("Enter target URL").white.bg(:red) + "  " + Rainbow("[#{target_url}] > ").cyan
  input = gets.chomp
  target_url = input if input.length > 0

  begin
    print Rainbow("Enter java keystore file path").white.bg(:red) + "  " + Rainbow("[#{keystore}] > ").cyan.blink
    input = gets.chomp
    _ks = input.length > 0 ? input : keystore
    raise FileNotFound unless File.exists?(_ks)
  rescue FileNotFound
    puts Rainbow("File #{_ks} not found. Please try again").red
    retry
  end
  keystore = _ks

  print Rainbow("Enter keystore password").white.bg(:red) + "  " + Rainbow("[#{password}] > ").cyan
  input = gets.chomp
  password = input if input.length > 0

  print Rainbow("Enter number of threads to run").white.bg(:red) + "  " + Rainbow("[#{threads.to_s}] > ").cyan
  input = gets.chomp
  threads = input.to_i if input.length > 0
end

begin
  AuditResponseHandler.threads= threads
  FCKeyStore.initialize_keystore( keystore, password  )

  RDFMigrator.set_target(target_url)

  FCClient.instance.start

  uris_request = HttpAsyncMethods.create_get(source_url)
  response = FCClient.instance.client.execute(uris_request, AuditResponseHandler.new, nil)
  queue = response.get
  while ( queue.size > 0 )
    sleep 5
  end
ensure
  FCClient.instance.stop
end
