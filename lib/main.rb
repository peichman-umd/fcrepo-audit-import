require 'java'
require 'singleton'
require 'thread'


Dir.glob(File.join(__dir__, "*.jar")).each { |f| require f }

java_import java.lang.System
java_import java.io.FileInputStream
java_import java.io.ByteArrayOutputStream
java_import java.io.IOException
java_import java.nio.CharBuffer
java_import java.security.KeyStore
java_import java.util.concurrent.Future

java_import javax.net.ssl.SSLContext

java_import org.apache.http.HttpResponse
java_import org.apache.http.conn.ssl.TrustSelfSignedStrategy
java_import org.apache.http.client.methods.HttpGet
java_import org.apache.http.client.methods.HttpPost
java_import org.apache.http.impl.nio.client.CloseableHttpAsyncClient
java_import org.apache.http.impl.nio.client.HttpAsyncClients
java_import org.apache.http.util.EntityUtils

java_import org.apache.http.nio.IOControl
java_import org.apache.http.nio.client.methods.AsyncCharConsumer
java_import org.apache.http.nio.client.methods.HttpAsyncMethods
java_import org.apache.http.protocol.HttpContext
java_import org.apache.http.ssl.SSLContexts
java_import org.apache.http.message.BasicHeader

java_import java.util.concurrent.LinkedBlockingQueue

java_import org.apache.jena.rdf.model.ModelFactory
java_import org.apache.http.entity.ByteArrayEntity
java_import org.apache.http.entity.ContentType

class FCKeyStore
  include Singleton

  def keystore
    @@keystore
  end

  def password
    @@password
  end

  def self.initialize_keystore(keystore_file, password)

    @@keystore = KeyStore.get_instance("JKS")
    @@password = password.to_java.to_char_array

    ios = FileInputStream.new(keystore_file)
    begin
      @@keystore.load(ios, @@password)
    ensure
      ios.close
    end
  end

end

class FCClient
  include Singleton
  attr_accessor :client

  def initialize
    keystore = FCKeyStore.instance
    sslcontext = SSLContexts.custom.load_trust_material(nil, TrustSelfSignedStrategy.new).load_key_material(keystore.keystore, keystore.password).build

    headers = [
      BasicHeader.new("Accept", "application/n-triples"),
    ]

    @client = HttpAsyncClients.custom.setSSLContext(sslcontext)
      .setDefaultHeaders(headers)
      .build

  end

  def start
    @client.start
  end

  def stop
    @client.close
  end
end



class RDFMigrator
  attr_accessor :queue
  attr_accessor :name

  @@target = "https://localhost:/fuseki/fcrepo-audit/data"

  FEDORA_PREFIX = "http://fedora.info/definitions/v4/repository#"
  LDP_PREFIX = "http://www.w3.org/ns/ldp#"
  RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"

  def initialize( queue, name )
    @queue = queue
    @name = name
  end

  def target
    @@target
  end

  def run
    puts "starting worker #{@name}"
    while ( uri = @queue.poll(10000, java.util.concurrent.TimeUnit::MILLISECONDS); uri != "DONE" )
      print "."
      begin
        request = HttpGet.new(uri)
        future = FCClient.instance.client.execute(request, nil)
        response = future.get

        model = ModelFactory.createDefaultModel
        filteredModel = ModelFactory.createDefaultModel
        model.read(response.getEntity.getContent, nil, 'N-TRIPLES')
        statements = model.listStatements
        while statements.hasNext
          statement = statements.nextStatement
          if filter(statement)
            filteredModel.add(statement)
          end
        end
        filteredStream = ByteArrayOutputStream.new
        filteredModel.write(filteredStream, 'N-TRIPLES')

        post = HttpPost.new(target)
        post.set_entity(ByteArrayEntity.new(filteredStream.toByteArray, ContentType.create("application/n-triples")))

        future = FCClient.instance.client.execute(post, nil)
        status = future.get.get_status_line
        case status.status_code
        when 200...399
          print "+"
        else
          "Problem migrating #{uri}. Received #{status}"
        end
        #puts EntityUtils.toString(future.get.get_entity)
      rescue => e
        puts "ERROR with #{uri} : #{e.message}"
        raise e
      end
    end
  end

  def filter(statement)
    p = statement.getPredicate
    if p.getURI.start_with?(FEDORA_PREFIX)
      # skip it!
      return false
    elsif p.getURI == RDF_TYPE
      o = statement.getResource
      if o.getURI.start_with?(FEDORA_PREFIX) || o.getURI.start_with?(LDP_PREFIX)
        # skip it!
        return false
      end
    end
    return true
  end

  def self.set_target(target)
    @@target = target
  end

end


class Forbidden < StandardError; end
class AuditResponseHandler <  AsyncCharConsumer

  attr_accessor :accumulator
  attr_accessor :queue
  attr_accessor :exception

  @@threads = 5

  def onCharReceived( buf, ioctrl)
    if ( !@accumulator.nil? )
      # convert to a string block
      output = @accumulator + java.lang.StringBuilder.new(buf).to_s
      lines = output.lines

      # we're getting in chunks, so don't assume last line to complete...
      @accumulator = lines.pop

      lines.select { |line| line.include?("<http://www.w3.org/ns/ldp#contains>") }
        .map { |line| line.split[2].gsub(/\<|\>/, '') }.each { |uri| @queue.offer uri }
    end
  end

  def onResponseReceived( response )
    status = response.getStatusLine
    puts "Received response : #{status}"

    case status.status_code
    when 200...399
      @accumulator = ""
      @queue = LinkedBlockingQueue.new
      @@threads.times { |x| Thread.new { RDFMigrator.new(@queue, x.to_s).run } }
    else
      @exception = Forbidden.new "There is a problem. Received #{status}"
    end
  end

  def releaseResources
  end

  def buildResult(context)
    if ( !@exception.nil?  )
      raise @exception
    else
      puts "Finished with URIS!!"
      @@threads.times { @queue.offer("DONE")  }
      return @queue
    end
  end

  def self.threads=(threads)
    @@threads = threads
  end

end
