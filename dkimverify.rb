require 'digest'
require 'openssl'
require 'base64'
require_relative './dkim-query/lib/dkim/query'


# TODO make this an option somehow
$debuglog = nil # alternatively, set this to `STDERR` to log to stdout.
require 'mail'

module Mail
    class Header
        def first_field(name)
            self[name].class == Array ? self[name].first : self[name]
        end
    end
end

module Dkim
    # what are these magic numbers?!
    # These values come from RFC 3447, section 9.2 Notes, page 43.
    # cf. https://github.com/emboss/krypt/blob/c804f736d4dbaa4425014d036d2e68d8ee66d559/lib/krypt/asn1/common.rb
    #       SHA1       = algorithm_null_params('1.3.14.3.2.26')
    #       SHA256 = algorithm_null_params('2.16.840.1.101.3.4.2.1')    
    OpenSSL::ASN1::ObjectId.register('1.3.14.3.2.26', 'sha1', 'HASHID_SHA1')
    OpenSSL::ASN1::ObjectId.register('2.16.840.1.101.3.4.2.1', 'sha256', 'HASHID_SHA256')
    HASHID_SHA1   = OpenSSL::ASN1::ObjectId.new('sha1')
    HASHID_SHA256 = OpenSSL::ASN1::ObjectId.new('sha256')

    class DkimError < StandardError; end
    class DkimTempFail < DkimError; end
    class DkimPermFail < DkimError; end
    class InvalidDkimSignature < DkimPermFail; end
    class DkimVerificationFailure < DkimPermFail; end

    class Verifier
        def initialize(email_filename)
            mail = Mail.read(email_filename) # TODO make this `mail` not `@mail`
            @headers = mail.header
            @body = mail.body.raw_source
        end


        def verify!
            return false if @headers["DKIM-Signature"].nil?

            dkim_signature_str = @headers.first_field("DKIM-Signature").value.to_s
            @dkim_signature = {}
            dkim_signature_str.split(/\s*;\s*/).each do |key_val| 
                if m = key_val.match(/(\w+)\s*=\s*(.*)/)
                    @dkim_signature[m[1]] = m[2]
                end
            end
            validate_signature! # just checking to make sure we have all the ingredients we need to actually verify the signature

            figure_out_canonicalization_methods!
            verify_body_hash!

            # 'b=' is the signed message headers' hash.
            # we need to decrypt the 'b=' value (with the public key)
            # and compare it with the computed headers_hash.
            # decrypted_header_hash is the "expected" value.
            my_headers_hash = headers_hash
            my_decrypted_header_hash = decrypted_header_hash

            raise DkimVerificationFailure.new("header hash signatures sizes don't match") if my_decrypted_header_hash.size != my_headers_hash.size
            
            # Byte-by-byte compare of signatures
            does_signature_match = my_decrypted_header_hash.bytes.zip(my_headers_hash.bytes).all?{|exp, got| exp == got }
            raise DkimVerificationFailure.new("header hash signatures don't match. expected #{my_decrypted_header_hash}, got #{my_headers_hash}") unless does_signature_match
            return does_signature_match # always true, but this is a good guarantee of somebody accidentally refactoring this to always return true
        end

        private


        def verify_body_hash!
            # here we're figuring out what algorithm to use for computing the signature
            hasher, @hashid = if @dkim_signature['a'] == "rsa-sha1"
                      [Digest::SHA1, HASHID_SHA1]
                    elsif @dkim_signature['a'] == "rsa-sha256"
                      [Digest::SHA256, HASHID_SHA256]
                    else
                      $debuglog.puts "couldn't figure out the right algorithm to use"
                      exit 1
                    end
            
            body = Dkim.canonicalize_body(@body, @how_to_canonicalize_body)
            
            
            bodyhash = hasher.digest(body)

            $debuglog.puts "bh: #{Base64.encode64(bodyhash)}" unless $debuglog.nil?

            if bodyhash != Base64.decode64(@dkim_signature['bh'].gsub(/\s+/, ''))
                error_msg = "body hash mismatch (got #{Base64.encode64(bodyhash)}, expected #{@dkim_signature['bh']})"
                $debuglog.puts error_msg unless $debuglog.nil?
                raise DkimVerificationFailure.new(error_msg)
            end
            nil
        end


        # here we're figuring out the canonicalization algorithm for the body and for the headers
        def figure_out_canonicalization_methods!
            c_match = @dkim_signature['c'].match(/(\w+)(?:\/(\w+))?$/)
            if not c_match
              puts "can't figure out canonicalization ('c=')"
              return false
            end
            @how_to_canonicalize_headers = c_match[1]
            if c_match[2]
                @how_to_canonicalize_body = c_match[2]
            else
                @how_to_canonicalize_body = "simple"
            end
            raise ArgumentError, "invalid canonicalization method for headers" unless ["relaxed", "simple"].include?(@how_to_canonicalize_headers)
            raise ArgumentError, "invalid canonicalization method for body" unless ["relaxed", "simple"].include?(@how_to_canonicalize_body)
        end

        def public_key
            # here we're getting the website's actual public key from the DNS system
            # s = dnstxt(sig['s']+"._domainkey."+sig['d']+".")
            dkim_record_from_dns = DKIM::Query::Domain.query(@dkim_signature['d'], {:selectors => [@dkim_signature['s']]}).keys[@dkim_signature['s']]
            raise DkimTempFail.new("couldn't get public key from DNS system for #{@dkim_signature['s']}/#{@dkim_signature['d']}") if dkim_record_from_dns.nil? || dkim_record_from_dns.class == DKIM::Query::MalformedKey
            x = OpenSSL::ASN1.decode(Base64.decode64(dkim_record_from_dns.public_key.to_s))
            publickey = x.value[1].value
        end

        def headers_to_sign

            # we figure out which headers we care about, then canonicalize them
            header_fields_to_include = @dkim_signature['h'].split(/\s*:\s*/)
            $debuglog.puts "header_fields_to_include: #{header_fields_to_include}" unless $debuglog.nil?
            canonicalized_headers = []
            header_fields_to_include_with_values = header_fields_to_include.map do |header_name|                                
                [header_name, @headers.first_field(header_name).instance_eval { unfold(split(@raw_value)[1]) } ] 
                # .value and .instance_eval { unfold(split(@raw_value)[1]) } return subtly different values
                # if the value of the Date header is a date with a single-digit day.
                # see https://github.com/mikel/mail/issues/1075
                # incidentally, .instance_variable_get("@value") gives a third subtly different value in a way that I don't understand.
            end
            canonicalized_headers = Dkim.canonicalize_headers(header_fields_to_include_with_values, @how_to_canonicalize_headers)

            canonicalized_headers += Dkim.canonicalize_headers([
                [
                    @headers.first_field("DKIM-Signature").name.to_s, 
                    @headers.first_field("DKIM-Signature").value.to_s.split(@dkim_signature['b']).join('')
                ]
            ], @how_to_canonicalize_headers).map{|x| [x[0], x[1].rstrip()] }

            $debuglog.puts "verify headers: #{canonicalized_headers}" unless $debuglog.nil?
            canonicalized_headers
        end

        def headers_digest
            hasher = if @dkim_signature['a'] == "rsa-sha1"
                      Digest::SHA1
                    elsif @dkim_signature['a'] == "rsa-sha256"
                      Digest::SHA256
                    else
                      raise InvalidDkimSignature.new "couldn't figure out the right algorithm to use"
                    end.new
            headers_to_sign.each do |header|
                hasher.update(header[0])
                hasher.update(":")
                hasher.update(header[1])
            end
            digest = hasher.digest
            $debuglog.puts "verify digest: #{  digest.each_byte.map { |b| b.to_s(16) }.join ' ' }" unless $debuglog.nil?
            digest
        end
        

        def headers_hash
            dinfo = OpenSSL::ASN1::Sequence.new([
                        OpenSSL::ASN1::Sequence.new([
                            @hashid,
                            OpenSSL::ASN1::Null.new(nil),
                        ]),
                        OpenSSL::ASN1::OctetString.new(headers_digest),
                ])
            $debuglog.puts "dinfo: #{ dinfo.to_der  }" unless $debuglog.nil?
            headers_der = Base64.encode64(dinfo.to_der).gsub(/\s+/, '')
            $debuglog.puts "headers_hash: #{headers_der}" unless $debuglog.nil?
            headers_der
        end

        def decrypted_header_hash
            decrypted_header_hash_bytes = OpenSSL::PKey::RSA.new(public_key).public_decrypt(Base64.decode64(@dkim_signature['b']))
            ret = Base64.encode64(decrypted_header_hash_bytes).gsub(/\s+/, '')
            $debuglog.puts "decrypted_header_hash: #{ret}" unless $debuglog.nil?
            ret
        end

        def validate_signature!
            # version: only version 1 is defined
            raise InvalidDkimSignature("DKIM signature is missing required tag v=") unless @dkim_signature.include?('v')
            raise InvalidDkimSignature("DKIM signature v= value is invalid (got \"#{@dkim_signature['v']}\"; expected \"1\")") unless @dkim_signature['v'] == "1"
            
            # encryption algorithm
            raise InvalidDkimSignature("DKIM signature is missing required tag a=") unless @dkim_signature.include?('a')
            
            # header hash
            raise InvalidDkimSignature("DKIM signature is missing required tag b=") unless @dkim_signature.include?('b')
            raise InvalidDkimSignature("DKIM signature b= value is not valid base64") unless @dkim_signature['b'].match(/[\s0-9A-Za-z+\/]+=*$/)
            raise InvalidDkimSignature("DKIM signature is missing required tag h=") unless @dkim_signature.include?('h')
            
            # body hash (not directly encrypted)
            raise InvalidDkimSignature("DKIM signature is missing required tag bh=") unless @dkim_signature.include?('bh')
            raise InvalidDkimSignature("DKIM signature bh= value is not valid base64") unless @dkim_signature['bh'].match(/[\s0-9A-Za-z+\/]+=*$/)
            
            # domain selector
            raise InvalidDkimSignature("DKIM signature is missing required tag d=") unless @dkim_signature.include?('d')
            raise InvalidDkimSignature("DKIM signature is missing required tag s=") unless @dkim_signature.include?('s')
            
            # these are expiration dates, which are not checked above.
            raise InvalidDkimSignature("DKIM signature t= value is not a valid decimal integer") unless @dkim_signature['t'].nil? || @dkim_signature['t'].match(/\d+$/)
            raise InvalidDkimSignature("DKIM signature x= value is not a valid decimal integer") unless @dkim_signature['x'].nil? || @dkim_signature['x'].match(/\d+$/)
            raise InvalidDkimSignature("DKIM signature x= value is less than t= (and must be greater than or equal to t=). (x=#{@dkim_signature['x']}, t=#{@dkim_signature['t']}) ") unless @dkim_signature['x'].nil? || @dkim_signature['x'].to_i >= @dkim_signature['t'].to_i

            # other unimplemented stuff
            raise InvalidDkimSignature("DKIM signature i= domain is not a subdomain of d= (i=#{@dkim_signature[i]} d=#{@dkim_signature[d]})") if @dkim_signature['i'] && !(@dkim_signature['i'].end_with?(@dkim_signature['d']) || ["@", ".", "@."].include?(@dkim_signature['i'][-@dkim_signature['d'].size-1]))
            raise InvalidDkimSignature("DKIM signature l= value is invalid") if @dkim_signature['l'] && !@dkim_signature['l'].match(/\d{,76}$/)
            raise InvalidDkimSignature("DKIM signature q= value is invalid (got \"#{@dkim_signature['q']}\"; expected \"dns/txt\")") if @dkim_signature['q'] && @dkim_signature['q'] != "dns/txt"
        end
    end

    # these two canonicalization methods are defined in the DKIM RFC
    def self.canonicalize_headers(headers, how)
      if how == "simple"
        # No changes to headers.
        $debuglog.puts "canonicalizing headers with 'simple'" unless $debuglog.nil?
        return headers
      elsif how == "relaxed"
        # Convert all header field names to lowercase.
        # Unfold all header lines.
        # Compress WSP to single space.
        # Remove all WSP at the start or end of the field value (strip).
        $debuglog.puts "canonicalizing headers with 'relaxed'" unless $debuglog.nil?
        headers.map{|k, v| [k.downcase, v.gsub(/\r\n/, '').gsub(/\s+/, " ").strip + "\r\n"]  }
      end
    end
    def self.canonicalize_body(body, how)
      if how == "simple"  
        $debuglog.puts "canonicalizing body with 'simple'" unless $debuglog.nil?
        # Ignore all empty lines at the end of the message body.
        body.gsub(/(\r\n)*$/, "\r\n")
      elsif how == "relaxed"
        $debuglog.puts "canonicalizing body with 'relaxed'" unless $debuglog.nil?
        
        body.gsub(/[\x09\x20]+\r\n/, "\r\n") # Remove all trailing WSP at end of lines.
            .gsub(/[\x09\x20]+/, " ")        # Compress non-line-ending WSP to single space.
            .gsub(/(\r\n)+\Z/, "\r\n")       # Ignore all empty lines at the end of the message body.
                                             # POTENTIAL PROBLEM: the python source has /(\r\n)*$/ so the + / * change is dubious
      end
    end

end

if __FILE__ == $0
    emlfn = ARGV[0] || "/Users/204434/code/stevedore-uploader-internal/inputs/podesta-part36/59250.eml"
    begin
        ret = Dkim::Verifier.new(emlfn).verify!
    rescue Dkim::DkimPermFail
        puts "uh oh, something went wrong, the signature did not verify correctly"
        exit 1
    end
    puts ret ? "DKIM signature verified correctly" : "DKIM signature absent"
end
