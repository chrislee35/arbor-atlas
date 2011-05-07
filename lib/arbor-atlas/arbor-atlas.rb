require 'net/http'
require 'net/https'
require 'crack'

module Arbor
	class Atlas
		@@baseurl = "https://atlas.arbor.net"
		
		attr_reader :cookie
		def initialize(username, password)
			params = {'name' => username, 'password' => password, 'referer' => @@baseurl+"/"}
			@cookie = nil
			_post("user/login",params)
		end
		
		def _post(path, params)
			url = URI.parse "#{@@baseurl}/#{path}"
			request = Net::HTTP::Post.new(url.path)
			request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} arbor-atlas rubygem (https://github.com/chrislee35/arbor-atlas)")
			request.add_field("Referer", @@baseurl)
			request.add_field("Cookie", @cookie) if @cookie
			request.set_form_data(params)
			
			http = Net::HTTP.new(url.host, url.port)
			if url.scheme == 'https'
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
			end
			resp = http.request(request)
			@cookie = resp.header["set-cookie"] if resp.header["set-cookie"]
			resp.body
		end
		
		def _get(path, params)
			url = URI.parse "#{@@baseurl}/#{path}"
			data = params.map { |k,v|
				"#{k}=#{v}".gsub(/([^ a-zA-Z0-9_.-=]+)/) do
					'%' + $1.unpack('H2' * $1.bytesize).join('%').upcase
				end.tr(' ', '+')
			}.join("&")
			request = Net::HTTP::Get.new(url.path+"?"+data)
			request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} arbor-atlas rubygem (https://github.com/chrislee35/arbor-atlas)")
			request.add_field("Referer", @@baseurl)
			request.add_field("Cookie", @cookie) if @cookie

			http = Net::HTTP.new(url.host, url.port)
			if url.scheme == 'https'
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
			end
			resp = http.request(request)
			@cookie = resp.header["set-cookie"] if resp.header["set-cookie"]
			resp.body
		end

		def lookup_ip(ip)
			doc = _get("ip/#{ip}",{'out'=>'xml'})
			Crack::XML.parse(doc)
		end
		
		def lookup_asn(asn)
			asn = asn.gsub(/[^0-9]/,'')
			doc = _get("asn/#{asn}",{'out'=>'xml'})
			Crack::XML.parse(doc)
		end
		
		def lookup_cve(cve)
			doc = _get("vuln/#{cve.upcase}",{'out'=>'xml'})
			Crack::XML.parse(doc)
		end
		
		def lookup_cc(cc)
			doc = _get("cc/#{cc.upcase}",{'out'=>'xml'})
			Crack::XML.parse(doc)
		end
		
		def lookup_cidr(cidr)
			lookup_ip(cidr)
		end
		
		def lookup(item)
			if item =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/
				lookup_ip(item)
			elsif item =~ /^(AS)?\d{1,7}$/i
				lookup_asn(item)
			elsif item =~ /^CVE\-\d{4}-\d+$/i
				lookup_cve(item)
			elsif item =~ /^\w{2}$/i
				lookup_cc(item)
			else
				raise ArgumentError, "unknown query type for item: #{item}"
			end
		end
	end
end