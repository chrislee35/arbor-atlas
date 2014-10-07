# Arbor::Atlas

The arbor-atlas gem provides a very thin wrapper around Arbor Atlas' web interface, https://atlas.arbor.net/.

The ATLAS portal today is a public resource that delivers a sub-set of the intelligence derived from the ATLAS sensor network on host/port scanning activity, zero-day exploits and worm propagation, security events, vulnerability disclosures and dynamic botnet and phishing infrastructures.

## Installation

Add this line to your application's Gemfile:

    gem 'arbor-atlas'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install arbor-atlas

## Usage

	require 'arbor/atlas'
	username = "your atlas username"
	password = "your atlas password"
	arbor = Arbor::Atlas.new(username, password)
	ip_rec = arbor.lookup("1.2.3.4")
	net_rec = arbor.lookup("1.2.3.0/24")
	asn_rec = arbor.lookup("AS701")
	cc_rec = arbor.lookup("US")
	cve_rec = arbor.lookup("CVE-2006-4139")

all the records are simply hashes like the following

	pp ip_rec # =>
	{"report"=>
	  {"title"=>"ATLAS Host Report: Global 1.2.3.4",
	   "scans"=>
	    {"sources"=>
	      {"country"=>
	        {"entity"=>{"name"=>"Other", "percent"=>"0.0%", "bytes_avg"=>"0"}},
	       "asn"=>
	        {"entity"=>{"name"=>"Other", "percent"=>"0.0%", "bytes_avg"=>"0"}},
	       "host"=>
	        {"entity"=>{"name"=>"Other", "percent"=>"0.0%", "bytes_avg"=>"0"}}},
	     "services"=>
	      {"service"=>
	        {"entity"=>{"name"=>"Other", "percent"=>"0.0%", "bytes_avg"=>"0"}}}},
	   "background"=>
	    {"country"=>"AU",
	     "asn"=>nil,
	     "blacklist"=>
	      {"dnsbl"=>
	        [{"server"=>"dnsbl.ahbl.org", "status"=>"OK"},
	         {"server"=>"bl.spamcop.net", "status"=>"OK"},
	         {"server"=>"dnsbl.njabl.org", "status"=>"OK"},
	         {"server"=>"sbl-xbl.spamhaus.org", "status"=>"OK"},
	         {"server"=>"multi.surbl.org", "status"=>"OK"},
	         {"server"=>"dnsbl.sorbs.net", "status"=>"OK"},
	         {"server"=>"virbl.dnsbl.bit.nl", "status"=>"OK"},
	         {"server"=>"dnsbl.dronebl.org", "status"=>"OK"}]}},
	   "attacks"=>
	    {"attack_changes"=>
	      {"attacks"=>"0.00",
	       "change"=>{"absolute"=>"0.0", "percent"=>"0.0"},
	       "cve"=>nil,
	       "description"=>"Other"},
	     "sources"=>
	      {"country"=>
	        {"entity"=>
	          {"name"=>"Other", "percent"=>"0.0%", "attacks_avg"=>"0.00"}},
	       "asn"=>
	        {"entity"=>
	          {"name"=>"Other", "percent"=>"0.0%", "attacks_avg"=>"0.00"}},
	       "host"=>
	        {"entity"=>
	          {"name"=>"Other", "percent"=>"0.0%", "attacks_avg"=>"0.00"}}}},
	   "servers"=>
	    {"phishing"=>
	      {"brands"=>nil,
	       "servers"=>
	        {"country"=>
	          {"entity"=>{"name"=>"Other", "urls"=>"0", "percent"=>"0.0%"}},
	         "asn"=>{"entity"=>{"name"=>"Other", "urls"=>"0", "percent"=>"0.0%"}},
	         "host"=>
	          {"entity"=>{"name"=>"Other", "urls"=>"0", "percent"=>"0.0%"}}}},
	     "botnets"=>
	      {"country"=>
	        {"entity"=>{"name"=>"Other", "controllers"=>"0", "percent"=>"0.0%"}},
	       "asn"=>
	        {"entity"=>{"name"=>"Other", "controllers"=>"0", "percent"=>"0.0%"}},
	       "host"=>
	        {"entity"=>
	          {"name"=>"Other", "controllers"=>"0", "percent"=>"0.0%"}}}}}}

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
