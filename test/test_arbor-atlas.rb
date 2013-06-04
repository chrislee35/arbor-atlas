unless Kernel.respond_to?(:require_relative)
	module Kernel
		def require_relative(path)
			require File.join(File.dirname(caller[0]), path.to_str)
		end
	end
end

require_relative 'helper'

class TestArborAtlas < Test::Unit::TestCase
	def setup
		raise "You must set ARBORUSER and ARBORPASS in your environment before running tests" unless ENV['ARBORUSER'] and ENV['ARBORPASS']
	end
	
	def test_return_host_report_on_1_2_3_4
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("1.2.3.4")
		assert_not_nil(ipinfo)
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Host Report: Global 1.2.3.4", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['background']['blacklist'])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'][0])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'][0]['status'])
		assert_equal("OK", ipinfo['report']['background']['blacklist']['dnsbl'][0]['status'])
		assert_not_nil(ipinfo['report']['scans'])
		assert_not_nil(ipinfo['report']['attacks'])
		assert_not_nil(ipinfo['report']['servers'])
	end

	def test_return_network_report_on_1_2_3_0_24
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("1.2.3.0/24")
		assert_not_nil(ipinfo)
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Network Report: Global 1.2.3.0/24", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['background']['blacklist'])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'][0])
		assert_not_nil(ipinfo['report']['background']['blacklist']['dnsbl'][0]['status'])
		assert_equal("OK", ipinfo['report']['background']['blacklist']['dnsbl'][0]['status'])
		assert_not_nil(ipinfo['report']['scans'])
		assert_not_nil(ipinfo['report']['attacks'])
		assert_not_nil(ipinfo['report']['servers'])
	end

	def test_return_network_as_report_for_AS701
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("AS701")
		assert_not_nil(ipinfo)
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Network AS Report: Global AS701 (UUNET)", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['background']['peers'])
		assert_not_nil(ipinfo['report']['background']['peers']['peer'])
		assert_not_nil(ipinfo['report']['background']['peers']['peer'].index("AS174 (COGENT)"))
		assert_not_nil(ipinfo['report']['scans'])
		assert_not_nil(ipinfo['report']['attacks'])
		assert_not_nil(ipinfo['report']['servers'])
		assert_not_nil(ipinfo['report']['dos_attacks'])
	end

	def test_return_vulnerability_report_for_CVE_2006_4139
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("CVE-2006-4139")
		assert_not_nil(ipinfo)
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Vulnerability Report: Global CVE-2006-4139", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['scans'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['background']['description'])
		assert_equal("Race condition in Sun Solaris 10 allows attackers to cause a denial of service (system panic) via unspecified vectors related to ifconfig and either netstat or SNMP queries.", ipinfo['report']['background']['description'])
		assert_not_nil(ipinfo['report']['attacks'])
	end

	def test_return_country_report_for_US
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("US")
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Country Report: Global United States", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['attacks'])
		assert_not_nil(ipinfo['report']['dos_attacks'])
		assert_not_nil(ipinfo['report']['servers'])
	end

	def test_return_service_report_for_tcp_445
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		ipinfo = a.lookup("tcp/445")
		assert_not_nil(ipinfo['report'])
		assert_not_nil(ipinfo['report']['title'])
		assert_equal("ATLAS Service Report: Global TCP/445 (microsoft-ds)", ipinfo['report']['title'])
		assert_not_nil(ipinfo['report']['scans'])
		assert_not_nil(ipinfo['report']['background'])
		assert_not_nil(ipinfo['report']['attacks'])
		assert_not_nil(ipinfo['report']['vulnerabilities'])
	end

	def test_raise_exception_on_unknown_query_type
		a = Arbor::Atlas.new(ENV['ARBORUSER'], ENV['ARBORPASS'])
		assert_not_nil(a.cookie)
		assert_raise(ArgumentError) do a.lookup("unknown type") end
	end
end
