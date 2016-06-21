/*

 ModSecurity, http://www.modsecurity.org/
 Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)

 You may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 If any of the files related to licensing are missing or if you have any
 other questions related to licensing please contact Trustwave Holdings, Inc.
 directly using the email address security@modsecurity.org.

 Author: Manish Malik <manishmalikkvs at gmail dot com>

*/

//We are using chai for assertions
var chai = require('chai');

var should = chai.should();

var modsecurity = require('./../build/Release/modsecurity');

describe('ModSecurity Unit Tests : ', function() {

	describe('Tests for ModSecurity version', function() {
		it('whoAmI() should return the current version of ModSecurity', function() {
			var whoAmI = modsecurity.ModSecurity.whoAmI();
			whoAmI.should.exist;
			whoAmI.should.contain('ModSecurity');
		});
	});

	describe('Rules related tests to', function() {
		it('rules.load() should return number of rules loaded otherwise -1', function() {
			rules = new modsecurity.Rules();
			//load one rule
			ret = rules.load('SecRule ARGS_POST|XML:/* "(\n|\r)" "id:1,deny,phase:2"');
			ret.should.equal(1);

			//load two rules
			ret = rules.load('SecRule ARGS_POST|XML:/* "(\n|\r)" "id:1,deny,phase:2" SecRule ARGS_POST|XML:/* "(\n|\r)" "id:2,deny,phase:2"');
			ret.should.equal(2);

			//bad rule
			ret = rules.load('SecRule ARGS_POST|XML:/* "(\n|\r)" "deny,phase:2"');
			ret.should.equal(-1);

			//Parse error
			ret = rules.getParserError();
			ret.should.contain('Rules must have an ID.');

		});

		it('Loading rules from local conf file (it should return number of rules loaded i.e 6)', function() {
			//Initializes modsecurity APIs
			var modsec = new modsecurity.msc_init();

			//uri to the basic_rules.conf
			var main_rule_uri = "./example/basic_rules.conf";

			//error variable
			var error = "";

			//Sets information about the connector utilizing the ModSec.
			modsecurity.msc_set_connector_info(modsec, "ModSecurity-nodejs-test v0.0.1-alpha (Simple example of nodejs connector)");

			//Instantiate new rules object
			rules = new modsecurity.msc_create_rules_set();

			/*
				Add rules from file

				TODO: FIX type mapping of char const** error
				libmodsecurity requires error to be char const **, and updates the error variable when there
				are some error while adding rules. By swig typemaping we can change the nodejs variable into char const **
				but it is unable to update this variable.
			*/
			ret = modsecurity.msc_rules_add_file(rules, main_rule_uri, error);

			modsecurity.msc_rules_cleanup(rules);
			modsecurity.msc_cleanup(modsec);

			ret.should.equal(6);

		});

		it('Loading rules from remote server (it should return number of rules loaded i.e 1)', function() {
			//Initializes modsecurity APIs
			var modsec = new modsecurity.msc_init();

			//error variable
			var error = "";

			//Sets information about the connector utilizing the ModSec.
			modsecurity.msc_set_connector_info(modsec, "ModSecurity-nodejs-test v0.0.1-alpha (Simple example of nodejs connector)");

			//Instantiate new rules object
			rules = new modsecurity.msc_create_rules_set();

			/*
				Add remote rules

				TODO: FIX type mapping of char const** error
				libmodsecurity requires error to be char const **, and updates the error variable when there
				are some error while adding rules. By swig typemaping we can change the nodejs variable into char const **
				but it is unable to update this variable.
			*/
			ret = modsecurity.msc_rules_add_remote(rules, "test",
				"https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt", error);

			modsecurity.msc_rules_cleanup(rules);
			modsecurity.msc_cleanup(modsec);

			ret.should.equal(1);
			this.timeout(60000); //delay for reply
		});
	});

	describe('Transaction related tests to', function() {
		//Initializes modsecurity APIs
		var modsec = new modsecurity.msc_init();

		//uri to the basic_rules.conf
		var main_rule_uri = "./example/basic_rules.conf";

		//error variable
		var error = "";

		//Sets information about the connector utilizing the ModSec.
		modsecurity.msc_set_connector_info(modsec, "ModSecurity-nodejs-test v0.0.1-alpha (Simple example of nodejs connector");

		//Instantiate new rules object
		rules = new modsecurity.msc_create_rules_set();

		intervention = new modsecurity.ModSecurityIntervention();

		/*
			Add rules from file

			TODO: FIX type mapping of char const** error
			libmodsecurity requires error to be char const **, and updates the error variable when there
			are some error while adding rules. By swig typemaping we can change the nodejs variable into char const **
			but it is unable to update this variable.
		*/
		ret = modsecurity.msc_rules_add_file(rules, main_rule_uri, error);

		transaction = new modsecurity.msc_new_transaction(modsec, rules, null);

		it('Initiate Transaction variable (it should be null)', function() {
			transaction.should.not.be.null;
		});

		it('performs analysis on connection (it should return 1)', function() {
			retVal = modsecurity.msc_process_connection(transaction, "127.0.0.1", 12345, "127.0.0.1", 80);
			retVal.should.equal(1);
		});

		it('performs analysis on the uri and all the query string variables (it should return 1)', function() {
			retVal = modsecurity.msc_process_uri(transaction,
				"http://www.modsecurity.org/test?key1=value1&key2=value2&key3=value3",
				"GET", "1.1");
			retVal.should.equal(1);
		});

		it('Add requests body to be inspected', function() {
			body = '"--------------------------756b6d74fa1a8ee2",\
        "Content-Disposition: form-data; name=\"name\"",\
        "",\
        "test",\
        "--------------------------756b6d74fa1a8ee2",\
        "Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"",\
        "Content-Type: text/plain",\
        "",\
        "This is a very small test file..",\
        "--------------------------756b6d74fa1a8ee2",\
        "Content-Disposition: form-data; name=\"filedata\"; filename=\"small_text_file.txt\"",\
        "Content-Type: text/plain",\
        "",\
        "This is another very small test file..",\
        "--------------------------756b6d74fa1a8ee2--"';
			retVal = modsecurity.msc_append_request_body(transaction, body, body.length);
			retVal.should.equal(1);

			//TODO use msc_request_body_from_file
		});

		it('Add requests headers to be inspected', function() {
			retVal = modsecurity.msc_add_request_header(transaction, 'Host', 'localhost');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'User-Agent', 'curl/7.38.0');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Accept', '*/*');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Content-Length', '330');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Content-Type', 'multipart/form-data; boundary=--------------------------756b6d74fa1a8ee2');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Expect', '100-continue');
			retVal.should.equal(1);

			retVal = 0;
			retVal = modsecurity.msc_add_n_request_header(transaction, 'test', 'test'.length, 'test', 'test'.length);
			retVal.should.equal(1);
		});

		it('performs analysis on request headers', function() {
			retVal = modsecurity.msc_process_request_headers(transaction);
			retVal.should.equal(1);
		});

		it('performs analysis on request body', function() {
			retVal = modsecurity.msc_process_request_body(transaction);
			retVal.should.equal(1);
		});

		it('Add response body', function() {
			body = "no need.";
			retVal = modsecurity.msc_append_response_body(transaction, body, body.length);
			retVal.should.equal(1);
		});

		it('Add response headers', function() {
			retVal = modsecurity.msc_add_response_header(transaction, 'Date', 'Mon, 13 Jul 2015 20:02:41 GMT');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Last-Modified', 'Sun, 26 Oct 2014 22:33:37 GMT');
			retVal.should.equal(1);
			retVal = 0;
			retVal = modsecurity.msc_add_request_header(transaction, 'Content-Type', 'text/html');
			retVal.should.equal(1);

			retVal = 0;
			retVal = modsecurity.msc_add_n_response_header(transaction, 'test', 'test'.length, 'test', 'test'.length);
			retVal.should.equal(1);
		});

		it('performs analysis on response headers', function() {
			retVal = modsecurity.msc_process_response_headers(transaction, 200, "HTTP 1.0");
			retVal.should.equal(1);
		});

		it('performs analysis on response body', function() {
			retVal = modsecurity.msc_process_response_body(transaction);
			retVal.should.equal(1);
		});

		it('Check if intervention status is ok', function() {
			//TODO: do better testing on 	
			modsecurity.msc_intervention(transaction, intervention);
			intervention.status.should.equal(200);
		});

		it('Retrieve buffer with updated response body (it should return null in this test)', function() {
			//TODO: check for updated body (case when retVal.length !== 0)
			retVal = modsecurity.msc_get_response_body(transaction);
			retVal.length.should.equal(0);
		});

		it('Retrieve the length of the updated response body (it should return 0 in this case)', function() {
			retVal = modsecurity.msc_get_response_body_length(transaction);
			retVal.should.equal(0);
		});

		it('Logging all the information related to this transaction', function() {
			modsecurity.msc_intervention(transaction, intervention);
			retVal = modsecurity.msc_process_logging(transaction);
			retVal.should.equal(1);
		});

		it('Cleaning up transaction and modsecurity instances', function() {
			modsecurity.msc_transaction_cleanup(transaction);
			modsecurity.msc_cleanup(modsec);
		});
	});
});