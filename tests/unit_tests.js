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

var expect = chai.should(); // we are using the "should" style of Chai

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
	});
});