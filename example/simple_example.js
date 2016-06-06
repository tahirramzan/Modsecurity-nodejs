/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 * Author: Manish Malik <manishmalikkvs at gmail dot com>
 */

// Importing modsecurity
var modsecurity = require('./../build/Release/modsecurity');


//uri to the basic_rules.conf
var main_rule_uri = "./basic_rules.conf";

//error variable
var error = "";

//Initializes modsecurity APIs
var modsec = new modsecurity.msc_init();

//Sets information about the connector utilizing the ModSec.
modsecurity.msc_set_connector_info(modsec, "ModSecurity-nodejs-test v0.0.1-alpha (Simple example of nodejs connector");

//Instantiate new rules object
rules = new modsecurity.msc_create_rules_set();

console.log('Adding local rules: ');
/*
	Add rules from file

	TODO: FIX type mapping of char const** error
	libmodsecurity requires error to be char const **, and updates the error variable when there
	are some error while adding rules. By swig typemaping we can change the nodejs variable into char const **
	but it is unable to update this variable.
*/
ret = modsecurity.msc_rules_add_file(rules, main_rule_uri, error);

if (ret < 0) {
	console.log("Problems while loading the rules from file --\n");
	console.log('Error : ' + error);
	modsecurity.msc_rules_cleanup(rules);
	modsecurity.msc_cleanup(modsec);
} else {
	//rules are loaded properly

	//generate the rules dump
	modsecurity.msc_rules_dump(rules);
	console.log('Adding rules from remote files: ');
	/*
		Add remote rules

		TODO: FIX type mapping of char const** error
		libmodsecurity requires error to be char const **, and updates the error variable when there
		are some error while adding rules. By swig typemaping we can change the nodejs variable into char const **
		but it is unable to update this variable.
	*/
	ret = modsecurity.msc_rules_add_remote(rules, "test",
		"https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt", error);

	if (ret < 0) {
		console.log("Problems while loading the remote rules --\n");
		console.log(error.toString());
		modsecurity.msc_rules_cleanup(rules);
		modsecurity.msc_cleanup(modsec);
	} else {

		modsecurity.msc_rules_dump(rules);

		//unit that will be used to inspect every requests
		transaction = modsecurity.msc_new_transaction(modsec, rules, null);

		//performs analysis on the connection
		modsecurity.msc_process_connection(transaction, "127.0.0.1", 12345, "127.0.0.1", 80);

		//performs analysis on the uri
		modsecurity.msc_process_uri(transaction,
			"http://www.modsecurity.org/test?key1=value1&key2=value2&key3=value3",
			"GET", "1.1");

		//Adds dummy request header
		if (modsecurity.msc_add_n_request_header(transaction, 'test', 'test'.length, 'test', 'test'.length)) {
			//perform request headers analysis
			modsecurity.msc_process_request_headers(transaction);

			// adds dummy request body
			if (modsecurity.msc_append_request_body(transaction, 'randomn test buffer', 'randomn test buffer'.length)) {
				modsecurity.msc_process_request_body(transaction);
			} else {
				console.log('Failed to add dummy request body');
				modsecurity.msc_rules_cleanup(rules);
				modsecurity.msc_cleanup(modsec);
			}
		} else {
			console.log('Failed to add request headers in transaction');
			modsecurity.msc_rules_cleanup(rules);
			modsecurity.msc_cleanup(modsec);
		}

		//adds dummy response header
		if (modsecurity.msc_add_n_response_header(transaction, 'test', 'test'.length, 'test', 'test'.length)) {
			//performs response headers analysis
			modsecurity.msc_process_response_headers(transaction);

			// adds dummy response body
			if (modsecurity.msc_append_response_body(transaction, 'randomn test buffer', 'randomn test buffer'.length)) {
				modsecurity.msc_process_response_body(transaction);
				modsecurity.msc_process_logging(transaction, 200);
				modsecurity.msc_rules_cleanup(rules);
				modsecurity.msc_cleanup(modsec);
			} else {
				console.log('Failed to add dummy response body');
				modsecurity.msc_rules_cleanup(rules);
				modsecurity.msc_cleanup(modsec);
			}
		} else {
			console.log('Failed to add response headers in transaction');
			modsecurity.msc_rules_cleanup(rules);
			modsecurity.msc_cleanup(modsec);
		}
	}
}