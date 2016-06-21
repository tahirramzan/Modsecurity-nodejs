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

//importing modsecurity
var modsecurity = require('./../build/Release/modsecurity');

//for searching test cases
var fs = require('fs');

findModSecDir(function(ModSecDir) {
	if (ModSecDir.length === 0) {
		console.log("\n It's seems like ModSecurity is not installed in your system.\n Please clone ModSecurity repository in /opt or within /home");
		console.log("\n\n Loading custom regressions test locally. \n PLEASE NOTE: IT'S HIGHLY RECOMMENDED TO CLONE CLONE ModSecurity REPO");
		runTestCases('./tests/test-cases');
	} else {
		var numberOfTestCases = fs.readdirSync(ModSecDir + '/test/test-cases/regression').length;
		if (numberOfTestCases > 0) {
			console.log('\n ModSecurity default test_cases found!');
			// runTestCases(ModSecDir + '/test/test-cases/regression');
			runTestCases('./tests/test-cases');
		} else {
			console.log("\n It's seems like your default ModSecurity directory do not contain test_cases. \n Please make sure you clone ModSecurity repository in /opt or within /home");
			console.log("\n\n Loading custom regressions test locally. \n PLEASE NOTE: IT'S HIGHLY RECOMMENDED TO CLONE CLONE ModSecurity REPO");
			runTestCases('./tests/test-cases');
		}
	}
});

/*
	Run all the test cases one by one
*/
function runTestCases(testDir) {
	var testFiles = fs.readdirSync(testDir);
	describe('Runing Regression Tests: ', function() {
		testFiles.forEach(function(testFile) {
			//parse only json test cases
			if (testFile.split('.').pop() === 'json') {
				var testCases = JSON.parse(fs.readFileSync(testDir + '/' + testFile, 'utf8'));
				testCases.forEach(function(testCase) {
					loadTest(testCase, testFile);
				});
			}
		});
	});
}

/*
	Load mocha - chai based test
*/
function loadTest(testCase, testFileName) {
	it(testCase.title + ', ' + testFileName, function() {
		//Initializes modsecurity APIs
		var modsec = new modsecurity.ModSecurity();

		//Sets information about the connector utilizing the ModSec.
		modsec.setConnectorInformation("ModSecurity-nodejs-regression v0.0.1-alpha (ModSecurity-Nodejs Regression test utility)");

		var debugLog = new modsecurity.DebugLog();

		//Instantiate new rules object
		rules = new modsecurity.Rules(debugLog);

		retVal = rules.load(testCase.rules.join('\n'), testFileName);

		// console.log(retVal);

		if (retVal < 0) {
			chai.expect(testCase.expected.parser_error, 'Test Case expects parse error to exist. \n Received parser error: ' + rules.getParserError()).to.exist;
			parseError = rules.getParserError().match(testCase.expected.parser_error);
			chai.expect(parseError, 'regex miss-match\n parse-error: \n' + rules.getParserError() + '\n expected error: \n' + testCase.expected.parser_error + '\n').to.not.null;
			//chai.expect(rules.getParserError(), 'Comparing parser error with expected error if available').to.match(testCase.expected.parser_error);	
		} else {
			//first clear log file
			fs.closeSync(fs.openSync('./test.log', 'w'));
			chai.expect(testCase.expected.parser_error, "Parse error expected but didn't occur").to.not.exist;
			modsecTransaction = new modsecurity.Transaction(modsec, rules, null);
			modsecIntervention = new modsecurity.ModSecurityIntervention();

			/*
				TODO:

				Instead of storing logs in file, store directly in memory.
			*/
			debugLog.setDebugLogFile('test.log');
			debugLog.setDebugLogLevel(9);

			//process connection
			if (typeof testCase.client !== 'undefined' && typeof testCase.server !== 'undefined') {
				modsecTransaction.processConnection(testCase.client.ip, testCase.client.port, testCase.server.ip, testCase.server.port);
				//check for intervention

				modsecTransaction.intervention(modsecIntervention);

				if (modsecIntervention.status !== 200) {
					if (testCase.expected.http_code) {
						chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
					}
					modsecTransaction.processLogging();
					if (testCase.expected.debug_log) {
						var log = fs.readFileSync('./test.log', 'utf8');
						regexMatch = log.match(testCase.expected.debug_log);
						chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
					}
					return;
				}
			}

			if (testCase.request) {
				// if not available assume it to be 1.1
				var httpVersion = testCase.request.http_version ? (testCase.request.http_version + '') : '1.1';

				// console.log('URI: ' + testCase.request.uri + '\nMethod: ' + testCase.request.method + '\nversion: ' + httpVersion);
				modsecTransaction.processURI(testCase.request.uri, testCase.request.method, httpVersion);

				modsecTransaction.intervention(modsecIntervention);

				if (modsecIntervention.status !== 200) {
					if (testCase.expected.http_code) {
						chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
					}
					modsecTransaction.processLogging();
					if (testCase.expected.debug_log) {
						var log = fs.readFileSync('./test.log', 'utf8');
						regexMatch = log.match(testCase.expected.debug_log);
						chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
					}
					return;
				}

				Object.keys(testCase.request.headers).forEach(function(requestHeader) {
					modsecTransaction.addRequestHeader(requestHeader, testCase.request.headers[requestHeader]);
					// console.log(testCase.request.headers[requestHeader]);
				});

				modsecTransaction.processRequestHeaders();

				modsecTransaction.intervention(modsecIntervention);

				if (modsecIntervention.status !== 200) {
					if (testCase.expected.http_code) {
						chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
					}
					modsecTransaction.processLogging();
					if (testCase.expected.debug_log) {
						var log = fs.readFileSync('./test.log', 'utf8');
						regexMatch = log.match(testCase.expected.debug_log);
						chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
					}
					return;
				}

				if (testCase.request.body) {
					// converting body from array to string.
					var requestBody = testCase.request.body.join('\n');

					modsecTransaction.appendRequestBody(requestBody, requestBody.length);

					modsecTransaction.processRequestBody();

					modsecTransaction.intervention(modsecIntervention);

					if (modsecIntervention.status !== 200) {
						if (testCase.expected.http_code) {
							chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
						}
						modsecTransaction.processLogging();
						if (testCase.expected.debug_log) {
							var log = fs.readFileSync('./test.log', 'utf8');
							regexMatch = log.match(testCase.expected.debug_log);
							chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
						}
						return;
					}
				}
			}

			if (testCase.response) {
				Object.keys(testCase.response.headers).forEach(function(responseHeader) {
					modsecTransaction.addResponseHeader(responseHeader, testCase.response.headers[responseHeader]);
					// console.log(testCase.request.headers[requestHeader]);
				});

				modsecTransaction.processResponseHeaders(modsecIntervention.status, "HTTP 1.1");

				modsecTransaction.intervention(modsecIntervention);

				if (modsecIntervention.status !== 200) {
					if (testCase.expected.http_code) {
						chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
					}
					modsecTransaction.processLogging();
					if (testCase.expected.debug_log) {
						var log = fs.readFileSync('./test.log', 'utf8');
						regexMatch = log.match(testCase.expected.debug_log);
						chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
					}
					return;
				}

				// converting body from array to string.
				var responseBody = testCase.response.body.join('\n');

				modsecTransaction.appendResponseBody(responseBody, responseBody.length);

				modsecTransaction.processResponseBody();

				modsecTransaction.intervention(modsecIntervention);

				if (modsecIntervention.status !== 200) {
					if (testCase.expected.http_code) {
						chai.expect(modsecIntervention.status, 'HTTP Status code do not match with the expected value.').to.equal(testCase.expected.http_code);
					}
					modsecTransaction.processLogging();
					if (testCase.expected.debug_log) {
						var log = fs.readFileSync('./test.log', 'utf8');
						regexMatch = log.match(testCase.expected.debug_log);
						chai.expect(regexMatch, 'Matching debug logs with expected logs. Regex miss-match. \n debug log: \n' + log + '\n expected debug-log: \n' + testCase.expected.debug_log + '\n').to.not.null;
					}
					return;
				}
			}
		}
	});
}
/*
	Find modsec repository within /home and /opt
*/
function findModSecDir(CallBack) {
	//listing home directory
	var homeDir = fs.readdirSync('/home');
	//listing opt dir
	var optDir = fs.readdirSync('/opt')

	findRecursive('/opt', function(ModSecDir) {
		if (ModSecDir.length !== 0) {
			CallBack(ModSecDir);
		} else {
			findRecursive('/home', CallBack);
		}
	});
}

/*
	Recursively find for the libmodsec folder
*/
function findRecursive(parentDir, CallBack) {
	var dirFiles = fs.readdirSync(parentDir);
	if ((dirFiles.indexOf('ModSecurity') > -1) && (fs.lstatSync(parentDir + '/ModSecurity').isDirectory())) {
		CallBack(parentDir + '/ModSecurity');
	} else {
		var numberOfFiles = dirFiles.length;
		dirFiles.forEach(function(folder) {
			if (numberOfFiles > 0) {
				numberOfFiles--;
				if (fs.lstatSync(parentDir + '/' + folder).isDirectory()) {
					findRecursive(parentDir + '/' + folder, CallBack);
				}
			} else {
				CallBack('');
			}
		});
	}
}