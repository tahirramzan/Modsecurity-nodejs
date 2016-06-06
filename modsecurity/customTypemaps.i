%inline %{
#include <node_buffer.h>
#include <node.h>
#include <string>
%}

/*
	Type map for char const **error supplied as input argument
*/
%typemap(in) const char **error {

	if (!($input)->IsString()) {
		SWIG_exception_fail(SWIG_ERROR, "Expected a string variable for error");
	}

	char const *error = NULL;
	
	$1 =  (char **)&error;
}

/*
	Type map for char const** error for output argument
*/
%typemap(argout) const char **error {
	v8::HandleScope scope;
	$input = scope.Close(v8::String::New(*($1)));
}

/*
	Type map for unsigned char * supplied as input argument mostly in msc_append_request_body and msc_add_n_response_header
*/
%typemap(in) unsigned char * {
	
	if (!($input)->IsString()) {
		SWIG_exception_fail(SWIG_ERROR, "Expected a string");
	}
	
	v8::String::Utf8Value str(args[0]->ToString());

	$1 = (unsigned char*) *str;
}