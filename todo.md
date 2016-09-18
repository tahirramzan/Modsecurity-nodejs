#TODO:
The following are the known issues with this binding:
 - [ ] `std_multimap.i` is not supported
 - [ ] Automate the search for linking libraries
 - [x] Add Unit tests
 - [ ] Variable not updating when they passed by pointer (or passed by reference) (for instance `char const ** error` in `msc_rules_add_file`)
 - [ ] Adding a callback function in `msc_set_log_cb`. Currently it's unable to register the call back function.
 - [ ] Running test cases synchronously.
 - [ ] Multimaps are unstable 