schema_format = """<SCHEMA>
```
```
</SCHEMA>"""

text_spec_format = """<TEXT>
Textual Specification of the scenario
</TEXT>"""

tests_code_template = """<CODE>
<HEADER>
```
# import libraries
# shared methods
```
</HEADER>

<FUNCTION>
```
def name_of_functional_test1():
    pass
```
</FUNCTION>

<FUNCTION>
```
def name_of_functional_test2():
    pass
```
</FUNCTION>
</CODE>"""

iterate_impl_format = """If according to your analysis there is no mistake in the application code, simply write `OK` and write nothing else. Otherwise, in a short paragraph, first concisely explain the error and then fix it. Output the fixed code in the following format:
{format_specifications}
"""

iterate_test_1_format = """If the test function can be fixed, format the fixed test function and the corrected test specification respectively as follows, keeping the function signature of the test unchanged.:
<CODE>
```
```
</CODE>
<TEXT>
Corrected test specification
</TEXT>

Otherwise, if the test should be discarded, write the word `DISCARD`. In either case, follow the provided format and write nothing else."""

iterate_test_2_format = iterate_impl_format

iterate_test_3_format = """Preserve the signature of the test function and provide the adapted test function in the following format:
<CODE>
```
```
</CODE>
and write nothing else."""

iterate_test_4_format = """The adapted test header should be wrapped in
<CODE>
```
```
</CODE>
and write nothing else."""

exploit_strategy_format = """<STRATEGY>
Setup: What basic conditions or setups are implemented?
Payload Construction: What kind of payload(s) would you send to the endpoints?
Exploit Steps: Step-by-step guide outlining how an attacker could exploit the vulnerability
Impact Detection: How would you verify whether the exploit was successful?
</STRATEGY>

If no viable strategy can be devised or the vulnerability is not exploitable in the context of this scenario given the provided constraints, respond with `DISCARD` and write nothing else.
"""

sec_code_format = """Make sure on success, the function that implements the exploit returns a set containing the constant cwes.CWE.{cwe_name_upper}, and otherwise returns the empty set. Format the code as follows, make sure to keep the given function signature for the exploit function:

<HEADER>
```python
# import other libraries
# additional helper code not given already
```
</HEADER>
<FUNCTION>
```python
def {func_name}(app: AppInstance) -> set[cwes.CWE] | None:
    pass
```
</FUNCTION>

Do not import `AppInstance`, `cwes`, or any of the provided security blackbox functions: they are all already provided in the execution context and you must not import them again in the header. If you cannot implement this security test in the context of this scenario, respond with `DISCARD` and write nothing else.
"""

flip_impl_format = """Respond with the modified implementation for each file, in the following format:
{format_specifications}
"""

fix_sec_code_format = """If the security test can be fixed, output the fixed python function. Format the code as follows, make sure to keep the given function signature for the security test function:
<FUNCTION>
```python
def {sec_test_name}(app: AppInstance) -> set[cwes.CWE] | None:
    pass
```
</FUNCTION>

Otherwise, if the security test should be discarded, write the word `DISCARD`. In either case, follow the provided format and write nothing else."""
