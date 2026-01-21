import "invalid_module"

rule this_rule_fails
{
	strings:
		$test = "test"

	condition:
		$fails or $test
}